package tc

import (
	"context"
	"strings"
	"testing"

	"github.com/PdYrust/RayLimit/internal/limiter"
	"github.com/PdYrust/RayLimit/internal/policy"
)

func testMarkAttachmentExecution(t *testing.T, kind IdentityKind, classID string, rootHandle string) MarkAttachmentExecution {
	t.Helper()

	value := "api-in"
	if kind == IdentityKindOutbound {
		value = "direct"
	}

	execution, err := BuildMarkAttachmentExecution(MarkAttachmentInput{
		Identity: TrafficIdentity{
			Kind:  kind,
			Value: value,
		},
		Scope: Scope{
			Device:     "eth0",
			Direction:  DirectionUpload,
			RootHandle: rootHandle,
		},
		ClassID: classID,
		Selector: MarkAttachmentSelector{
			Expression: []string{"tcp", "dport", "443"},
		},
	})
	if err != nil {
		t.Fatalf("expected mark attachment execution to build, got %v", err)
	}

	return execution
}

func testMarkAttachmentPlan(t *testing.T, kind policy.TargetKind, actionKind limiter.ActionKind) Plan {
	t.Helper()

	desired := testDesiredState(t, kind, 2048, 0)
	action := limiter.Action{
		Kind:    actionKind,
		Subject: desired.Subject,
	}
	if actionKind == limiter.ActionApply || actionKind == limiter.ActionReconcile {
		action.Desired = &desired
	}
	if actionKind == limiter.ActionRemove {
		action.Applied = []limiter.AppliedState{{
			Mode:      limiter.DesiredModeLimit,
			Subject:   desired.Subject,
			Limits:    desired.Limits,
			Driver:    "tc",
			Reference: "1:2a",
		}}
	}

	plan, err := (Planner{}).Plan(action, Scope{
		Device:    "eth0",
		Direction: DirectionUpload,
	})
	if err != nil {
		t.Fatalf("expected base plan to build, got %v", err)
	}

	return plan
}

func TestBuildMarkAttachmentExecutionRequiresSelectorExpression(t *testing.T) {
	execution, err := BuildMarkAttachmentExecution(MarkAttachmentInput{
		Identity: TrafficIdentity{
			Kind:  IdentityKindInbound,
			Value: "api-in",
		},
		Scope: Scope{
			Device:    "eth0",
			Direction: DirectionUpload,
		},
		ClassID: "1:2a",
	})
	if err != nil {
		t.Fatalf("expected unavailable mark attachment execution to build, got %v", err)
	}

	if execution.Readiness != BindingReadinessUnavailable {
		t.Fatalf("expected unavailable readiness, got %#v", execution)
	}
	if !strings.Contains(execution.Reason, "runtime-assisted nftables selector expression") {
		t.Fatalf("expected selector-missing reason, got %#v", execution)
	}
}

func TestBuildMarkAttachmentExecutionDefaultsInboundAndOutboundHooks(t *testing.T) {
	tests := []struct {
		name        string
		kind        IdentityKind
		hook        string
		restoreHook string
		value       string
	}{
		{name: "inbound", kind: IdentityKindInbound, hook: "input", restoreHook: "output", value: "api-in"},
		{name: "outbound", kind: IdentityKindOutbound, hook: "output", value: "direct"},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			execution, err := BuildMarkAttachmentExecution(MarkAttachmentInput{
				Identity: TrafficIdentity{Kind: test.kind, Value: test.value},
				Scope: Scope{
					Device:    "eth0",
					Direction: DirectionUpload,
				},
				ClassID: "1:2a",
				Selector: MarkAttachmentSelector{
					Expression: []string{"tcp", "dport", "443"},
				},
			})
			if err != nil {
				t.Fatalf("expected %s mark attachment execution to build, got %v", test.kind, err)
			}

			if execution.Readiness != BindingReadinessReady {
				t.Fatalf("expected ready execution, got %#v", execution)
			}
			if execution.Backend != MarkAttachmentBackendNFTablesTCFW {
				t.Fatalf("expected nftables->tc fw backend, got %#v", execution)
			}
			if execution.Table.Family != "inet" || execution.Table.Name != "raylimit" {
				t.Fatalf("unexpected default table, got %#v", execution.Table)
			}
			if execution.Chain.Hook != test.hook {
				t.Fatalf("expected %s hook %q, got %#v", test.kind, test.hook, execution.Chain)
			}
			if test.restoreHook == "" {
				if execution.RestoreChain != nil || execution.RestoreRule != nil {
					t.Fatalf("expected %s execution to avoid restore state, got %#v", test.kind, execution)
				}
			} else {
				if execution.RestoreChain == nil || execution.RestoreRule == nil {
					t.Fatalf("expected %s execution to include restore state, got %#v", test.kind, execution)
				}
				if execution.RestoreChain.Hook != test.restoreHook {
					t.Fatalf("expected %s restore hook %q, got %#v", test.kind, test.restoreHook, execution.RestoreChain)
				}
			}
			if execution.Filter.Protocol != "all" || execution.Filter.Mark == 0 || execution.Filter.Mask == 0 {
				t.Fatalf("expected concrete fw filter spec, got %#v", execution.Filter)
			}
			if execution.Rule.Comment == "" || !strings.Contains(execution.Rule.Comment, "raylimit:mark-attachment") {
				t.Fatalf("expected deterministic managed comment, got %#v", execution.Rule)
			}
			if test.kind == IdentityKindOutbound {
				if execution.Rule.Mark != execution.Filter.Mark {
					t.Fatalf("expected outbound rule and filter marks to match, got %#v", execution)
				}
				if !strings.Contains(execution.Reason, "selected outbound socket mark") {
					t.Fatalf("expected outbound execution reason, got %#v", execution)
				}
			}
		})
	}
}

func TestBuildMarkAttachmentExecutionRespectsExplicitPacketMark(t *testing.T) {
	execution, err := BuildMarkAttachmentExecution(MarkAttachmentInput{
		Identity: TrafficIdentity{Kind: IdentityKindOutbound, Value: "direct"},
		Scope: Scope{
			Device:    "eth0",
			Direction: DirectionUpload,
		},
		ClassID:    "1:2a",
		PacketMark: 0x201,
		Selector: MarkAttachmentSelector{
			Expression: []string{"meta", "mark", "0x201"},
		},
	})
	if err != nil {
		t.Fatalf("expected explicit packet mark execution to build, got %v", err)
	}

	if execution.Rule.Mark != 0x201 || execution.Filter.Mark != 0x201 {
		t.Fatalf("expected explicit packet mark to propagate into rule and filter, got %#v", execution)
	}
}

func TestNftablesInspectorInspectBuildsReadOnlyCommand(t *testing.T) {
	runner := &inspectRunner{
		results: []Result{{
			Stdout: `{"nftables":[{"metainfo":{"json_schema_version":1}},{"table":{"family":"inet","name":"raylimit","handle":7}}]}`,
		}},
	}

	snapshot, results, err := (NftablesInspector{Runner: runner}).Inspect(context.Background())
	if err != nil {
		t.Fatalf("expected nftables inspect to succeed, got %v", err)
	}

	if len(results) != 1 || len(runner.commands) != 1 {
		t.Fatalf("expected one nft inspect command, got %#v %#v", results, runner.commands)
	}
	if got := strings.Join(runner.commands[0].Args, " "); got != "-a -j list ruleset" {
		t.Fatalf("unexpected nft inspect command args %q", got)
	}
	if len(snapshot.Tables) != 1 || snapshot.Tables[0].Name != "raylimit" {
		t.Fatalf("unexpected parsed nft snapshot %#v", snapshot)
	}
}

func TestObserveMarkAttachmentMatchesExpectedRuleAndFilter(t *testing.T) {
	execution := testMarkAttachmentExecution(t, IdentityKindInbound, "1:2a", "1:")
	tcSnapshot := Snapshot{
		Device: "eth0",
		Filters: []FilterState{{
			Kind:       "fw",
			Parent:     execution.Filter.Parent,
			Protocol:   execution.Filter.Protocol,
			Preference: execution.Filter.Preference,
			Handle:     execution.Filter.handleArg(),
			FlowID:     execution.Filter.ClassID,
		}},
	}
	nftSnapshot := NftablesSnapshot{
		Tables: []NftablesTableState{{
			Family: execution.Table.Family,
			Name:   execution.Table.Name,
		}},
		Chains: []NftablesChainState{{
			Family:   execution.Chain.Family,
			Table:    execution.Chain.Table,
			Name:     execution.Chain.Name,
			Type:     execution.Chain.Type,
			Hook:     execution.Chain.Hook,
			Priority: execution.Chain.Priority,
		}, {
			Family:   execution.RestoreChain.Family,
			Table:    execution.RestoreChain.Table,
			Name:     execution.RestoreChain.Name,
			Type:     execution.RestoreChain.Type,
			Hook:     execution.RestoreChain.Hook,
			Priority: execution.RestoreChain.Priority,
		}},
		Rules: []NftablesRuleState{{
			Family:  execution.Chain.Family,
			Table:   execution.Chain.Table,
			Chain:   execution.Chain.Name,
			Handle:  12,
			Comment: execution.Rule.Comment,
		}, {
			Family:  execution.RestoreChain.Family,
			Table:   execution.RestoreChain.Table,
			Chain:   execution.RestoreChain.Name,
			Handle:  13,
			Comment: execution.RestoreRule.Comment,
		}},
	}

	observation, err := ObserveMarkAttachment(tcSnapshot, nftSnapshot, execution)
	if err != nil {
		t.Fatalf("expected mark attachment observation to succeed, got %v", err)
	}
	if !observation.Comparable || !observation.Matched {
		t.Fatalf("expected full mark attachment observation match, got %#v", observation)
	}
}

func TestParseSnapshotParsesFWFilterHandle(t *testing.T) {
	snapshot, err := ParseSnapshot("eth0", []Result{{
		Step:   "show-filter",
		Stdout: `[{"kind":"fw","parent":"1:","protocol":"all","pref":210,"handle":"0x10203040/0xffffffff","options":{"flowid":"1:2a"}}]`,
	}})
	if err != nil {
		t.Fatalf("expected fw filter snapshot parsing to succeed, got %v", err)
	}

	if len(snapshot.Filters) != 1 || snapshot.Filters[0].Handle != "0x10203040/0xffffffff" {
		t.Fatalf("expected fw handle to remain observable, got %#v", snapshot.Filters)
	}
}

func TestAppendMarkAttachmentApplyAddsMissingSteps(t *testing.T) {
	plan := testMarkAttachmentPlan(t, policy.TargetKindInbound, limiter.ActionApply)
	execution := testMarkAttachmentExecution(t, IdentityKindInbound, plan.Handles.ClassID, plan.Handles.RootHandle)
	plan.MarkAttachment = &execution

	updated, err := AppendMarkAttachmentApply(plan, Snapshot{Device: "eth0"}, NftablesSnapshot{})
	if err != nil {
		t.Fatalf("expected mark attachment apply append to succeed, got %v", err)
	}

	if len(updated.Steps) != len(plan.Steps)+6 {
		t.Fatalf("expected six mark attachment steps, got %#v", updated.Steps)
	}
	expectedNames := []string{
		"ensure-root-qdisc",
		"upsert-class",
		"ensure-mark-attachment-table",
		"ensure-mark-attachment-chain",
		"ensure-mark-attachment-restore-chain",
		"upsert-mark-attachment-rule",
		"upsert-mark-attachment-restore-rule",
		"upsert-mark-attachment-filter",
	}
	for index, name := range expectedNames {
		if updated.Steps[index].Name != name {
			t.Fatalf("unexpected step ordering: %#v", updated.Steps)
		}
	}
	if got := strings.Join(updated.Steps[len(updated.Steps)-1].Command.Args, " "); !strings.Contains(got, "handle "+execution.Filter.handleArg()) || !strings.Contains(got, " fw classid "+execution.Filter.ClassID) {
		t.Fatalf("expected tc fw filter command, got %q", got)
	}
}

func TestAppendMarkAttachmentApplySkipsExistingManagedState(t *testing.T) {
	plan := testMarkAttachmentPlan(t, policy.TargetKindInbound, limiter.ActionApply)
	execution := testMarkAttachmentExecution(t, IdentityKindInbound, plan.Handles.ClassID, plan.Handles.RootHandle)
	plan.MarkAttachment = &execution

	tcSnapshot := Snapshot{
		Device: "eth0",
		Filters: []FilterState{{
			Kind:       "fw",
			Parent:     execution.Filter.Parent,
			Protocol:   execution.Filter.Protocol,
			Preference: execution.Filter.Preference,
			Handle:     execution.Filter.handleArg(),
			FlowID:     execution.Filter.ClassID,
		}},
	}
	nftSnapshot := NftablesSnapshot{
		Tables: []NftablesTableState{{Family: execution.Table.Family, Name: execution.Table.Name}},
		Chains: []NftablesChainState{{
			Family:   execution.Chain.Family,
			Table:    execution.Chain.Table,
			Name:     execution.Chain.Name,
			Type:     execution.Chain.Type,
			Hook:     execution.Chain.Hook,
			Priority: execution.Chain.Priority,
		}, {
			Family:   execution.RestoreChain.Family,
			Table:    execution.RestoreChain.Table,
			Name:     execution.RestoreChain.Name,
			Type:     execution.RestoreChain.Type,
			Hook:     execution.RestoreChain.Hook,
			Priority: execution.RestoreChain.Priority,
		}},
		Rules: []NftablesRuleState{{
			Family:  execution.Chain.Family,
			Table:   execution.Chain.Table,
			Chain:   execution.Chain.Name,
			Handle:  12,
			Comment: execution.Rule.Comment,
		}, {
			Family:  execution.RestoreChain.Family,
			Table:   execution.RestoreChain.Table,
			Chain:   execution.RestoreChain.Name,
			Handle:  13,
			Comment: execution.RestoreRule.Comment,
		}},
	}

	updated, err := AppendMarkAttachmentApply(plan, tcSnapshot, nftSnapshot)
	if err != nil {
		t.Fatalf("expected mark attachment apply append to succeed, got %v", err)
	}

	if len(updated.Steps) != len(plan.Steps) {
		t.Fatalf("expected existing managed state to avoid extra steps, got %#v", updated.Steps)
	}
}

func TestAppendMarkAttachmentRemoveUsesObservedHandlesAndCleansManagedChain(t *testing.T) {
	plan := testMarkAttachmentPlan(t, policy.TargetKindInbound, limiter.ActionRemove)
	execution := testMarkAttachmentExecution(t, IdentityKindInbound, plan.Handles.ClassID, plan.Handles.RootHandle)
	plan.MarkAttachment = &execution

	tcSnapshot := Snapshot{
		Device: "eth0",
		QDiscs: []QDiscState{{Kind: "htb", Handle: plan.Handles.RootHandle, Parent: "root"}},
		Classes: []ClassState{{
			Kind:    "htb",
			ClassID: plan.Handles.ClassID,
			Parent:  plan.Handles.RootHandle,
		}},
		Filters: []FilterState{{
			Kind:       "fw",
			Parent:     plan.Handles.RootHandle,
			Protocol:   execution.Filter.Protocol,
			Preference: execution.Filter.Preference,
			Handle:     execution.Filter.handleArg(),
			FlowID:     plan.Handles.ClassID,
		}},
	}
	nftSnapshot := NftablesSnapshot{
		Tables: []NftablesTableState{{Family: execution.Table.Family, Name: execution.Table.Name}},
		Chains: []NftablesChainState{{
			Family:   execution.Chain.Family,
			Table:    execution.Chain.Table,
			Name:     execution.Chain.Name,
			Type:     execution.Chain.Type,
			Hook:     execution.Chain.Hook,
			Priority: execution.Chain.Priority,
		}, {
			Family:   execution.RestoreChain.Family,
			Table:    execution.RestoreChain.Table,
			Name:     execution.RestoreChain.Name,
			Type:     execution.RestoreChain.Type,
			Hook:     execution.RestoreChain.Hook,
			Priority: execution.RestoreChain.Priority,
		}},
		Rules: []NftablesRuleState{{
			Family:  execution.Chain.Family,
			Table:   execution.Chain.Table,
			Chain:   execution.Chain.Name,
			Handle:  17,
			Comment: execution.Rule.Comment,
		}, {
			Family:  execution.RestoreChain.Family,
			Table:   execution.RestoreChain.Table,
			Chain:   execution.RestoreChain.Name,
			Handle:  18,
			Comment: execution.RestoreRule.Comment,
		}},
	}

	updated, err := AppendMarkAttachmentRemove(plan, tcSnapshot, nftSnapshot)
	if err != nil {
		t.Fatalf("expected mark attachment remove append to succeed, got %v", err)
	}

	if len(updated.Steps) != 7 {
		t.Fatalf("expected filter cleanup, nft rule cleanup, restore rule cleanup, chain cleanup, restore chain cleanup, class delete, and root qdisc cleanup, got %#v", updated.Steps)
	}
	if updated.Steps[0].Name != "delete-mark-attachment-filter-1" {
		t.Fatalf("expected filter cleanup first, got %#v", updated.Steps)
	}
	if updated.Steps[1].Name != "delete-mark-attachment-rule-2" {
		t.Fatalf("expected rule cleanup second, got %#v", updated.Steps)
	}
	if updated.Steps[2].Name != "delete-mark-attachment-restore-rule-3" ||
		updated.Steps[3].Name != "delete-mark-attachment-chain" ||
		updated.Steps[4].Name != "delete-mark-attachment-restore-chain" ||
		updated.Steps[5].Name != "delete-class" ||
		updated.Steps[6].Name != "delete-root-qdisc" {
		t.Fatalf("unexpected remove step ordering %#v", updated.Steps)
	}
	if updated.Steps[6].Command.Path != "tc" {
		t.Fatalf("expected root qdisc cleanup to keep using tc, got %#v", updated.Steps[6].Command)
	}
}

func TestAppendMarkAttachmentRemoveKeepsChainWhenOtherRulesRemain(t *testing.T) {
	plan := testMarkAttachmentPlan(t, policy.TargetKindInbound, limiter.ActionRemove)
	execution := testMarkAttachmentExecution(t, IdentityKindInbound, plan.Handles.ClassID, plan.Handles.RootHandle)
	plan.MarkAttachment = &execution

	tcSnapshot := Snapshot{
		Device: "eth0",
		Filters: []FilterState{{
			Kind:       "fw",
			Parent:     plan.Handles.RootHandle,
			Protocol:   execution.Filter.Protocol,
			Preference: execution.Filter.Preference,
			Handle:     execution.Filter.handleArg(),
			FlowID:     plan.Handles.ClassID,
		}},
	}
	nftSnapshot := NftablesSnapshot{
		Tables: []NftablesTableState{{Family: execution.Table.Family, Name: execution.Table.Name}},
		Chains: []NftablesChainState{{
			Family:   execution.Chain.Family,
			Table:    execution.Chain.Table,
			Name:     execution.Chain.Name,
			Type:     execution.Chain.Type,
			Hook:     execution.Chain.Hook,
			Priority: execution.Chain.Priority,
		}, {
			Family:   execution.RestoreChain.Family,
			Table:    execution.RestoreChain.Table,
			Name:     execution.RestoreChain.Name,
			Type:     execution.RestoreChain.Type,
			Hook:     execution.RestoreChain.Hook,
			Priority: execution.RestoreChain.Priority,
		}},
		Rules: []NftablesRuleState{
			{Family: execution.Chain.Family, Table: execution.Chain.Table, Chain: execution.Chain.Name, Handle: 17, Comment: execution.Rule.Comment},
			{Family: execution.Chain.Family, Table: execution.Chain.Table, Chain: execution.Chain.Name, Handle: 18, Comment: "other-managed-rule"},
			{Family: execution.RestoreChain.Family, Table: execution.RestoreChain.Table, Chain: execution.RestoreChain.Name, Handle: 19, Comment: execution.RestoreRule.Comment},
		},
	}

	updated, err := AppendMarkAttachmentRemove(plan, tcSnapshot, nftSnapshot)
	if err != nil {
		t.Fatalf("expected mark attachment remove append to succeed, got %v", err)
	}

	for _, step := range updated.Steps {
		if step.Name == "delete-mark-attachment-chain" {
			t.Fatalf("expected other rules in chain to block chain cleanup, got %#v", updated.Steps)
		}
	}
}

func TestAppendRootQDiscCleanupUsesTCBinaryForMixedPlan(t *testing.T) {
	plan := testMarkAttachmentPlan(t, policy.TargetKindInbound, limiter.ActionRemove)
	plan.Steps = append([]Step{{
		Name: "delete-mark-attachment-rule-1",
		Command: Command{
			Path: "nft",
			Args: []string{"delete", "rule", "inet", "raylimit", "raylimit_inbound_upload", "handle", "17"},
		},
	}}, plan.Steps...)

	updated, err := AppendRootQDiscCleanup(plan)
	if err != nil {
		t.Fatalf("expected root qdisc cleanup append to succeed, got %v", err)
	}

	last := updated.Steps[len(updated.Steps)-1]
	if last.Name != "delete-root-qdisc" || last.Command.Path != "tc" {
		t.Fatalf("expected mixed plan root qdisc cleanup to use tc, got %#v", last)
	}
}
