package tc

import (
	"strings"
	"testing"

	"github.com/PdYrust/RayLimit/internal/limiter"
	"github.com/PdYrust/RayLimit/internal/policy"
)

func testManagedPlan(t *testing.T, kind policy.TargetKind, direction Direction, rate int64) Plan {
	t.Helper()

	desired := testDesiredState(t, kind, rate, 0)
	plan, err := (Planner{}).Plan(limiter.Action{
		Kind:    limiter.ActionApply,
		Subject: desired.Subject,
		Desired: &desired,
	}, Scope{
		Device:    "eth0",
		Direction: direction,
	})
	if err != nil {
		t.Fatalf("expected managed test plan to succeed, got %v", err)
	}

	return plan
}

func testInboundMarkAttachmentExecution(t *testing.T, plan Plan) MarkAttachmentExecution {
	t.Helper()

	execution, err := BuildMarkAttachmentExecution(MarkAttachmentInput{
		Identity: *plan.Binding.Identity,
		Scope:    plan.Scope,
		ClassID:  plan.Handles.ClassID,
		Selector: MarkAttachmentSelector{
			Expression:  []string{"tcp", "dport", "8443"},
			Description: `tcp listener 127.0.0.1:8443 for inbound tag "api-in"`,
		},
	})
	if err != nil {
		t.Fatalf("expected inbound mark attachment execution to succeed, got %v", err)
	}

	return execution
}

func testObservedMarkManagedState(scope Scope, classID string, execution MarkAttachmentExecution) (Snapshot, NftablesSnapshot) {
	tcSnapshot := Snapshot{
		Device: scope.Device,
		QDiscs: []QDiscState{{
			Kind:   "htb",
			Handle: execution.Filter.Parent,
			Parent: "root",
		}},
		Classes: []ClassState{{
			Kind:    "htb",
			ClassID: classID,
			Parent:  execution.Filter.Parent,
		}},
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
			Handle: 1,
		}},
		Chains: []NftablesChainState{{
			Family:   execution.Chain.Family,
			Table:    execution.Chain.Table,
			Name:     execution.Chain.Name,
			Type:     execution.Chain.Type,
			Hook:     execution.Chain.Hook,
			Priority: execution.Chain.Priority,
		}},
		Rules: []NftablesRuleState{{
			Family:  execution.Chain.Family,
			Table:   execution.Chain.Table,
			Chain:   execution.Chain.Name,
			Handle:  21,
			Comment: execution.Rule.Comment,
		}},
	}
	if execution.usesRestoreRule() {
		nftSnapshot.Chains = append(nftSnapshot.Chains, NftablesChainState{
			Family:   execution.RestoreChain.Family,
			Table:    execution.RestoreChain.Table,
			Name:     execution.RestoreChain.Name,
			Type:     execution.RestoreChain.Type,
			Hook:     execution.RestoreChain.Hook,
			Priority: execution.RestoreChain.Priority,
		})
		nftSnapshot.Rules = append(nftSnapshot.Rules, NftablesRuleState{
			Family:  execution.RestoreChain.Family,
			Table:   execution.RestoreChain.Table,
			Chain:   execution.RestoreChain.Name,
			Handle:  22,
			Comment: execution.RestoreRule.Comment,
		})
	}

	return tcSnapshot, nftSnapshot
}

func findManagedObjectsByKind(objects []ManagedObject, kind ManagedObjectKind) []ManagedObject {
	matches := make([]ManagedObject, 0)
	for _, object := range objects {
		if object.Kind == kind {
			matches = append(matches, object)
		}
	}

	return matches
}

func findStaleObjectByKind(stale []StaleManagedObject, kind ManagedObjectKind) (StaleManagedObject, bool) {
	for _, object := range stale {
		if object.Object.Kind == kind {
			return object, true
		}
	}

	return StaleManagedObject{}, false
}

func TestDesiredManagedStateForIPPlanUsesConcreteOwnedObjects(t *testing.T) {
	plan := testManagedPlan(t, policy.TargetKindIP, DirectionUpload, 2048)

	state, err := DesiredManagedState(plan)
	if err != nil {
		t.Fatalf("expected desired managed state to succeed, got %v", err)
	}

	if !strings.Contains(state.OwnerKey, "|ip|203.0.113.10") {
		t.Fatalf("expected ip owner key, got %#v", state)
	}
	if len(findManagedObjectsByKind(state.Objects, ManagedObjectRootQDisc)) != 1 ||
		len(findManagedObjectsByKind(state.Objects, ManagedObjectClass)) != 1 ||
		len(findManagedObjectsByKind(state.Objects, ManagedObjectDirectAttachmentFilter)) != 1 {
		t.Fatalf("expected root qdisc, class, and direct attachment ownership, got %#v", state.Objects)
	}
	for _, object := range state.Objects {
		if object.RetainRequiresRuntimeEvidence {
			t.Fatalf("expected concrete ip ownership to remain valid without live runtime evidence, got %#v", state.Objects)
		}
	}
}

func TestDesiredManagedStateForIPBaselinePlanUsesAllOwnerKey(t *testing.T) {
	desired := testDesiredStateForPolicy(t, policy.Policy{
		Name: "ip-all-limit",
		Target: policy.Target{
			Kind: policy.TargetKindIP,
			All:  true,
		},
		Limits: policy.LimitPolicy{
			Upload: &policy.RateLimit{BytesPerSecond: 2048},
		},
	})
	plan, err := (Planner{}).Plan(limiter.Action{
		Kind:    limiter.ActionApply,
		Subject: desired.Subject,
		Desired: &desired,
	}, Scope{
		Device:    "eth0",
		Direction: DirectionUpload,
	})
	if err != nil {
		t.Fatalf("expected baseline managed test plan to succeed, got %v", err)
	}

	state, err := DesiredManagedState(plan)
	if err != nil {
		t.Fatalf("expected baseline desired managed state to succeed, got %v", err)
	}

	if !strings.Contains(state.OwnerKey, "|ip|all") {
		t.Fatalf("expected baseline ip owner key, got %#v", state)
	}
	if len(findManagedObjectsByKind(state.Objects, ManagedObjectRootQDisc)) != 1 ||
		len(findManagedObjectsByKind(state.Objects, ManagedObjectClass)) != 1 ||
		len(findManagedObjectsByKind(state.Objects, ManagedObjectDirectAttachmentFilter)) != 1 {
		t.Fatalf("expected root qdisc, class, and one baseline direct attachment filter, got %#v", state.Objects)
	}
}

func TestDesiredManagedStateForIPUnlimitedPlanOmitsClassOwnership(t *testing.T) {
	desired := testDesiredStateForPolicy(t, policy.Policy{
		Name:   "ip-unlimited",
		Effect: policy.EffectExclude,
		Target: policy.Target{
			Kind:  policy.TargetKindIP,
			Value: "203.0.113.10",
		},
	})
	plan, err := (Planner{}).Plan(limiter.Action{
		Kind:    limiter.ActionApply,
		Subject: desired.Subject,
		Desired: &desired,
	}, Scope{
		Device:    "eth0",
		Direction: DirectionUpload,
	})
	if err != nil {
		t.Fatalf("expected unlimited managed test plan to succeed, got %v", err)
	}

	state, err := DesiredManagedState(plan)
	if err != nil {
		t.Fatalf("expected unlimited desired managed state to succeed, got %v", err)
	}

	if len(findManagedObjectsByKind(state.Objects, ManagedObjectRootQDisc)) != 1 {
		t.Fatalf("expected one managed root qdisc, got %#v", state.Objects)
	}
	if len(findManagedObjectsByKind(state.Objects, ManagedObjectClass)) != 0 {
		t.Fatalf("expected unlimited plan to avoid managed classes, got %#v", state.Objects)
	}
	if len(findManagedObjectsByKind(state.Objects, ManagedObjectDirectAttachmentFilter)) != 1 {
		t.Fatalf("expected unlimited plan to keep one direct attachment filter, got %#v", state.Objects)
	}
}

func TestDesiredManagedStateForInboundMarkPlanRequiresRuntimeEvidence(t *testing.T) {
	plan := testManagedPlan(t, policy.TargetKindInbound, DirectionUpload, 2048)
	execution := testInboundMarkAttachmentExecution(t, plan)
	plan.MarkAttachment = &execution

	state, err := DesiredManagedState(plan)
	if err != nil {
		t.Fatalf("expected desired managed state to succeed, got %v", err)
	}

	for _, kind := range []ManagedObjectKind{
		ManagedObjectRootQDisc,
		ManagedObjectClass,
		ManagedObjectMarkAttachmentTable,
		ManagedObjectMarkAttachmentChain,
		ManagedObjectMarkAttachmentRestoreChain,
		ManagedObjectMarkAttachmentRule,
		ManagedObjectMarkAttachmentRestoreRule,
		ManagedObjectMarkAttachmentFilter,
	} {
		if len(findManagedObjectsByKind(state.Objects, kind)) != 1 {
			t.Fatalf("expected one %s managed object, got %#v", kind, state.Objects)
		}
	}
	for _, object := range state.Objects {
		if !object.RetainRequiresRuntimeEvidence {
			t.Fatalf("expected inbound mark-backed ownership to require runtime evidence for retention, got %#v", state.Objects)
		}
	}
}

func TestClassifyManagedStateMarksObservedIPObjectsAsStaleAndCleanupEligible(t *testing.T) {
	plan := testManagedPlan(t, policy.TargetKindIP, DirectionUpload, 2048)
	snapshot := Snapshot{
		Device: "eth0",
		QDiscs: []QDiscState{{
			Kind:   "htb",
			Handle: plan.Handles.RootHandle,
			Parent: "root",
		}},
		Classes: []ClassState{{
			Kind:    "htb",
			ClassID: plan.Handles.ClassID,
			Parent:  plan.Handles.RootHandle,
		}},
		Filters: []FilterState{{
			Kind:       "u32",
			Parent:     plan.Handles.RootHandle,
			Protocol:   "ip",
			Preference: plan.AttachmentExecution.Rules[0].Preference,
			FlowID:     plan.Handles.ClassID,
		}},
	}

	observed, err := ObservedManagedState(snapshot, NftablesSnapshot{}, plan)
	if err != nil {
		t.Fatalf("expected observed managed state to succeed, got %v", err)
	}
	inventory, err := ClassifyManagedState(ManagedStateSet{OwnerKey: observed.OwnerKey}, observed)
	if err != nil {
		t.Fatalf("expected managed state classification to succeed, got %v", err)
	}

	if len(inventory.Stale) != 3 {
		t.Fatalf("expected root qdisc, class, and direct attachment filter to be stale, got %#v", inventory.Stale)
	}
	root, ok := findStaleObjectByKind(inventory.Stale, ManagedObjectRootQDisc)
	if !ok || !root.CleanupEligible {
		t.Fatalf("expected stale root qdisc cleanup to be eligible after stale direct cleanup, got %#v", inventory.Stale)
	}
}

func TestClassifyManagedStateMakesManagedMarkTableCleanupEligibleWhenOnlyManagedChainsRemain(t *testing.T) {
	plan := testManagedPlan(t, policy.TargetKindInbound, DirectionUpload, 2048)
	execution := testInboundMarkAttachmentExecution(t, plan)
	plan.MarkAttachment = &execution
	tcSnapshot, nftSnapshot := testObservedMarkManagedState(plan.Scope, plan.Handles.ClassID, execution)

	observed, err := ObservedManagedState(tcSnapshot, nftSnapshot, plan)
	if err != nil {
		t.Fatalf("expected observed mark-backed managed state to succeed, got %v", err)
	}
	inventory, err := ClassifyManagedState(ManagedStateSet{OwnerKey: observed.OwnerKey}, observed)
	if err != nil {
		t.Fatalf("expected mark-backed managed state classification to succeed, got %v", err)
	}

	table, ok := findStaleObjectByKind(inventory.Stale, ManagedObjectMarkAttachmentTable)
	if !ok || !table.CleanupEligible {
		t.Fatalf("expected managed mark table cleanup to stay eligible when only managed chains remain, got %#v", inventory.Stale)
	}
	if !strings.Contains(table.CleanupReason, "only managed chains remain") {
		t.Fatalf("expected explicit table cleanup limitation, got %#v", table)
	}
	chain, ok := findStaleObjectByKind(inventory.Stale, ManagedObjectMarkAttachmentChain)
	if !ok || !chain.CleanupEligible {
		t.Fatalf("expected managed mark chain cleanup to stay eligible when only managed rules remain, got %#v", inventory.Stale)
	}
}

func TestClassifyManagedStateKeepsManagedMarkTableBlockedWhenUnrelatedChainRemains(t *testing.T) {
	plan := testManagedPlan(t, policy.TargetKindInbound, DirectionUpload, 2048)
	execution := testInboundMarkAttachmentExecution(t, plan)
	plan.MarkAttachment = &execution
	tcSnapshot, nftSnapshot := testObservedMarkManagedState(plan.Scope, plan.Handles.ClassID, execution)
	nftSnapshot.Chains = append(nftSnapshot.Chains, NftablesChainState{
		Family: execution.Table.Family,
		Table:  execution.Table.Name,
		Name:   "manual-chain",
	})

	observed, err := ObservedManagedState(tcSnapshot, nftSnapshot, plan)
	if err != nil {
		t.Fatalf("expected observed mark-backed managed state to succeed, got %v", err)
	}
	inventory, err := ClassifyManagedState(ManagedStateSet{OwnerKey: observed.OwnerKey}, observed)
	if err != nil {
		t.Fatalf("expected mark-backed managed state classification to succeed, got %v", err)
	}

	table, ok := findStaleObjectByKind(inventory.Stale, ManagedObjectMarkAttachmentTable)
	if !ok || table.CleanupEligible {
		t.Fatalf("expected unrelated chain to block managed mark table cleanup, got %#v", inventory.Stale)
	}
	if !strings.Contains(table.CleanupReason, "unmanaged or unrelated chains") {
		t.Fatalf("expected explicit blocked table cleanup reason, got %#v", table)
	}
}
