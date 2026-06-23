package tc

import (
	"context"
	"testing"

	"github.com/PdYrust/RayLimit/internal/limiter"
	"github.com/PdYrust/RayLimit/internal/policy"
)

func TestParseNftablesSnapshotParsesJSONRulesetRegression(t *testing.T) {
	snapshot, err := ParseNftablesSnapshot(`{"nftables":[
		{"metainfo":{"json_schema_version":1}},
		{"table":{"family":"inet","name":"raylimit","handle":7}},
		{"chain":{"family":"inet","table":"raylimit","name":"raylimit_inbound_upload","handle":8,"type":"filter","hook":"input","prio":-150}},
		{"rule":{"family":"inet","table":"raylimit","chain":"raylimit_inbound_upload","handle":9,"comment":"raylimit:mark-attachment:inbound:upload:1:2a:00000001:00000002"}}
	]}`)
	if err != nil {
		t.Fatalf("expected JSON nft ruleset parsing to succeed, got %v", err)
	}

	if len(snapshot.Tables) != 1 || snapshot.Tables[0].Name != "raylimit" || snapshot.Tables[0].Handle != 7 {
		t.Fatalf("unexpected parsed tables: %#v", snapshot.Tables)
	}
	if len(snapshot.Chains) != 1 || snapshot.Chains[0].Hook != "input" || snapshot.Chains[0].Priority != -150 {
		t.Fatalf("unexpected parsed chains: %#v", snapshot.Chains)
	}
	if len(snapshot.Rules) != 1 || snapshot.Rules[0].Handle != 9 ||
		snapshot.Rules[0].Comment != "raylimit:mark-attachment:inbound:upload:1:2a:00000001:00000002" {
		t.Fatalf("unexpected parsed rules: %#v", snapshot.Rules)
	}
}

func TestParseNftablesSnapshotParsesPlainTextRuleset(t *testing.T) {
	stdout := `table inet raylimit { # handle 1
	chain raylimit_inbound_upload { # handle 2
		type filter hook input priority mangle; policy accept;
		tcp dport 443 counter packets 0 bytes 0 meta mark set 0x1 ct mark set 0x1 comment "raylimit:mark-attachment:inbound:upload:1:2a:00000001:00000002" # handle 4
	}
}`

	snapshot, err := ParseNftablesSnapshot(stdout)
	if err != nil {
		t.Fatalf("expected plain-text nft ruleset parsing to succeed, got %v", err)
	}

	if len(snapshot.Tables) != 1 {
		t.Fatalf("expected one table, got %#v", snapshot.Tables)
	}
	table := snapshot.Tables[0]
	if table.Family != "inet" || table.Name != "raylimit" || table.Handle != 1 {
		t.Fatalf("unexpected table: %#v", table)
	}

	if len(snapshot.Chains) != 1 {
		t.Fatalf("expected one chain, got %#v", snapshot.Chains)
	}
	chain := snapshot.Chains[0]
	if chain.Family != "inet" || chain.Table != "raylimit" || chain.Name != "raylimit_inbound_upload" {
		t.Fatalf("unexpected chain identity: %#v", chain)
	}
	if chain.Handle != 2 || chain.Type != "filter" || chain.Hook != "input" {
		t.Fatalf("unexpected chain definition: %#v", chain)
	}
	if chain.Priority != 0 {
		t.Fatalf("expected symbolic priority keyword to leave numeric priority unset, got %#v", chain)
	}

	if len(snapshot.Rules) != 1 {
		t.Fatalf("expected one rule, got %#v", snapshot.Rules)
	}
	rule := snapshot.Rules[0]
	if rule.Family != "inet" || rule.Table != "raylimit" || rule.Chain != "raylimit_inbound_upload" {
		t.Fatalf("unexpected rule identity: %#v", rule)
	}
	if rule.Handle != 4 || rule.Comment != "raylimit:mark-attachment:inbound:upload:1:2a:00000001:00000002" {
		t.Fatalf("unexpected rule fields: %#v", rule)
	}
}

func TestParseNftablesSnapshotPlainTextParsesNumericPriorityAndSkipsUnknownFamily(t *testing.T) {
	stdout := `table arp legacy {
	chain ignored {
		type filter hook input priority 0; policy accept;
	}
}
table ip6 raylimit {
	chain raylimit_outbound_download {
		type filter hook output priority -150; policy accept;
		meta mark 0x2 comment "raylimit:mark-attachment:outbound:download:1:3b:00000002:00000003"
	}
}`

	snapshot, err := ParseNftablesSnapshot(stdout)
	if err != nil {
		t.Fatalf("expected lenient plain-text parsing to succeed, got %v", err)
	}

	if len(snapshot.Tables) != 1 || snapshot.Tables[0].Family != "ip6" {
		t.Fatalf("expected the unsupported arp family table to be skipped, got %#v", snapshot.Tables)
	}
	if len(snapshot.Chains) != 1 || snapshot.Chains[0].Priority != -150 {
		t.Fatalf("expected the numeric priority to be parsed and the arp chain skipped, got %#v", snapshot.Chains)
	}
	if len(snapshot.Rules) != 1 || snapshot.Rules[0].Family != "ip6" {
		t.Fatalf("expected only the supported-family rule, got %#v", snapshot.Rules)
	}
}

func TestParseNftablesSnapshotEmptyOutputYieldsEmptySnapshot(t *testing.T) {
	for _, stdout := range []string{"", "   \n\t"} {
		snapshot, err := ParseNftablesSnapshot(stdout)
		if err != nil {
			t.Fatalf("expected empty nft output to yield an empty snapshot, got %v", err)
		}
		if len(snapshot.Tables) != 0 || len(snapshot.Chains) != 0 || len(snapshot.Rules) != 0 {
			t.Fatalf("expected an empty snapshot, got %#v", snapshot)
		}
	}
}

func TestAppendMarkAttachmentApplyUsesPlannerBinaryForFilterStep(t *testing.T) {
	desired := testDesiredState(t, policy.TargetKindInbound, 2048, 0)
	action := limiter.Action{
		Kind:    limiter.ActionApply,
		Subject: desired.Subject,
		Desired: &desired,
	}
	plan, err := (Planner{Binary: "/sbin/tc"}).Plan(action, Scope{Device: "eth0", Direction: DirectionUpload})
	if err != nil {
		t.Fatalf("expected overridden-binary plan to build, got %v", err)
	}
	execution := testMarkAttachmentExecution(t, IdentityKindInbound, plan.Handles.ClassID, plan.Handles.RootHandle)
	plan.MarkAttachment = &execution

	updated, err := AppendMarkAttachmentApply(plan, Snapshot{Device: "eth0"}, NftablesSnapshot{})
	if err != nil {
		t.Fatalf("expected mark attachment apply append to succeed, got %v", err)
	}

	var filterStep *Step
	for index := range updated.Steps {
		if updated.Steps[index].Name == "upsert-mark-attachment-filter" {
			filterStep = &updated.Steps[index]
			break
		}
	}
	if filterStep == nil {
		t.Fatalf("expected an upsert-mark-attachment-filter step, got %#v", stepNames(updated.Steps))
	}
	if filterStep.Command.Path != "/sbin/tc" {
		t.Fatalf("expected mark attachment filter to use the overridden tc binary, got %q", filterStep.Command.Path)
	}
}

func TestIsTCCommandIgnoresLeadingGlobalFlags(t *testing.T) {
	plan := Plan{
		Steps: []Step{{
			Name:    "noisy",
			Command: Command{Path: "/sbin/tc", Args: []string{"-s", "-N", "filter", "show", "dev", "eth0"}},
		}},
	}

	if got := tcCommandPath(plan); got != "/sbin/tc" {
		t.Fatalf("expected tc command path to survive leading global flags, got %q", got)
	}
}

func TestNftJSONCapabilityCachesProbeResult(t *testing.T) {
	runner := &countingProbeRunner{stdout: `{"nftables":[]}`}
	var capability nftJSONCapability

	if !capability.Supported(context.Background(), runner, "") {
		t.Fatal("expected JSON support to be detected from a JSON probe response")
	}
	if !capability.Supported(context.Background(), runner, "") {
		t.Fatal("expected the cached capability to remain true")
	}
	if runner.calls != 1 {
		t.Fatalf("expected the probe to run exactly once, got %d", runner.calls)
	}
}

func TestNftJSONCapabilityDetectsPlainTextRuntime(t *testing.T) {
	runner := &countingProbeRunner{stdout: "table inet raylimit {\n}"}
	var capability nftJSONCapability

	if capability.Supported(context.Background(), runner, "nft") {
		t.Fatal("expected a plain-text probe response to report no JSON support")
	}
}

// The nft binary override must reach the JSON-capability probe so a custom nft
// path is honored rather than the hardcoded default.
func TestNftJSONCapabilityProbesProvidedBinary(t *testing.T) {
	runner := &inspectRunner{results: []Result{{Stdout: `{"nftables":[]}`}}}
	var capability nftJSONCapability

	if !capability.Supported(context.Background(), runner, "/usr/local/sbin/nft") {
		t.Fatal("expected JSON support to be detected from the JSON probe response")
	}
	if len(runner.commands) != 1 {
		t.Fatalf("expected exactly one probe command, got %d", len(runner.commands))
	}
	if got := runner.commands[0].Path; got != "/usr/local/sbin/nft" {
		t.Fatalf("expected the probe to use the overridden nft binary, got %q", got)
	}
}

// With no override the probe falls back to the default nft binary, preserving
// the pre-flag behavior.
func TestNftJSONCapabilityProbeDefaultsToNftBinary(t *testing.T) {
	runner := &inspectRunner{results: []Result{{Stdout: `{"nftables":[]}`}}}
	var capability nftJSONCapability

	capability.Supported(context.Background(), runner, "")
	if len(runner.commands) != 1 {
		t.Fatalf("expected exactly one probe command, got %d", len(runner.commands))
	}
	if got := runner.commands[0].Path; got != defaultNftBinary {
		t.Fatalf("expected the probe to fall back to %q, got %q", defaultNftBinary, got)
	}
}

// A NftablesInspector with no Binary override must issue its read-only command
// against the default nft binary (backwards-compatible).
func TestNftablesInspectorDefaultsToNftBinary(t *testing.T) {
	runner := &inspectRunner{results: []Result{{Stdout: `{"nftables":[]}`}}}

	if _, _, err := (NftablesInspector{Runner: runner}).Inspect(context.Background()); err != nil {
		t.Fatalf("expected default-binary nft inspect to succeed, got %v", err)
	}
	if len(runner.commands) != 1 {
		t.Fatalf("expected exactly one inspect command, got %d", len(runner.commands))
	}
	if got := runner.commands[0].Path; got != defaultNftBinary {
		t.Fatalf("expected the inspector to fall back to %q, got %q", defaultNftBinary, got)
	}
}

// A NftablesInspector with a Binary override must issue its read-only command
// against that overridden nft binary.
func TestNftablesInspectorUsesOverriddenBinary(t *testing.T) {
	runner := &inspectRunner{results: []Result{{Stdout: `{"nftables":[]}`}}}

	if _, _, err := (NftablesInspector{Runner: runner, Binary: "/usr/local/sbin/nft"}).Inspect(context.Background()); err != nil {
		t.Fatalf("expected overridden-binary nft inspect to succeed, got %v", err)
	}
	if len(runner.commands) != 1 {
		t.Fatalf("expected exactly one inspect command, got %d", len(runner.commands))
	}
	if got := runner.commands[0].Path; got != "/usr/local/sbin/nft" {
		t.Fatalf("expected the inspector to use the overridden nft binary, got %q", got)
	}
}
