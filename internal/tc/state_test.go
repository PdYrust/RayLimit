package tc

import (
	"context"
	"errors"
	"testing"

	"github.com/PdYrust/RayLimit/internal/limiter"
	"github.com/PdYrust/RayLimit/internal/policy"
)

type inspectRunner struct {
	commands []Command
	results  []Result
	errors   []error
}

func (r *inspectRunner) Run(_ context.Context, command Command) (Result, error) {
	r.commands = append(r.commands, command)

	index := len(r.commands) - 1
	var result Result
	if index < len(r.results) {
		result = r.results[index]
	}
	result.Command = command

	var err error
	if index < len(r.errors) {
		err = r.errors[index]
	}

	return result, err
}

func TestInspectRequestValidateRejectsInvalidDevice(t *testing.T) {
	err := (InspectRequest{Device: "eth 0"}).Validate()
	if err == nil {
		t.Fatal("expected invalid device to fail validation")
	}
}

func TestInspectorInspectBuildsReadOnlyCommands(t *testing.T) {
	runner := &inspectRunner{
		results: []Result{
			{Stdout: `[{"kind":"htb","handle":"1:"}]`},
			{Stdout: `[{"kind":"htb","classid":"1:2a","parent":"1:","options":{"rate":"2048bps","ceil":"4096bps"}}]`},
			{Stdout: `[{"kind":"u32","parent":"1:","protocol":"ip"}]`},
		},
	}

	snapshot, results, err := (Inspector{Runner: runner}).Inspect(context.Background(), InspectRequest{Device: "eth0"})
	if err != nil {
		t.Fatalf("expected inspect to succeed, got %v", err)
	}

	if len(runner.commands) != 3 {
		t.Fatalf("expected three read-only commands, got %#v", runner.commands)
	}
	if len(results) != 3 {
		t.Fatalf("expected three command results, got %#v", results)
	}
	if runner.commands[0].Args[0] != "-j" || runner.commands[0].Args[1] != "qdisc" {
		t.Fatalf("unexpected qdisc command: %#v", runner.commands[0])
	}
	if runner.commands[1].Args[1] != "class" || runner.commands[2].Args[1] != "filter" {
		t.Fatalf("unexpected inspect commands: %#v", runner.commands)
	}
	if snapshot.Device != "eth0" {
		t.Fatalf("unexpected snapshot device: %#v", snapshot)
	}
	if len(snapshot.QDiscs) != 1 || len(snapshot.Classes) != 1 || len(snapshot.Filters) != 1 {
		t.Fatalf("unexpected parsed snapshot: %#v", snapshot)
	}
}

func TestParseSnapshotParsesRepresentativeOutput(t *testing.T) {
	snapshot, err := ParseSnapshot("eth0", []Result{
		{
			Step:   "show-qdisc",
			Stdout: `[{"kind":"htb","handle":"1:"}]`,
		},
		{
			Step: "show-class",
			Stdout: `[
				{"kind":"htb","classid":"1:2a","parent":"1:","options":{"rate":"2048bps","ceil":"4096bps"}},
				{"kind":"htb","handle":"1:2b","parent":"1:","rate":"1024bps"}
			]`,
		},
		{
			Step:   "show-filter",
			Stdout: `[{"kind":"u32","parent":"1:","protocol":"ip","pref":101,"options":{"flowid":"1:2a"}}]`,
		},
	})
	if err != nil {
		t.Fatalf("expected snapshot parsing to succeed, got %v", err)
	}

	if len(snapshot.QDiscs) != 1 || snapshot.QDiscs[0].Handle != "1:" {
		t.Fatalf("unexpected qdisc state: %#v", snapshot.QDiscs)
	}
	if len(snapshot.Classes) != 2 {
		t.Fatalf("unexpected class state count: %#v", snapshot.Classes)
	}
	if snapshot.Classes[0].RateBytesPerSecond != 2048 || snapshot.Classes[0].CeilBytesPerSecond != 4096 {
		t.Fatalf("unexpected parsed class rates: %#v", snapshot.Classes[0])
	}
	if snapshot.Classes[1].ClassID != "1:2b" || snapshot.Classes[1].RateBytesPerSecond != 1024 {
		t.Fatalf("unexpected parsed secondary class: %#v", snapshot.Classes[1])
	}
	if len(snapshot.Filters) != 1 || snapshot.Filters[0].Protocol != "ip" {
		t.Fatalf("unexpected filter state: %#v", snapshot.Filters)
	}
	if snapshot.Filters[0].Preference != 101 || snapshot.Filters[0].FlowID != "1:2a" {
		t.Fatalf("expected filter preference and flowid to parse, got %#v", snapshot.Filters[0])
	}
}

func TestParseSnapshotParsesObservedBitRateUnits(t *testing.T) {
	snapshot, err := ParseSnapshot("eth0", []Result{
		{
			Step: "show-class",
			Stdout: `[
				{"kind":"htb","classid":"1:2a","parent":"1:","options":{"rate":"16384bit","ceil":"32768bit"}},
				{"kind":"htb","classid":"1:2b","parent":"1:","options":{"rate":"16.384Kbit","ceil":"32.768Kbit"}}
			]`,
		},
	})
	if err != nil {
		t.Fatalf("expected bit-based class JSON to parse, got %v", err)
	}

	if len(snapshot.Classes) != 2 {
		t.Fatalf("unexpected class count: %#v", snapshot.Classes)
	}
	if snapshot.Classes[0].RateBytesPerSecond != 2048 || snapshot.Classes[0].CeilBytesPerSecond != 4096 {
		t.Fatalf("expected bit-based class rates to parse to bytes/s, got %#v", snapshot.Classes[0])
	}
	if snapshot.Classes[1].RateBytesPerSecond != 2048 || snapshot.Classes[1].CeilBytesPerSecond != 4096 {
		t.Fatalf("expected fractional kbit class rates to parse to bytes/s, got %#v", snapshot.Classes[1])
	}
}

func TestParseSnapshotAcceptsNumericRate64Fields(t *testing.T) {
	snapshot, err := ParseSnapshot("eth0", []Result{
		{
			Step:   "show-class",
			Stdout: `[{"kind":"htb","classid":"1:2a","parent":"1:","options":{"rate64":2048,"ceil64":4096}}]`,
		},
	})
	if err != nil {
		t.Fatalf("expected numeric rate64 fields to parse, got %v", err)
	}

	if len(snapshot.Classes) != 1 {
		t.Fatalf("unexpected class count: %#v", snapshot.Classes)
	}
	if snapshot.Classes[0].RateBytesPerSecond != 2048 || snapshot.Classes[0].CeilBytesPerSecond != 4096 {
		t.Fatalf("expected rate64 fields to parse to bytes/s, got %#v", snapshot.Classes[0])
	}
}

func TestParseSnapshotRejectsMalformedJSON(t *testing.T) {
	_, err := ParseSnapshot("eth0", []Result{
		{
			Step:   "show-class",
			Stdout: `[{"kind":"htb"`,
		},
	})
	if err == nil {
		t.Fatal("expected malformed class JSON to fail parsing")
	}
}

func TestParseSnapshotAcceptsPartialClassMetadata(t *testing.T) {
	snapshot, err := ParseSnapshot("eth0", []Result{
		{
			Step:   "show-class",
			Stdout: `[{"kind":"htb","classid":"1:2a","parent":"1:"}]`,
		},
	})
	if err != nil {
		t.Fatalf("expected partial class metadata to parse, got %v", err)
	}

	if len(snapshot.Classes) != 1 {
		t.Fatalf("unexpected class count: %#v", snapshot.Classes)
	}
	if snapshot.Classes[0].RateBytesPerSecond != 0 || snapshot.Classes[0].CeilBytesPerSecond != 0 {
		t.Fatalf("expected missing class rates to remain unset, got %#v", snapshot.Classes[0])
	}
}

func TestParseSnapshotAcceptsRealClassFieldFromTCJSON(t *testing.T) {
	snapshot, err := ParseSnapshot("lo", []Result{
		{
			Step:   "show-class",
			Stdout: `[{"class":"htb","classid":"1:82a4","parent":"1:","options":{"rate":"2048bps","ceil":"2048bps"}}]`,
		},
	})
	if err != nil {
		t.Fatalf("expected tc class JSON with class field to parse, got %v", err)
	}

	if len(snapshot.Classes) != 1 {
		t.Fatalf("unexpected class count: %#v", snapshot.Classes)
	}
	if snapshot.Classes[0].Kind != "htb" {
		t.Fatalf("expected class field to populate kind, got %#v", snapshot.Classes[0])
	}
	if snapshot.Classes[0].ClassID != "1:82a4" {
		t.Fatalf("unexpected class id: %#v", snapshot.Classes[0])
	}
}

func TestParsedObservedClassAppliedStateSupportsIPv6Subjects(t *testing.T) {
	snapshot, err := ParseSnapshot("lo", []Result{
		{
			Step:   "show-class",
			Stdout: `[{"class":"htb","classid":"1:82a4","parent":"1:","options":{"rate":"16.384Kbit","ceil":"16.384Kbit"}}]`,
		},
	})
	if err != nil {
		t.Fatalf("expected tc class JSON to parse, got %v", err)
	}

	subject := limiter.Subject{
		Kind:  policy.TargetKindIP,
		Value: "::1",
		Binding: limiter.RuntimeBinding{
			Runtime: testSession().Runtime,
		},
	}
	applied, err := snapshot.Classes[0].AppliedState(subject, DirectionUpload)
	if err != nil {
		t.Fatalf("expected parsed class to reconcile for an ipv6 subject, got %v", err)
	}
	if applied.Limits.Upload == nil || applied.Limits.Upload.BytesPerSecond != 2048 {
		t.Fatalf("expected parsed observed rate to remain 2048 bytes/s, got %#v", applied)
	}
}

func TestSnapshotEligibleForRootQDiscCleanupReturnsTrueWhenOnlyManagedStateRemains(t *testing.T) {
	snapshot := Snapshot{
		Device: "lo",
		QDiscs: []QDiscState{
			{
				Kind:   "htb",
				Handle: "1:",
				Parent: "root",
			},
		},
		Classes: []ClassState{
			{
				Kind:    "htb",
				ClassID: "1:2a",
				Parent:  "1:",
			},
		},
	}

	if !snapshot.EligibleForRootQDiscCleanup("1:", "1:2a") {
		t.Fatalf("expected snapshot to be eligible for root qdisc cleanup, got %#v", snapshot)
	}
}

func TestSnapshotEligibleForRootQDiscCleanupReturnsFalseWhenAdditionalStateRemains(t *testing.T) {
	testCases := []struct {
		name     string
		snapshot Snapshot
	}{
		{
			name: "extra class",
			snapshot: Snapshot{
				Device: "lo",
				QDiscs: []QDiscState{{Kind: "htb", Handle: "1:", Parent: "root"}},
				Classes: []ClassState{
					{Kind: "htb", ClassID: "1:2a", Parent: "1:"},
					{Kind: "htb", ClassID: "1:2b", Parent: "1:"},
				},
			},
		},
		{
			name: "attached filter",
			snapshot: Snapshot{
				Device:  "lo",
				QDiscs:  []QDiscState{{Kind: "htb", Handle: "1:", Parent: "root"}},
				Classes: []ClassState{{Kind: "htb", ClassID: "1:2a", Parent: "1:"}},
				Filters: []FilterState{{Kind: "u32", Parent: "1:", Protocol: "ip"}},
			},
		},
		{
			name: "non-root parent",
			snapshot: Snapshot{
				Device:  "lo",
				QDiscs:  []QDiscState{{Kind: "htb", Handle: "1:", Parent: "1:1"}},
				Classes: []ClassState{{Kind: "htb", ClassID: "1:2a", Parent: "1:"}},
			},
		},
	}

	for _, tc := range testCases {
		if tc.snapshot.EligibleForRootQDiscCleanup("1:", "1:2a") {
			t.Fatalf("expected %s snapshot to keep the root qdisc intact, got %#v", tc.name, tc.snapshot)
		}
	}
}

func TestSnapshotEligibleForRootQDiscCleanupAfterManagedObjectRemovalReturnsTrueWhenSelectedObjectsCoverObservedState(t *testing.T) {
	snapshot := Snapshot{
		Device: "lo",
		QDiscs: []QDiscState{{
			Kind:   "htb",
			Handle: "1:",
			Parent: "root",
		}},
		Classes: []ClassState{
			{Kind: "htb", ClassID: "1:2a", Parent: "1:"},
			{Kind: "htb", ClassID: "1:2b", Parent: "1:"},
		},
		Filters: []FilterState{
			{Kind: "u32", Parent: "1:", Protocol: "ip", Preference: 120, FlowID: "1:2a"},
			{Kind: "u32", Parent: "1:", Protocol: "ip", Preference: 140, FlowID: "1:2b"},
		},
	}

	if !snapshot.EligibleForRootQDiscCleanupAfterManagedObjectRemoval("1:", []ManagedObject{
		{Kind: ManagedObjectRootQDisc, Device: "lo", RootHandle: "1:", ID: "1:"},
		{Kind: ManagedObjectClass, Device: "lo", RootHandle: "1:", ID: "1:2a"},
		{Kind: ManagedObjectClass, Device: "lo", RootHandle: "1:", ID: "1:2b"},
		{Kind: ManagedObjectDirectAttachmentFilter, Device: "lo", RootHandle: "1:", ID: directAttachmentManagedObjectID("1:", "u32", "ip", 120, "1:2a")},
		{Kind: ManagedObjectDirectAttachmentFilter, Device: "lo", RootHandle: "1:", ID: directAttachmentManagedObjectID("1:", "u32", "ip", 140, "1:2b")},
	}) {
		t.Fatalf("expected selected managed objects to make root qdisc cleanup eligible, got %#v", snapshot)
	}
}

func TestSnapshotEligibleForRootQDiscCleanupAfterManagedObjectRemovalReturnsFalseWhenObservedStateRemains(t *testing.T) {
	snapshot := Snapshot{
		Device: "lo",
		QDiscs: []QDiscState{{
			Kind:   "htb",
			Handle: "1:",
			Parent: "root",
		}},
		Classes: []ClassState{
			{Kind: "htb", ClassID: "1:2a", Parent: "1:"},
			{Kind: "htb", ClassID: "1:2b", Parent: "1:"},
		},
		Filters: []FilterState{
			{Kind: "u32", Parent: "1:", Protocol: "ip", Preference: 120, FlowID: "1:2a"},
			{Kind: "u32", Parent: "1:", Protocol: "ip", Preference: 140, FlowID: "1:2b"},
		},
	}

	if snapshot.EligibleForRootQDiscCleanupAfterManagedObjectRemoval("1:", []ManagedObject{
		{Kind: ManagedObjectRootQDisc, Device: "lo", RootHandle: "1:", ID: "1:"},
		{Kind: ManagedObjectClass, Device: "lo", RootHandle: "1:", ID: "1:2a"},
		{Kind: ManagedObjectDirectAttachmentFilter, Device: "lo", RootHandle: "1:", ID: directAttachmentManagedObjectID("1:", "u32", "ip", 120, "1:2a")},
	}) {
		t.Fatalf("expected remaining observed managed state to block root qdisc cleanup, got %#v", snapshot)
	}
}

func TestSnapshotDirectAttachmentFiltersReturnsMatchingManagedFilters(t *testing.T) {
	execution := DirectAttachmentExecution{
		Readiness:  BindingReadinessReady,
		Confidence: BindingConfidenceHigh,
		Rules: []DirectAttachmentRule{
			{
				Identity:    TrafficIdentity{Kind: IdentityKindClientIP, Value: "203.0.113.10"},
				Classifier:  DirectAttachmentClassifierU32,
				Disposition: DirectAttachmentDispositionClassify,
				MatchField:  AttachmentMatchSource,
				Preference:  120,
				ClassID:     "1:2a",
				Readiness:   BindingReadinessReady,
				Confidence:  BindingConfidenceHigh,
			},
			{
				Identity:    TrafficIdentity{Kind: IdentityKindClientIP, Value: "203.0.113.11"},
				Classifier:  DirectAttachmentClassifierU32,
				Disposition: DirectAttachmentDispositionClassify,
				MatchField:  AttachmentMatchSource,
				Preference:  140,
				ClassID:     "1:2a",
				Readiness:   BindingReadinessReady,
				Confidence:  BindingConfidenceHigh,
			},
		},
	}
	snapshot := Snapshot{
		Device: "lo",
		Filters: []FilterState{
			{Kind: "u32", Parent: "1:", Protocol: "ip", Preference: 140, FlowID: "1:2a"},
			{Kind: "u32", Parent: "1:", Protocol: "ip", Preference: 120, FlowID: "1:2a"},
			{Kind: "u32", Parent: "1:", Protocol: "ip", Preference: 160, FlowID: "1:2b"},
			{Kind: "flower", Parent: "1:", Protocol: "ip", Preference: 180, FlowID: "1:2a"},
		},
	}

	filters := snapshot.DirectAttachmentFilters("1:", "1:2a", execution)
	if len(filters) != 2 {
		t.Fatalf("expected two matching direct attachment filters, got %#v", filters)
	}
	if filters[0].Preference != 120 || filters[1].Preference != 140 {
		t.Fatalf("expected matching filters to remain deterministic by preference, got %#v", filters)
	}
}

func TestSnapshotDirectAttachmentFiltersReturnsMatchingManagedIPv6Filters(t *testing.T) {
	execution := DirectAttachmentExecution{
		Readiness:  BindingReadinessReady,
		Confidence: BindingConfidenceMedium,
		Rules: []DirectAttachmentRule{
			{
				Identity:    TrafficIdentity{Kind: IdentityKindClientIP, Value: "2001:db8::10"},
				Classifier:  DirectAttachmentClassifierU32,
				Disposition: DirectAttachmentDispositionClassify,
				MatchField:  AttachmentMatchSource,
				Preference:  120,
				ClassID:     "1:2a",
				Readiness:   BindingReadinessReady,
				Confidence:  BindingConfidenceMedium,
			},
		},
	}
	snapshot := Snapshot{
		Device: "lo",
		Filters: []FilterState{
			{Kind: "u32", Parent: "1:", Protocol: "ipv6", Preference: 120, FlowID: "1:2a"},
			{Kind: "u32", Parent: "1:", Protocol: "ip", Preference: 120, FlowID: "1:2a"},
		},
	}

	filters := snapshot.DirectAttachmentFilters("1:", "1:2a", execution)
	if len(filters) != 1 || filters[0].Protocol != "ipv6" {
		t.Fatalf("expected one matching ipv6 direct attachment filter, got %#v", filters)
	}
}

func TestClassStateAppliedStateBuildsLimiterState(t *testing.T) {
	subject := testDesiredState(t, policy.TargetKindIP, 2048, 0).Subject
	class := ClassState{
		Kind:               "htb",
		ClassID:            "1:2a",
		Parent:             "1:",
		RateBytesPerSecond: 2048,
	}

	applied, err := class.AppliedState(subject, DirectionUpload)
	if err != nil {
		t.Fatalf("expected applied state construction to succeed, got %v", err)
	}

	if applied.Driver != driverName {
		t.Fatalf("unexpected driver: %#v", applied)
	}
	if applied.Reference != "1:2a" {
		t.Fatalf("unexpected class reference: %#v", applied)
	}
	if applied.Limits.Upload == nil || applied.Limits.Upload.BytesPerSecond != 2048 {
		t.Fatalf("unexpected applied upload limit: %#v", applied)
	}
}

func TestInspectorInspectReturnsRunnerFailure(t *testing.T) {
	runner := &inspectRunner{
		results: []Result{
			{Stdout: `[]`},
			{Stderr: "failed", ExitCode: 1},
		},
		errors: []error{
			nil,
			errors.New("command failed"),
		},
	}

	_, results, err := (Inspector{Runner: runner}).Inspect(context.Background(), InspectRequest{Device: "eth0"})
	if err == nil {
		t.Fatal("expected inspect runner failure to be returned")
	}

	if len(results) != 2 {
		t.Fatalf("expected partial read results, got %#v", results)
	}
	if results[1].Step != "show-class" || results[1].Error != "command failed" {
		t.Fatalf("unexpected failing inspect result: %#v", results[1])
	}
}
