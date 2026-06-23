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

func findManagedObjectsByKind(objects []ManagedObject, kind ManagedObjectKind) []ManagedObject {
	matches := make([]ManagedObject, 0)
	for _, object := range objects {
		if object.Kind == kind {
			matches = append(matches, object)
		}
	}

	return matches
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

func TestDesiredManagedStateForIPAllPerIPPlanDefersOwnedObjects(t *testing.T) {
	desired := testDesiredStateForPolicy(t, policy.Policy{
		Name: "ip-all-per-ip-limit",
		Target: policy.Target{
			Kind:          policy.TargetKindIP,
			All:           true,
			IPAggregation: policy.IPAggregationModePerIP,
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
		t.Fatalf("expected per_ip managed test plan to succeed, got %v", err)
	}

	state, err := DesiredManagedState(plan)
	if err != nil {
		t.Fatalf("expected per_ip desired managed state to succeed, got %v", err)
	}

	if !strings.Contains(state.OwnerKey, "|ip|all|per_ip") {
		t.Fatalf("expected per_ip owner key to stay distinct, got %#v", state)
	}
	if len(state.Objects) != 0 {
		t.Fatalf("expected per_ip desired managed state to defer concrete owned objects, got %#v", state.Objects)
	}
}

func TestReconcileInputForPlanUsesDerivedManagedStateSets(t *testing.T) {
	plan := testManagedPlan(t, policy.TargetKindIP, DirectionUpload, 2048)
	snapshot := Snapshot{
		Device: "eth0",
		QDiscs: []QDiscState{{
			Kind:   "htb",
			Handle: plan.Handles.RootHandle,
			Parent: "root",
		}},
		Classes: []ClassState{{
			Kind:               "htb",
			ClassID:            plan.Handles.ClassID,
			Parent:             plan.Handles.RootHandle,
			RateBytesPerSecond: 2048,
		}},
		Filters: []FilterState{{
			Kind:       "u32",
			Parent:     plan.Handles.RootHandle,
			Protocol:   "ip",
			Preference: plan.AttachmentExecution.Rules[0].Preference,
			FlowID:     plan.Handles.ClassID,
		}},
	}

	input, err := ReconcileInputForPlan(snapshot, NftablesSnapshot{}, plan)
	if err != nil {
		t.Fatalf("expected reconcile input derivation to succeed, got %v", err)
	}

	if input.Desired.OwnerKey != input.Observed.OwnerKey {
		t.Fatalf("expected desired and observed owner keys to match, got %#v", input)
	}
	if len(input.Desired.Objects) != 3 {
		t.Fatalf("expected desired managed state to include three objects, got %#v", input.Desired.Objects)
	}
	if len(input.Observed.Objects) != 3 {
		t.Fatalf("expected observed managed state to include three objects, got %#v", input.Observed.Objects)
	}
	if input.Desired.Objects[0].fingerprint() > input.Desired.Objects[1].fingerprint() {
		t.Fatalf("expected desired managed objects to remain deterministically sorted, got %#v", input.Desired.Objects)
	}
	if input.Observed.Objects[0].fingerprint() > input.Observed.Objects[1].fingerprint() {
		t.Fatalf("expected observed managed objects to remain deterministically sorted, got %#v", input.Observed.Objects)
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
