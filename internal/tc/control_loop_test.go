package tc

import (
	"strings"
	"testing"
	"time"

	"github.com/PdYrust/RayLimit/internal/discovery"
	"github.com/PdYrust/RayLimit/internal/policy"
)

func testControlLoopRuntimeOwnerKey() string {
	return "host_process|xray|edge-a|1001||inbound|api-in"
}

func testControlLoopRuntimeDerivedState(objects ...ManagedObject) ManagedStateSet {
	return ManagedStateSet{
		OwnerKey: testControlLoopRuntimeOwnerKey(),
		Objects:  append([]ManagedObject(nil), objects...),
	}
}

func TestControlLoopInputValidateRejectsDesiredObservedOwnerMismatch(t *testing.T) {
	input := ControlLoopInput{
		Desired:  ManagedStateSet{OwnerKey: "host_process|xray|edge-a|1001||ip|203.0.113.10"},
		Observed: ManagedStateSet{OwnerKey: "host_process|xray|edge-a|1001||outbound|proxy-out"},
	}

	err := input.Validate()
	if err == nil || !strings.Contains(err.Error(), "do not describe the same owner") {
		t.Fatalf("expected desired/observed owner mismatch to fail early, got %v", err)
	}
}

func TestControlLoopCoordinatorNoChangeForMatchingConcreteState(t *testing.T) {
	plan := testManagedPlan(t, policy.TargetKindIP, DirectionUpload, 2048)
	desired, err := DesiredManagedState(plan)
	if err != nil {
		t.Fatalf("expected desired managed state to succeed, got %v", err)
	}

	result, err := (ControlLoopCoordinator{}).Execute(ControlLoopInput{
		Desired:  desired,
		Observed: desired,
	})
	if err != nil {
		t.Fatalf("expected control-loop no-change to succeed, got %v", err)
	}

	if result.Kind != ControlLoopOutcomeNoChange {
		t.Fatalf("expected no_change control-loop outcome, got %#v", result)
	}
	if result.Reconcile == nil || result.Reconcile.Kind != ReconcileOutcomeNoChange {
		t.Fatalf("expected no_change reconcile result, got %#v", result)
	}
}

func TestControlLoopCoordinatorUsesGraceRetainedSignalForRuntimeDerivedOwner(t *testing.T) {
	desired := testControlLoopRuntimeDerivedState(
		testPeriodicReconcileObject(ManagedObjectRootQDisc, "1:", true, false, true),
		testPeriodicReconcileObject(ManagedObjectMarkAttachmentTable, "inet|raylimit_eth0_upload", true, false, false),
	)
	graceUntil := time.Date(2026, time.March, 15, 16, 0, 0, 0, time.UTC)

	result, err := (ControlLoopCoordinator{}).Execute(ControlLoopInput{
		Desired:  desired,
		Observed: desired,
		RuntimeSignals: ControlLoopRuntimeSignals{
			RuntimeEvidence: &discovery.RuntimeEvidenceChurnDecision{
				Action:     discovery.RuntimeEvidenceChurnActionGraceRetained,
				GraceUntil: &graceUntil,
				Reason:     "recent trusted presence remains within disconnect grace",
			},
		},
	})
	if err != nil {
		t.Fatalf("expected grace-retained control-loop result, got %v", err)
	}

	if result.Kind != ControlLoopOutcomeGraceRetained {
		t.Fatalf("expected grace_retained control-loop outcome, got %#v", result)
	}
	if result.GraceUntil == nil || !result.GraceUntil.Equal(graceUntil) {
		t.Fatalf("expected grace deadline to be preserved, got %#v", result)
	}
	if result.Reconcile == nil || result.Reconcile.Kind != ReconcileOutcomeNoChange {
		t.Fatalf("expected no_change reconcile result under grace, got %#v", result)
	}
}

func TestControlLoopCoordinatorUsesRefreshRequiredSignalForRuntimeDerivedDelta(t *testing.T) {
	desired := testControlLoopRuntimeDerivedState(
		testPeriodicReconcileObject(ManagedObjectRootQDisc, "1:", true, false, true),
		testPeriodicReconcileObject(ManagedObjectMarkAttachmentTable, "inet|raylimit_eth0_upload", true, false, false),
	)

	result, err := (ControlLoopCoordinator{}).Execute(ControlLoopInput{
		Desired:  desired,
		Observed: ManagedStateSet{OwnerKey: desired.OwnerKey},
		RuntimeSignals: ControlLoopRuntimeSignals{
			RuntimeEvidence: &discovery.RuntimeEvidenceChurnDecision{
				Action: discovery.RuntimeEvidenceChurnActionRefreshRequired,
				Reason: "runtime-derived owner evidence requires a fresher refresh",
			},
		},
	})
	if err != nil {
		t.Fatalf("expected refresh-required control-loop result, got %v", err)
	}

	if result.Kind != ControlLoopOutcomeRefreshRequired {
		t.Fatalf("expected refresh_required control-loop outcome, got %#v", result)
	}
	if result.Reconcile == nil || result.Reconcile.Kind != ReconcileOutcomeBlockedMissingEvidence {
		t.Fatalf("expected blocked_missing_evidence reconcile result, got %#v", result)
	}
}
