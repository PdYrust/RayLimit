package tc

import (
	"strings"
	"testing"
	"time"

	"github.com/PdYrust/RayLimit/internal/discovery"
)

func testRestartRecoveryInventory(t *testing.T, observed ...ManagedObject) ManagedStateInventory {
	t.Helper()

	inventory, err := ClassifyManagedState(
		ManagedStateSet{OwnerKey: "host_process|xray|edge-a|4242||inbound|api-in"},
		ManagedStateSet{
			OwnerKey: "host_process|xray|edge-a|4242||inbound|api-in",
			Objects:  append([]ManagedObject(nil), observed...),
		},
	)
	if err != nil {
		t.Fatalf("expected managed-state inventory classification to succeed, got %v", err)
	}

	return inventory
}

func TestRestartRecovererRecoversConcreteObservedStateWithoutRuntimeEvidence(t *testing.T) {
	inventory, err := ClassifyManagedState(
		ManagedStateSet{OwnerKey: "host_process|xray|edge-a|4242||ip|203.0.113.10"},
		ManagedStateSet{
			OwnerKey: "host_process|xray|edge-a|4242||ip|203.0.113.10",
			Objects: []ManagedObject{
				testPeriodicReconcileObject(ManagedObjectRootQDisc, "1:", false, false, true),
				testPeriodicReconcileObject(ManagedObjectClass, "1:1001", false, false, false),
				testPeriodicReconcileObject(ManagedObjectDirectAttachmentFilter, "1:|u32|ip|49153|1:1001", false, false, false),
			},
		},
	)
	if err != nil {
		t.Fatalf("expected concrete restart inventory to succeed, got %v", err)
	}

	result, err := (RestartRecoverer{}).Decide(RestartRecoveryInput{Inventory: inventory})
	if err != nil {
		t.Fatalf("expected concrete restart recovery to succeed, got %v", err)
	}

	if result.Kind != RestartRecoveryRecoverableObservedState {
		t.Fatalf("expected recoverable_observed_state result, got %#v", result)
	}
	if len(result.RecoverableObserved) != 3 {
		t.Fatalf("expected all concrete observed objects to be recoverable, got %#v", result)
	}
}

func TestRestartRecovererRequiresRefreshForRuntimeDerivedStateWithoutCachedEvidence(t *testing.T) {
	inventory := testRestartRecoveryInventory(
		t,
		testPeriodicReconcileObject(ManagedObjectRootQDisc, "1:", true, false, true),
		testPeriodicReconcileObject(ManagedObjectMarkAttachmentTable, "inet|raylimit_eth0_upload", true, false, false),
	)

	result, err := (RestartRecoverer{}).Decide(RestartRecoveryInput{Inventory: inventory})
	if err != nil {
		t.Fatalf("expected runtime-derived restart recovery to succeed, got %v", err)
	}

	if result.Kind != RestartRecoveryRefreshRequired {
		t.Fatalf("expected restart_refresh_required result, got %#v", result)
	}
	if !strings.Contains(result.Reason, "cached runtime evidence is missing after restart") {
		t.Fatalf("expected missing cached evidence reason, got %#v", result)
	}
}

func TestRestartRecovererKeepsRuntimeDerivedStateRecoverableWhenEvidenceIsStable(t *testing.T) {
	inventory := testRestartRecoveryInventory(
		t,
		testPeriodicReconcileObject(ManagedObjectRootQDisc, "1:", true, false, true),
		testPeriodicReconcileObject(ManagedObjectMarkAttachmentTable, "inet|raylimit_eth0_upload", true, false, false),
	)

	result, err := (RestartRecoverer{}).Decide(RestartRecoveryInput{
		Inventory: inventory,
		RuntimeEvidence: &discovery.RuntimeEvidenceChurnDecision{
			Action: discovery.RuntimeEvidenceChurnActionStable,
			Reason: "fresh runtime evidence still sees the owner",
		},
	})
	if err != nil {
		t.Fatalf("expected stable runtime-derived restart recovery to succeed, got %v", err)
	}

	if result.Kind != RestartRecoveryRecoverableObservedState {
		t.Fatalf("expected recoverable_observed_state result, got %#v", result)
	}
	if len(result.RecoverableObserved) != len(inventory.Observed) {
		t.Fatalf("expected all observed runtime-derived state to remain recoverable, got %#v", result)
	}
}

func TestRestartRecovererGraceRetainsObservedStateAfterBriefDisconnect(t *testing.T) {
	inventory := testRestartRecoveryInventory(
		t,
		testPeriodicReconcileObject(ManagedObjectRootQDisc, "1:", true, false, true),
	)
	graceUntil := time.Date(2026, time.March, 15, 11, 0, 0, 0, time.UTC)

	result, err := (RestartRecoverer{}).Decide(RestartRecoveryInput{
		Inventory: inventory,
		RuntimeEvidence: &discovery.RuntimeEvidenceChurnDecision{
			Action:     discovery.RuntimeEvidenceChurnActionGraceRetained,
			GraceUntil: &graceUntil,
			Reason:     "recent trusted presence remains within disconnect grace",
		},
	})
	if err != nil {
		t.Fatalf("expected grace-retained restart recovery to succeed, got %v", err)
	}

	if result.Kind != RestartRecoveryGraceRetained {
		t.Fatalf("expected restart_grace_retained result, got %#v", result)
	}
	if result.GraceUntil == nil || !result.GraceUntil.Equal(graceUntil) {
		t.Fatalf("expected restart grace deadline to be preserved, got %#v", result)
	}
	if len(result.RecoverableObserved) != 1 {
		t.Fatalf("expected observed state to remain recoverable under grace, got %#v", result)
	}
}

func TestRestartRecovererMarksCleanupSafeWhenAbsenceIsConfirmedAndObservedStateIsEligible(t *testing.T) {
	inventory := testRestartRecoveryInventory(
		t,
		testPeriodicReconcileObject(ManagedObjectRootQDisc, "1:", true, false, true),
	)

	result, err := (RestartRecoverer{}).Decide(RestartRecoveryInput{
		Inventory: inventory,
		RuntimeEvidence: &discovery.RuntimeEvidenceChurnDecision{
			Action: discovery.RuntimeEvidenceChurnActionImmediatelyRemovable,
			Reason: "fresh runtime evidence confirms the owner is gone",
		},
	})
	if err != nil {
		t.Fatalf("expected cleanup-safe restart recovery to succeed, got %v", err)
	}

	if result.Kind != RestartRecoveryCleanupSafe {
		t.Fatalf("expected restart_cleanup_safe result, got %#v", result)
	}
	if len(result.CleanupCandidates) != 1 || result.CleanupCandidates[0].Object.Kind != ManagedObjectRootQDisc {
		t.Fatalf("expected cleanup-safe root qdisc candidate, got %#v", result)
	}
}

func TestRestartRecovererDefersWhenConfirmedAbsenceStillLacksCleanupEligibleObservedState(t *testing.T) {
	inventory := testRestartRecoveryInventory(
		t,
		testPeriodicReconcileObject(ManagedObjectMarkAttachmentTable, "inet|raylimit_eth0_upload", true, false, false),
	)

	result, err := (RestartRecoverer{}).Decide(RestartRecoveryInput{
		Inventory: inventory,
		RuntimeEvidence: &discovery.RuntimeEvidenceChurnDecision{
			Action: discovery.RuntimeEvidenceChurnActionImmediatelyRemovable,
			Reason: "fresh runtime evidence confirms the owner is gone",
		},
	})
	if err != nil {
		t.Fatalf("expected deferred restart recovery to succeed, got %v", err)
	}

	if result.Kind != RestartRecoveryDefer {
		t.Fatalf("expected restart_defer result, got %#v", result)
	}
	if !strings.Contains(result.Reason, "no cleanup-eligible observed managed state") {
		t.Fatalf("expected cleanup-eligibility defer reason, got %#v", result)
	}
}

func TestRestartRecovererDefersWhenRuntimeEvidenceStillRemainsWeak(t *testing.T) {
	inventory := testRestartRecoveryInventory(
		t,
		testPeriodicReconcileObject(ManagedObjectRootQDisc, "1:", true, false, true),
	)

	result, err := (RestartRecoverer{}).Decide(RestartRecoveryInput{
		Inventory: inventory,
		RuntimeEvidence: &discovery.RuntimeEvidenceChurnDecision{
			Action: discovery.RuntimeEvidenceChurnActionDefer,
			Reason: "runtime evidence is only partially trustworthy after restart",
		},
	})
	if err != nil {
		t.Fatalf("expected deferred restart recovery to succeed, got %v", err)
	}

	if result.Kind != RestartRecoveryDefer {
		t.Fatalf("expected restart_defer result, got %#v", result)
	}
	if !strings.Contains(result.Reason, "partially trustworthy") {
		t.Fatalf("expected weak-evidence reason, got %#v", result)
	}
}
