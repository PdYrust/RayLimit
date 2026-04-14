package tc

import (
	"strings"
	"testing"
)

func testPeriodicReconcileObject(
	kind ManagedObjectKind,
	id string,
	retainRequiresRuntimeEvidence bool,
	cleanupRequiresRuntimeEvidence bool,
	cleanupEligible bool,
) ManagedObject {
	return ManagedObject{
		Kind:                           kind,
		Device:                         "eth0",
		RootHandle:                     "1:",
		ID:                             id,
		RetainRequiresRuntimeEvidence:  retainRequiresRuntimeEvidence,
		CleanupRequiresRuntimeEvidence: cleanupRequiresRuntimeEvidence,
		CleanupEligible:                cleanupEligible,
	}
}

func TestPeriodicReconcilerDecideNoChangeForMatchingConcreteState(t *testing.T) {
	desired := ManagedStateSet{
		OwnerKey: "host_process|xray|xray|1234|container-1",
		Objects: []ManagedObject{
			testPeriodicReconcileObject(ManagedObjectRootQDisc, "1:", false, false, true),
			testPeriodicReconcileObject(ManagedObjectClass, "1:1001", false, false, false),
			testPeriodicReconcileObject(ManagedObjectDirectAttachmentFilter, "1:|u32|ip|49153|1:1001", false, false, false),
		},
	}
	observed := ManagedStateSet{
		OwnerKey: desired.OwnerKey,
		Objects:  append([]ManagedObject(nil), desired.Objects...),
	}

	result, err := (PeriodicReconciler{}).Decide(PeriodicReconcileInput{
		Desired:  desired,
		Observed: observed,
	})
	if err != nil {
		t.Fatalf("expected no-change reconcile decision to succeed, got %v", err)
	}

	if result.Kind != ReconcileOutcomeNoChange {
		t.Fatalf("expected no_change result, got %#v", result)
	}
	if len(result.MissingDesired) != 0 || len(result.CleanupCandidates) != 0 {
		t.Fatalf("expected no missing or cleanup state for no_change result, got %#v", result)
	}
}

func TestPeriodicReconcilerDecideDefersWhenMatchingStateStillNeedsRetainEvidence(t *testing.T) {
	desired := ManagedStateSet{
		OwnerKey: "host_process|xray|xray|1234|container-1",
		Objects: []ManagedObject{
			testPeriodicReconcileObject(ManagedObjectRootQDisc, "1:", true, false, true),
			testPeriodicReconcileObject(ManagedObjectClass, "1:1002", true, false, false),
		},
	}
	observed := ManagedStateSet{
		OwnerKey: desired.OwnerKey,
		Objects:  append([]ManagedObject(nil), desired.Objects...),
	}

	result, err := (PeriodicReconciler{}).Decide(PeriodicReconcileInput{
		Desired:  desired,
		Observed: observed,
		RetainEvidence: ReconcileRetainEvidence{
			AllowsRetain: false,
			Reason:       "runtime proof is temporarily unavailable",
		},
	})
	if err != nil {
		t.Fatalf("expected deferred reconcile decision to succeed, got %v", err)
	}

	if result.Kind != ReconcileOutcomeDefer {
		t.Fatalf("expected defer result, got %#v", result)
	}
	if !strings.Contains(result.Reason, "runtime-derived retain evidence") ||
		!strings.Contains(result.Reason, "temporarily unavailable") {
		t.Fatalf("expected retain-evidence reason in %#v", result)
	}
}

func TestPeriodicReconcilerDecideApplyDeltaForMissingConcreteObjects(t *testing.T) {
	desired := ManagedStateSet{
		OwnerKey: "host_process|xray|xray|1234|container-1",
		Objects: []ManagedObject{
			testPeriodicReconcileObject(ManagedObjectRootQDisc, "1:", false, false, true),
			testPeriodicReconcileObject(ManagedObjectClass, "1:1003", false, false, false),
		},
	}
	observed := ManagedStateSet{
		OwnerKey: desired.OwnerKey,
		Objects: []ManagedObject{
			testPeriodicReconcileObject(ManagedObjectRootQDisc, "1:", false, false, true),
		},
	}

	result, err := (PeriodicReconciler{}).Decide(PeriodicReconcileInput{
		Desired:  desired,
		Observed: observed,
	})
	if err != nil {
		t.Fatalf("expected apply-delta reconcile decision to succeed, got %v", err)
	}

	if result.Kind != ReconcileOutcomeApplyDelta {
		t.Fatalf("expected apply_delta result, got %#v", result)
	}
	if len(result.MissingDesired) != 1 || result.MissingDesired[0].Kind != ManagedObjectClass {
		t.Fatalf("expected missing desired class object, got %#v", result)
	}
}

func TestPeriodicReconcilerDecideBlocksRuntimeDerivedDeltaWithoutRecreateEvidence(t *testing.T) {
	desired := ManagedStateSet{
		OwnerKey: "host_process|xray|xray|1234|container-1",
		Objects: []ManagedObject{
			testPeriodicReconcileObject(ManagedObjectClass, "1:1004", true, false, false),
		},
	}

	result, err := (PeriodicReconciler{}).Decide(PeriodicReconcileInput{
		Desired:  desired,
		Observed: ManagedStateSet{OwnerKey: desired.OwnerKey},
		RetainEvidence: ReconcileRetainEvidence{
			AllowsRecreate: false,
			Reason:         "live runtime selector proof is missing",
		},
	})
	if err != nil {
		t.Fatalf("expected blocked reconcile decision to succeed, got %v", err)
	}

	if result.Kind != ReconcileOutcomeBlockedMissingEvidence {
		t.Fatalf("expected blocked_missing_evidence result, got %#v", result)
	}
	if len(result.MissingDesired) != 1 || result.MissingDesired[0].Kind != ManagedObjectClass {
		t.Fatalf("expected missing desired class object, got %#v", result)
	}
	if !strings.Contains(result.Reason, "live runtime selector proof is missing") {
		t.Fatalf("expected recreate-evidence reason in %#v", result)
	}
}

func TestPeriodicReconcilerDecideCleanupStaleWhenObservedStateIsEligible(t *testing.T) {
	observed := ManagedStateSet{
		OwnerKey: "host_process|xray|xray|1234|container-1",
		Objects: []ManagedObject{
			testPeriodicReconcileObject(ManagedObjectRootQDisc, "1:", false, false, true),
		},
	}

	result, err := (PeriodicReconciler{}).Decide(PeriodicReconcileInput{
		Desired:  ManagedStateSet{OwnerKey: observed.OwnerKey},
		Observed: observed,
	})
	if err != nil {
		t.Fatalf("expected cleanup-stale reconcile decision to succeed, got %v", err)
	}

	if result.Kind != ReconcileOutcomeCleanupStale {
		t.Fatalf("expected cleanup_stale result, got %#v", result)
	}
	if len(result.CleanupCandidates) != 1 || result.CleanupCandidates[0].Object.Kind != ManagedObjectRootQDisc {
		t.Fatalf("expected root qdisc cleanup candidate, got %#v", result)
	}
}

func TestPeriodicReconcilerDecideDefersWhenObservedStaleStateIsNotCleanupEligible(t *testing.T) {
	observed := ManagedStateSet{
		OwnerKey: "host_process|xray|xray|1234|container-1",
		Objects: []ManagedObject{
			testPeriodicReconcileObject(ManagedObjectMarkAttachmentTable, "inet|raylimit_eth0_upload", true, false, false),
		},
	}

	result, err := (PeriodicReconciler{}).Decide(PeriodicReconcileInput{
		Desired:  ManagedStateSet{OwnerKey: observed.OwnerKey},
		Observed: observed,
	})
	if err != nil {
		t.Fatalf("expected deferred stale reconcile decision to succeed, got %v", err)
	}

	if result.Kind != ReconcileOutcomeDefer {
		t.Fatalf("expected defer result, got %#v", result)
	}
	if len(result.Inventory.Stale) != 1 || result.Inventory.Stale[0].CleanupEligible {
		t.Fatalf("expected one non-cleanup-eligible stale object, got %#v", result.Inventory)
	}
	if len(result.CleanupCandidates) != 0 {
		t.Fatalf("expected no cleanup candidates when stale state is not cleanup-eligible, got %#v", result)
	}
}

func TestPeriodicReconcilerDecideRejectsOwnerMismatch(t *testing.T) {
	_, err := (PeriodicReconciler{}).Decide(PeriodicReconcileInput{
		Desired: ManagedStateSet{
			OwnerKey: "host_process|xray|xray|1234|container-1|ip|203.0.113.10",
		},
		Observed: ManagedStateSet{
			OwnerKey: "host_process|xray|xray|1234|container-1|outbound|proxy-out",
		},
	})
	if err == nil {
		t.Fatal("expected owner mismatch validation error, got nil")
	}
	if !strings.Contains(err.Error(), "same owner") {
		t.Fatalf("expected owner mismatch error, got %v", err)
	}
}
