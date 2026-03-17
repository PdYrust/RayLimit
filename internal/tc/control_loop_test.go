package tc

import (
	"strings"
	"testing"
	"time"

	"github.com/PdYrust/RayLimit/internal/correlation"
	"github.com/PdYrust/RayLimit/internal/discovery"
	"github.com/PdYrust/RayLimit/internal/policy"
)

func testControlLoopUUIDOwnerKey() string {
	return testUUIDAggregateSubject().Key()
}

func testControlLoopUUIDManagedState(objects ...ManagedObject) ManagedStateSet {
	return ManagedStateSet{
		OwnerKey: testControlLoopUUIDOwnerKey(),
		Objects:  append([]ManagedObject(nil), objects...),
	}
}

func testControlLoopUUIDMembership(t *testing.T, sessions ...discovery.Session) *correlation.UUIDAggregateMembership {
	t.Helper()

	membership, err := correlation.NewUUIDAggregateMembership(testUUIDAggregateSubject(), sessions)
	if err != nil {
		t.Fatalf("expected uuid membership construction to succeed, got %v", err)
	}

	return &membership
}

func testControlLoopUUIDMembershipRefresh(
	t *testing.T,
	action correlation.UUIDMembershipRefreshAction,
	freshness discovery.RuntimeEvidenceFreshness,
	refreshNeeded bool,
	sessions ...discovery.Session,
) correlation.UUIDMembershipRefreshResult {
	t.Helper()

	result := correlation.UUIDMembershipRefreshResult{
		Action:        action,
		Subject:       testUUIDAggregateSubject(),
		Freshness:     freshness,
		RefreshNeeded: refreshNeeded,
		Reason:        "uuid membership refresh test signal",
	}
	if sessions != nil {
		result.Membership = testControlLoopUUIDMembership(t, sessions...)
	}
	if err := result.Validate(); err != nil {
		t.Fatalf("expected uuid membership refresh test signal to validate, got %v", err)
	}

	return result
}

func testControlLoopUUIDMembershipGrace(
	t *testing.T,
	action discovery.RuntimeEvidenceChurnAction,
	graceUntil *time.Time,
	sessions ...discovery.Session,
) correlation.UUIDMembershipGraceResult {
	t.Helper()

	result := correlation.UUIDMembershipGraceResult{
		Action:  action,
		Subject: testUUIDAggregateSubject(),
		Reason:  "uuid membership grace test signal",
	}
	if sessions != nil {
		result.EffectiveMembership = testControlLoopUUIDMembership(t, sessions...)
	}
	if graceUntil != nil {
		copy := *graceUntil
		result.GraceUntil = &copy
	}
	if err := result.Validate(); err != nil {
		t.Fatalf("expected uuid membership grace test signal to validate, got %v", err)
	}

	return result
}

func TestControlLoopInputValidateRejectsDesiredObservedOwnerMismatch(t *testing.T) {
	input := ControlLoopInput{
		Desired:  ManagedStateSet{OwnerKey: "host_process||edge-a|1001||uuid|user-a"},
		Observed: ManagedStateSet{OwnerKey: "host_process||edge-a|1001||uuid|user-b"},
	}

	err := input.Validate()
	if err == nil || !strings.Contains(err.Error(), "do not describe the same owner") {
		t.Fatalf("expected desired/observed owner mismatch to fail early, got %v", err)
	}
}

func TestControlLoopInputValidateRejectsMultipleRuntimeSignalSources(t *testing.T) {
	desired := testControlLoopUUIDManagedState(
		testPeriodicReconcileObject(ManagedObjectRootQDisc, "1:", true, false, true),
	)
	refresh := testControlLoopUUIDMembershipRefresh(
		t,
		correlation.UUIDMembershipRefreshRefreshRequired,
		discovery.RuntimeEvidenceFreshnessStale,
		true,
		testUUIDAggregateSession("conn-1"),
	)
	graceUntil := time.Date(2026, time.March, 15, 16, 0, 0, 0, time.UTC)
	grace := testControlLoopUUIDMembershipGrace(
		t,
		discovery.RuntimeEvidenceChurnActionGraceRetained,
		&graceUntil,
		testUUIDAggregateSession("conn-1"),
	)

	err := (ControlLoopInput{
		Desired:  desired,
		Observed: desired,
		RuntimeSignals: ControlLoopRuntimeSignals{
			UUIDMembershipRefresh: &refresh,
			UUIDMembershipGrace:   &grace,
		},
	}).Validate()
	if err == nil || !strings.Contains(err.Error(), "at most one authoritative signal source") {
		t.Fatalf("expected conflicting runtime signals to be rejected, got %v", err)
	}
}

func TestControlLoopInputValidateRejectsUUIDRefreshOwnerMismatch(t *testing.T) {
	desired := testControlLoopUUIDManagedState(
		testPeriodicReconcileObject(ManagedObjectRootQDisc, "1:", true, false, true),
	)
	mismatchedSubject := testUUIDAggregateSubject()
	mismatchedSubject.UUID = "user-b"
	refresh := correlation.UUIDMembershipRefreshResult{
		Action:        correlation.UUIDMembershipRefreshRefreshRequired,
		Subject:       mismatchedSubject,
		Freshness:     discovery.RuntimeEvidenceFreshnessStale,
		RefreshNeeded: true,
		Reason:        "mismatched uuid refresh owner",
	}
	if err := refresh.Validate(); err != nil {
		t.Fatalf("expected mismatched refresh test signal to validate, got %v", err)
	}

	err := (ControlLoopInput{
		Desired:  desired,
		Observed: desired,
		RuntimeSignals: ControlLoopRuntimeSignals{
			UUIDMembershipRefresh: &refresh,
		},
	}).Validate()
	if err == nil || !strings.Contains(err.Error(), "does not match the requested control-loop owner") {
		t.Fatalf("expected mismatched uuid refresh owner to be rejected, got %v", err)
	}
}

func TestControlLoopInputValidateRejectsUUIDGraceOwnerMismatch(t *testing.T) {
	desired := testControlLoopUUIDManagedState(
		testPeriodicReconcileObject(ManagedObjectRootQDisc, "1:", true, false, true),
	)
	mismatchedSubject := testUUIDAggregateSubject()
	mismatchedSubject.UUID = "user-b"
	grace := correlation.UUIDMembershipGraceResult{
		Action:  discovery.RuntimeEvidenceChurnActionDefer,
		Subject: mismatchedSubject,
		Reason:  "mismatched uuid grace owner",
	}
	if err := grace.Validate(); err != nil {
		t.Fatalf("expected mismatched grace test signal to validate, got %v", err)
	}

	err := (ControlLoopInput{
		Desired:  desired,
		Observed: desired,
		RuntimeSignals: ControlLoopRuntimeSignals{
			UUIDMembershipGrace: &grace,
		},
	}).Validate()
	if err == nil || !strings.Contains(err.Error(), "does not match the requested control-loop owner") {
		t.Fatalf("expected mismatched uuid grace owner to be rejected, got %v", err)
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

func TestControlLoopCoordinatorAppliesOnlyMissingConcreteDelta(t *testing.T) {
	plan := testManagedPlan(t, policy.TargetKindIP, DirectionUpload, 2048)
	desired, err := DesiredManagedState(plan)
	if err != nil {
		t.Fatalf("expected desired managed state to succeed, got %v", err)
	}

	rootObjects := findManagedObjectsByKind(desired.Objects, ManagedObjectRootQDisc)
	if len(rootObjects) != 1 {
		t.Fatalf("expected one root qdisc object, got %#v", desired.Objects)
	}
	observed := ManagedStateSet{
		OwnerKey: desired.OwnerKey,
		Objects:  append([]ManagedObject(nil), rootObjects...),
	}

	result, err := (ControlLoopCoordinator{}).Execute(ControlLoopInput{
		Desired:  desired,
		Observed: observed,
	})
	if err != nil {
		t.Fatalf("expected control-loop apply delta to succeed, got %v", err)
	}

	if result.Kind != ControlLoopOutcomeApplyDelta {
		t.Fatalf("expected apply_delta control-loop outcome, got %#v", result)
	}
	if result.Reconcile == nil || result.Reconcile.Kind != ReconcileOutcomeApplyDelta {
		t.Fatalf("expected apply_delta reconcile result, got %#v", result)
	}
}

func TestControlLoopCoordinatorBuildsCleanupDeltaForStaleConcreteObservedState(t *testing.T) {
	plan := testManagedPlan(t, policy.TargetKindIP, DirectionUpload, 2048)
	snapshot := Snapshot{
		Device: "eth0",
		QDiscs: []QDiscState{{Kind: "htb", Handle: plan.Handles.RootHandle, Parent: "root"}},
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

	result, err := (ControlLoopCoordinator{}).Execute(ControlLoopInput{
		Desired:  ManagedStateSet{OwnerKey: observed.OwnerKey},
		Observed: observed,
		Snapshot: &snapshot,
	})
	if err != nil {
		t.Fatalf("expected control-loop cleanup delta to succeed, got %v", err)
	}

	if result.Kind != ControlLoopOutcomeCleanupDelta {
		t.Fatalf("expected cleanup_delta control-loop outcome, got %#v", result)
	}
	if result.GarbageCollection == nil || result.GarbageCollection.Kind != GarbageCollectionOutcomeCleanupDelta {
		t.Fatalf("expected cleanup_delta garbage-collection plan, got %#v", result)
	}
}

func TestControlLoopCoordinatorUsesUUIDMembershipRefreshForRefreshRequired(t *testing.T) {
	desired := testControlLoopUUIDManagedState(
		testPeriodicReconcileObject(ManagedObjectRootQDisc, "1:", true, false, true),
		testPeriodicReconcileObject(ManagedObjectUUIDAggregateClass, "1:2001", true, false, false),
	)

	refresh := testControlLoopUUIDMembershipRefresh(
		t,
		correlation.UUIDMembershipRefreshRefreshRequired,
		discovery.RuntimeEvidenceFreshnessStale,
		true,
		testUUIDAggregateSession("conn-1"),
	)

	result, err := (ControlLoopCoordinator{}).Execute(ControlLoopInput{
		Desired:  desired,
		Observed: ManagedStateSet{OwnerKey: desired.OwnerKey},
		RuntimeSignals: ControlLoopRuntimeSignals{
			UUIDMembershipRefresh: &refresh,
		},
	})
	if err != nil {
		t.Fatalf("expected control-loop refresh-required path to succeed, got %v", err)
	}

	if result.Kind != ControlLoopOutcomeRefreshRequired {
		t.Fatalf("expected refresh_required control-loop outcome, got %#v", result)
	}
	if result.Reconcile == nil || result.Reconcile.Kind != ReconcileOutcomeBlockedMissingEvidence {
		t.Fatalf("expected blocked_missing_evidence reconcile context, got %#v", result)
	}
}

func TestControlLoopCoordinatorUsesUUIDMembershipGraceForGraceRetention(t *testing.T) {
	graceUntil := time.Date(2026, time.March, 15, 15, 0, 0, 0, time.UTC)
	desired := testControlLoopUUIDManagedState(
		testPeriodicReconcileObject(ManagedObjectRootQDisc, "1:", true, false, true),
		testPeriodicReconcileObject(ManagedObjectUUIDAggregateClass, "1:2001", true, false, false),
	)
	grace := testControlLoopUUIDMembershipGrace(
		t,
		discovery.RuntimeEvidenceChurnActionGraceRetained,
		&graceUntil,
		testUUIDAggregateSession("conn-1"),
	)

	result, err := (ControlLoopCoordinator{}).Execute(ControlLoopInput{
		Desired:  desired,
		Observed: desired,
		RuntimeSignals: ControlLoopRuntimeSignals{
			UUIDMembershipGrace: &grace,
		},
	})
	if err != nil {
		t.Fatalf("expected control-loop grace-retained path to succeed, got %v", err)
	}

	if result.Kind != ControlLoopOutcomeGraceRetained {
		t.Fatalf("expected grace_retained control-loop outcome, got %#v", result)
	}
	if result.GraceUntil == nil || !result.GraceUntil.Equal(graceUntil) {
		t.Fatalf("expected control-loop grace deadline to be preserved, got %#v", result)
	}
}

func TestControlLoopCoordinatorUsesRestartRecoveryForConcreteObservedState(t *testing.T) {
	plan := testManagedPlan(t, policy.TargetKindIP, DirectionUpload, 2048)
	snapshot := Snapshot{
		Device: "eth0",
		QDiscs: []QDiscState{{Kind: "htb", Handle: plan.Handles.RootHandle, Parent: "root"}},
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

	result, err := (ControlLoopCoordinator{}).Execute(ControlLoopInput{
		Desired:  ManagedStateSet{OwnerKey: observed.OwnerKey},
		Observed: observed,
		Restart:  true,
	})
	if err != nil {
		t.Fatalf("expected restart recovery control-loop path to succeed, got %v", err)
	}

	if result.Kind != ControlLoopOutcomeRestartRecovery {
		t.Fatalf("expected restart_recovery control-loop outcome, got %#v", result)
	}
	if result.RestartRecovery == nil || result.RestartRecovery.Kind != RestartRecoveryRecoverableObservedState {
		t.Fatalf("expected recoverable restart recovery context, got %#v", result)
	}
}

func TestControlLoopCoordinatorUsesRestartCleanupForConfirmedAbsentRuntimeOwner(t *testing.T) {
	observed := testControlLoopUUIDManagedState(
		testPeriodicReconcileObject(ManagedObjectRootQDisc, "1:", true, false, true),
	)
	snapshot := Snapshot{
		Device: "eth0",
		QDiscs: []QDiscState{{
			Kind:   "htb",
			Handle: "1:",
			Parent: "root",
		}},
	}
	runtimeEvidence := discovery.RuntimeEvidenceChurnDecision{
		Action: discovery.RuntimeEvidenceChurnActionImmediatelyRemovable,
		Reason: "fresh runtime evidence confirms the uuid owner is gone",
	}

	result, err := (ControlLoopCoordinator{}).Execute(ControlLoopInput{
		Desired:  ManagedStateSet{OwnerKey: observed.OwnerKey},
		Observed: observed,
		Snapshot: &snapshot,
		Restart:  true,
		RuntimeSignals: ControlLoopRuntimeSignals{
			RuntimeEvidence: &runtimeEvidence,
		},
	})
	if err != nil {
		t.Fatalf("expected restart cleanup control-loop path to succeed, got %v", err)
	}

	if result.Kind != ControlLoopOutcomeCleanupDelta {
		t.Fatalf("expected cleanup_delta control-loop outcome, got %#v", result)
	}
	if result.GarbageCollection == nil || result.GarbageCollection.Kind != GarbageCollectionOutcomeCleanupDelta {
		t.Fatalf("expected cleanup_delta garbage-collection plan after restart, got %#v", result)
	}
}

func TestControlLoopCoordinatorUsesApplyDeltaForAttachableUUIDMembershipChange(t *testing.T) {
	desired := testControlLoopUUIDManagedState(
		testPeriodicReconcileObject(ManagedObjectRootQDisc, "1:", true, false, true),
		testPeriodicReconcileObject(ManagedObjectUUIDAggregateClass, "1:2001", true, false, false),
		testPeriodicReconcileObject(ManagedObjectUUIDAggregateAttachmentFilter, uuidAggregateAttachmentManagedObjectID("1:", "1:2001", 110), true, false, false),
		testPeriodicReconcileObject(ManagedObjectUUIDAggregateAttachmentFilter, uuidAggregateAttachmentManagedObjectID("1:", "1:2001", 130), true, false, false),
	)
	observed := testControlLoopUUIDManagedState(
		testPeriodicReconcileObject(ManagedObjectRootQDisc, "1:", true, false, true),
		testPeriodicReconcileObject(ManagedObjectUUIDAggregateClass, "1:2001", true, false, false),
		testPeriodicReconcileObject(ManagedObjectUUIDAggregateAttachmentFilter, uuidAggregateAttachmentManagedObjectID("1:", "1:2001", 110), true, false, false),
		testPeriodicReconcileObject(ManagedObjectUUIDAggregateAttachmentFilter, uuidAggregateAttachmentManagedObjectID("1:", "1:2001", 120), true, false, false),
	)
	refresh := testControlLoopUUIDMembershipRefresh(
		t,
		correlation.UUIDMembershipRefreshRefreshed,
		discovery.RuntimeEvidenceFreshnessFresh,
		false,
		testUUIDAggregateSession("conn-1"),
		testUUIDAggregateSession("conn-3"),
	)

	result, err := (ControlLoopCoordinator{}).Execute(ControlLoopInput{
		Desired:  desired,
		Observed: observed,
		RuntimeSignals: ControlLoopRuntimeSignals{
			UUIDMembershipRefresh: &refresh,
		},
	})
	if err != nil {
		t.Fatalf("expected attachable uuid membership delta to reconcile cleanly, got %v", err)
	}

	if result.Kind != ControlLoopOutcomeApplyDelta {
		t.Fatalf("expected apply_delta control-loop outcome, got %#v", result)
	}
	if result.Reconcile == nil || result.Reconcile.Kind != ReconcileOutcomeApplyDelta {
		t.Fatalf("expected apply_delta reconcile result for attachable uuid membership change, got %#v", result)
	}
}

func TestControlLoopCoordinatorRejectsOwnerMismatch(t *testing.T) {
	_, err := (ControlLoopCoordinator{}).Execute(ControlLoopInput{
		Desired: ManagedStateSet{
			OwnerKey: "host_process|xray|edge-a|4242||ip|203.0.113.10",
		},
		Observed: ManagedStateSet{
			OwnerKey: testControlLoopUUIDOwnerKey(),
		},
	})
	if err == nil {
		t.Fatal("expected owner mismatch error, got nil")
	}
	if !strings.Contains(err.Error(), "same owner") {
		t.Fatalf("expected owner mismatch validation error, got %v", err)
	}
}
