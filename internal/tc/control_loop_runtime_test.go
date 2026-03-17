package tc

import (
	"strings"
	"testing"
	"time"

	"github.com/PdYrust/RayLimit/internal/correlation"
	"github.com/PdYrust/RayLimit/internal/discovery"
	"github.com/PdYrust/RayLimit/internal/policy"
)

func testControlLoopOperationalPolicy() ControlLoopOperationalPolicy {
	return ControlLoopOperationalPolicy{
		MaxOwnersPerTick:       2,
		SteadyInterval:         30 * time.Second,
		MutationVerifyInterval: 10 * time.Second,
		RefreshBackoffBase:     5 * time.Second,
		RefreshBackoffMax:      40 * time.Second,
		DeferBackoffBase:       7 * time.Second,
		DeferBackoffMax:        56 * time.Second,
		GraceProbeInterval:     20 * time.Second,
		JitterRatio:            0,
	}
}

func testControlLoopRuntimeUUIDRefresh(
	t *testing.T,
	action correlation.UUIDMembershipRefreshAction,
	freshness discovery.RuntimeEvidenceFreshness,
	refreshNeeded bool,
) correlation.UUIDMembershipRefreshResult {
	t.Helper()

	return testControlLoopUUIDMembershipRefresh(
		t,
		action,
		freshness,
		refreshNeeded,
		testUUIDAggregateSession("conn-1"),
	)
}

func testControlLoopRuntimeUUIDGrace(
	t *testing.T,
	action discovery.RuntimeEvidenceChurnAction,
	graceUntil *time.Time,
) correlation.UUIDMembershipGraceResult {
	t.Helper()

	return testControlLoopUUIDMembershipGrace(
		t,
		action,
		graceUntil,
		testUUIDAggregateSession("conn-1"),
	)
}

func TestControlLoopOperatorProcessKeepsNoChangeOnSteadyCadence(t *testing.T) {
	now := time.Date(2026, time.March, 15, 15, 30, 0, 0, time.UTC)
	plan := testManagedPlan(t, policy.TargetKindIP, DirectionUpload, 2048)
	desired, err := DesiredManagedState(plan)
	if err != nil {
		t.Fatalf("expected desired managed state to succeed, got %v", err)
	}

	result, err := (ControlLoopOperator{}).Process(ControlLoopProcessInput{
		Loop: ControlLoopInput{
			Desired:  desired,
			Observed: desired,
		},
		Policy: testControlLoopOperationalPolicy(),
		Now:    now,
	})
	if err != nil {
		t.Fatalf("expected operational control-loop processing to succeed, got %v", err)
	}

	if result.Loop.Kind != ControlLoopOutcomeNoChange {
		t.Fatalf("expected no_change integrated outcome, got %#v", result)
	}
	if result.State.NextRunAt != now.Add(30*time.Second) {
		t.Fatalf("expected steady cadence next run at %v, got %#v", now.Add(30*time.Second), result.State)
	}
	if result.Summary.Mode != ControlLoopOperationalModeSteadyWatch || result.Summary.Mutating || result.Summary.RefreshNeeded {
		t.Fatalf("expected steady non-mutating summary, got %#v", result.Summary)
	}
}

func TestControlLoopOperatorProcessCapsRepeatedRefreshBackoff(t *testing.T) {
	now := time.Date(2026, time.March, 15, 15, 31, 0, 0, time.UTC)
	desired := testControlLoopUUIDManagedState(
		testPeriodicReconcileObject(ManagedObjectRootQDisc, "1:", true, false, true),
		testPeriodicReconcileObject(ManagedObjectUUIDAggregateClass, "1:2001", true, false, false),
	)
	refresh := testControlLoopRuntimeUUIDRefresh(
		t,
		correlation.UUIDMembershipRefreshRefreshRequired,
		discovery.RuntimeEvidenceFreshnessStale,
		true,
	)
	previous := ControlLoopOwnerState{
		OwnerKey:                desired.OwnerKey,
		LastOutcome:             ControlLoopOutcomeRefreshRequired,
		ConsecutiveOutcomeCount: 4,
		LastRunAt:               now.Add(-5 * time.Second),
		NextRunAt:               now,
		LastReason:              "older refresh requirement",
	}

	result, err := (ControlLoopOperator{}).Process(ControlLoopProcessInput{
		State: &previous,
		Loop: ControlLoopInput{
			Desired:  desired,
			Observed: ManagedStateSet{OwnerKey: desired.OwnerKey},
			RuntimeSignals: ControlLoopRuntimeSignals{
				UUIDMembershipRefresh: &refresh,
			},
		},
		Policy: testControlLoopOperationalPolicy(),
		Now:    now,
	})
	if err != nil {
		t.Fatalf("expected operational refresh backoff to succeed, got %v", err)
	}

	if result.Loop.Kind != ControlLoopOutcomeRefreshRequired {
		t.Fatalf("expected refresh_required integrated outcome, got %#v", result)
	}
	if result.State.ConsecutiveOutcomeCount != 4 {
		t.Fatalf("expected refresh streak to stay capped at the saturated backoff count, got %#v", result.State)
	}
	if result.State.NextRunAt != now.Add(40*time.Second) {
		t.Fatalf("expected capped refresh backoff at 40s, got %#v", result.State)
	}
	if result.Summary.Mode != ControlLoopOperationalModeRefreshBackoff || !result.Summary.RefreshNeeded {
		t.Fatalf("expected refresh backoff summary, got %#v", result.Summary)
	}
}

func TestControlLoopOperatorProcessKeepsRefreshBackoffAcrossWeakEvidenceVariants(t *testing.T) {
	now := time.Date(2026, time.March, 15, 15, 31, 30, 0, time.UTC)
	desired := testControlLoopUUIDManagedState(
		testPeriodicReconcileObject(ManagedObjectRootQDisc, "1:", true, false, true),
		testPeriodicReconcileObject(ManagedObjectUUIDAggregateClass, "1:2001", true, false, false),
	)
	refresh := testControlLoopRuntimeUUIDRefresh(
		t,
		correlation.UUIDMembershipRefreshRefreshRequired,
		discovery.RuntimeEvidenceFreshnessStale,
		true,
	)
	previous := ControlLoopOwnerState{
		OwnerKey:                desired.OwnerKey,
		LastOutcome:             ControlLoopOutcomeBlockedMissingEvidence,
		ConsecutiveOutcomeCount: 2,
		LastRunAt:               now.Add(-5 * time.Second),
		NextRunAt:               now,
		LastReason:              "older weak-evidence block",
	}

	result, err := (ControlLoopOperator{}).Process(ControlLoopProcessInput{
		State: &previous,
		Loop: ControlLoopInput{
			Desired:  desired,
			Observed: ManagedStateSet{OwnerKey: desired.OwnerKey},
			RuntimeSignals: ControlLoopRuntimeSignals{
				UUIDMembershipRefresh: &refresh,
			},
		},
		Policy: testControlLoopOperationalPolicy(),
		Now:    now,
	})
	if err != nil {
		t.Fatalf("expected operational weak-evidence refresh handling to succeed, got %v", err)
	}

	if result.Loop.Kind != ControlLoopOutcomeRefreshRequired {
		t.Fatalf("expected refresh_required integrated outcome, got %#v", result)
	}
	if result.State.ConsecutiveOutcomeCount != 3 {
		t.Fatalf("expected weak-evidence refresh streak to continue across equivalent outcomes, got %#v", result.State)
	}
	if result.State.NextRunAt != now.Add(20*time.Second) {
		t.Fatalf("expected continued refresh backoff at 20s, got %#v", result.State)
	}
	if result.Summary.Mode != ControlLoopOperationalModeRefreshBackoff || !result.Summary.RefreshNeeded {
		t.Fatalf("expected refresh backoff summary, got %#v", result.Summary)
	}
}

func TestControlLoopOperatorProcessBoundsGraceProbeByGraceDeadline(t *testing.T) {
	now := time.Date(2026, time.March, 15, 15, 32, 0, 0, time.UTC)
	graceUntil := now.Add(8 * time.Second)
	desired := testControlLoopUUIDManagedState(
		testPeriodicReconcileObject(ManagedObjectRootQDisc, "1:", true, false, true),
		testPeriodicReconcileObject(ManagedObjectUUIDAggregateClass, "1:2001", true, false, false),
	)
	grace := testControlLoopRuntimeUUIDGrace(
		t,
		discovery.RuntimeEvidenceChurnActionGraceRetained,
		&graceUntil,
	)

	result, err := (ControlLoopOperator{}).Process(ControlLoopProcessInput{
		Loop: ControlLoopInput{
			Desired:  desired,
			Observed: desired,
			RuntimeSignals: ControlLoopRuntimeSignals{
				UUIDMembershipGrace: &grace,
			},
		},
		Policy: testControlLoopOperationalPolicy(),
		Now:    now,
	})
	if err != nil {
		t.Fatalf("expected operational grace handling to succeed, got %v", err)
	}

	if result.Loop.Kind != ControlLoopOutcomeGraceRetained {
		t.Fatalf("expected grace_retained integrated outcome, got %#v", result)
	}
	if result.State.NextRunAt != graceUntil {
		t.Fatalf("expected grace probe to cap at the grace deadline, got %#v", result.State)
	}
	if result.Summary.Mode != ControlLoopOperationalModeGraceProbe {
		t.Fatalf("expected grace probe summary mode, got %#v", result.Summary)
	}
}

func TestControlLoopOperatorProcessBacksOffRepeatedDeferWithoutMutation(t *testing.T) {
	now := time.Date(2026, time.March, 15, 15, 33, 0, 0, time.UTC)
	desired := testControlLoopUUIDManagedState(
		testPeriodicReconcileObject(ManagedObjectRootQDisc, "1:", true, false, true),
		testPeriodicReconcileObject(ManagedObjectUUIDAggregateClass, "1:2001", true, false, false),
	)
	runtimeEvidence := discovery.RuntimeEvidenceChurnDecision{
		Action: discovery.RuntimeEvidenceChurnActionDefer,
		Reason: "runtime evidence is only partially trustworthy",
	}
	previous := ControlLoopOwnerState{
		OwnerKey:                desired.OwnerKey,
		LastOutcome:             ControlLoopOutcomeDefer,
		ConsecutiveOutcomeCount: 3,
		LastRunAt:               now.Add(-7 * time.Second),
		NextRunAt:               now,
		LastReason:              "older defer",
	}

	result, err := (ControlLoopOperator{}).Process(ControlLoopProcessInput{
		State: &previous,
		Loop: ControlLoopInput{
			Desired:  desired,
			Observed: ManagedStateSet{OwnerKey: desired.OwnerKey},
			RuntimeSignals: ControlLoopRuntimeSignals{
				RuntimeEvidence: &runtimeEvidence,
			},
		},
		Policy: testControlLoopOperationalPolicy(),
		Now:    now,
	})
	if err != nil {
		t.Fatalf("expected operational defer handling to succeed, got %v", err)
	}

	if result.Loop.Kind != ControlLoopOutcomeDefer {
		t.Fatalf("expected defer integrated outcome, got %#v", result)
	}
	if result.State.NextRunAt != now.Add(56*time.Second) {
		t.Fatalf("expected capped defer backoff at 56s, got %#v", result.State)
	}
	if result.Summary.Mode != ControlLoopOperationalModeDeferBackoff || result.Summary.Mutating {
		t.Fatalf("expected defer backoff summary without mutation, got %#v", result.Summary)
	}
}

func TestControlLoopOperatorProcessDefersRestartCleanupWhenRuntimeEvidenceIsWeak(t *testing.T) {
	now := time.Date(2026, time.March, 15, 15, 33, 30, 0, time.UTC)
	observed := testControlLoopUUIDManagedState(
		testPeriodicReconcileObject(ManagedObjectRootQDisc, "1:", true, false, true),
	)
	runtimeEvidence := discovery.RuntimeEvidenceChurnDecision{
		Action: discovery.RuntimeEvidenceChurnActionDefer,
		Reason: "runtime evidence is only partially trustworthy after restart",
	}

	result, err := (ControlLoopOperator{}).Process(ControlLoopProcessInput{
		Loop: ControlLoopInput{
			Desired:  ManagedStateSet{OwnerKey: observed.OwnerKey},
			Observed: observed,
			Restart:  true,
			RuntimeSignals: ControlLoopRuntimeSignals{
				RuntimeEvidence: &runtimeEvidence,
			},
		},
		Policy: testControlLoopOperationalPolicy(),
		Now:    now,
	})
	if err != nil {
		t.Fatalf("expected restart-time weak-evidence handling to succeed, got %v", err)
	}

	if result.Loop.Kind != ControlLoopOutcomeDefer {
		t.Fatalf("expected defer integrated outcome, got %#v", result)
	}
	if result.Loop.GarbageCollection != nil || result.Summary.Mutating {
		t.Fatalf("expected no cleanup mutation under weak restart evidence, got %#v", result)
	}
	if result.Summary.Mode != ControlLoopOperationalModeDeferBackoff {
		t.Fatalf("expected defer backoff summary, got %#v", result.Summary)
	}
}

func TestControlLoopOperatorProcessRefreshRequiredDoesNotCleanRuntimeDerivedStaleState(t *testing.T) {
	now := time.Date(2026, time.March, 15, 15, 33, 45, 0, time.UTC)
	observed := testControlLoopUUIDManagedState(
		testPeriodicReconcileObject(ManagedObjectRootQDisc, "1:", true, false, true),
	)
	refresh := testControlLoopRuntimeUUIDRefresh(
		t,
		correlation.UUIDMembershipRefreshRefreshRequired,
		discovery.RuntimeEvidenceFreshnessStale,
		true,
	)

	result, err := (ControlLoopOperator{}).Process(ControlLoopProcessInput{
		Loop: ControlLoopInput{
			Desired:  ManagedStateSet{OwnerKey: observed.OwnerKey},
			Observed: observed,
			RuntimeSignals: ControlLoopRuntimeSignals{
				UUIDMembershipRefresh: &refresh,
			},
		},
		Policy: testControlLoopOperationalPolicy(),
		Now:    now,
	})
	if err != nil {
		t.Fatalf("expected refresh-required stale-state handling to succeed, got %v", err)
	}

	if result.Loop.Kind != ControlLoopOutcomeRefreshRequired {
		t.Fatalf("expected refresh_required integrated outcome, got %#v", result)
	}
	if result.Loop.GarbageCollection != nil || result.Summary.Mutating {
		t.Fatalf("expected runtime-derived stale state to avoid cleanup under refresh requirement, got %#v", result)
	}
	if !result.Summary.RefreshNeeded || result.Summary.Mode != ControlLoopOperationalModeRefreshBackoff {
		t.Fatalf("expected refresh-needed backoff summary, got %#v", result.Summary)
	}
}

func TestControlLoopOperatorProcessMarksMutationVerificationCadence(t *testing.T) {
	now := time.Date(2026, time.March, 15, 15, 34, 0, 0, time.UTC)
	plan := testManagedPlan(t, policy.TargetKindIP, DirectionUpload, 2048)
	desired, err := DesiredManagedState(plan)
	if err != nil {
		t.Fatalf("expected desired managed state to succeed, got %v", err)
	}
	rootObjects := findManagedObjectsByKind(desired.Objects, ManagedObjectRootQDisc)
	observed := ManagedStateSet{
		OwnerKey: desired.OwnerKey,
		Objects:  append([]ManagedObject(nil), rootObjects...),
	}

	result, err := (ControlLoopOperator{}).Process(ControlLoopProcessInput{
		Loop: ControlLoopInput{
			Desired:  desired,
			Observed: observed,
		},
		Policy: testControlLoopOperationalPolicy(),
		Now:    now,
	})
	if err != nil {
		t.Fatalf("expected operational mutation verification to succeed, got %v", err)
	}

	if result.Loop.Kind != ControlLoopOutcomeApplyDelta {
		t.Fatalf("expected apply_delta integrated outcome, got %#v", result)
	}
	if result.State.NextRunAt != now.Add(10*time.Second) {
		t.Fatalf("expected mutation verification cadence at 10s, got %#v", result.State)
	}
	if result.Summary.Mode != ControlLoopOperationalModeVerifyMutation || !result.Summary.Mutating {
		t.Fatalf("expected mutating verification summary, got %#v", result.Summary)
	}
}

func TestControlLoopOperatorProcessRejectsPriorStateOwnerMismatch(t *testing.T) {
	now := time.Date(2026, time.March, 15, 15, 34, 30, 0, time.UTC)
	plan := testManagedPlan(t, policy.TargetKindIP, DirectionUpload, 2048)
	desired, err := DesiredManagedState(plan)
	if err != nil {
		t.Fatalf("expected desired managed state to succeed, got %v", err)
	}

	_, err = (ControlLoopOperator{}).Process(ControlLoopProcessInput{
		State: &ControlLoopOwnerState{
			OwnerKey:                "host_process|xray|edge-a|4242||ip|198.51.100.99",
			LastOutcome:             ControlLoopOutcomeNoChange,
			ConsecutiveOutcomeCount: 1,
			LastRunAt:               now.Add(-30 * time.Second),
			NextRunAt:               now,
			LastReason:              "mismatched owner",
		},
		Loop: ControlLoopInput{
			Desired:  desired,
			Observed: desired,
		},
		Policy: testControlLoopOperationalPolicy(),
		Now:    now,
	})
	if err == nil || !strings.Contains(err.Error(), "does not match the requested owner") {
		t.Fatalf("expected prior-state owner mismatch to fail closed, got %v", err)
	}
}

func TestControlLoopOperatorProcessFailsClosedWhenCleanupWouldRequireSnapshot(t *testing.T) {
	now := time.Date(2026, time.March, 15, 15, 34, 45, 0, time.UTC)
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

	_, err = (ControlLoopOperator{}).Process(ControlLoopProcessInput{
		Loop: ControlLoopInput{
			Desired:  ManagedStateSet{OwnerKey: observed.OwnerKey},
			Observed: observed,
		},
		Policy: testControlLoopOperationalPolicy(),
		Now:    now,
	})
	if err == nil || !strings.Contains(err.Error(), "cleanup requires an observed tc snapshot") {
		t.Fatalf("expected cleanup without snapshot to fail closed, got %v", err)
	}
}

func TestControlLoopOperatorSelectDueOwnersHonorsBoundedWorkBudget(t *testing.T) {
	now := time.Date(2026, time.March, 15, 15, 35, 0, 0, time.UTC)
	states := []ControlLoopOwnerState{
		{
			OwnerKey:                "owner-c",
			LastOutcome:             ControlLoopOutcomeNoChange,
			ConsecutiveOutcomeCount: 1,
			LastRunAt:               now.Add(-40 * time.Second),
			NextRunAt:               now.Add(-2 * time.Second),
			LastReason:              "due earlier",
		},
		{
			OwnerKey:                "owner-a",
			LastOutcome:             ControlLoopOutcomeNoChange,
			ConsecutiveOutcomeCount: 1,
			LastRunAt:               now.Add(-40 * time.Second),
			NextRunAt:               now.Add(-4 * time.Second),
			LastReason:              "oldest due",
		},
		{
			OwnerKey:                "owner-b",
			LastOutcome:             ControlLoopOutcomeNoChange,
			ConsecutiveOutcomeCount: 1,
			LastRunAt:               now.Add(-40 * time.Second),
			NextRunAt:               now.Add(-3 * time.Second),
			LastReason:              "second due",
		},
		{
			OwnerKey:                "owner-future",
			LastOutcome:             ControlLoopOutcomeNoChange,
			ConsecutiveOutcomeCount: 1,
			LastRunAt:               now.Add(-10 * time.Second),
			NextRunAt:               now.Add(30 * time.Second),
			LastReason:              "not due yet",
		},
	}

	result, err := (ControlLoopOperator{}).SelectDueOwners(ControlLoopSelectionInput{
		States: states,
		Policy: testControlLoopOperationalPolicy(),
		Now:    now,
	})
	if err != nil {
		t.Fatalf("expected bounded work selection to succeed, got %v", err)
	}

	if len(result.Scheduled) != 2 || result.Scheduled[0].OwnerKey != "owner-a" || result.Scheduled[1].OwnerKey != "owner-b" {
		t.Fatalf("expected the two earliest due owners to be scheduled, got %#v", result.Scheduled)
	}
	if len(result.Deferred) != 1 || result.Deferred[0].OwnerKey != "owner-c" {
		t.Fatalf("expected the remaining due owner to be deferred by the work budget, got %#v", result.Deferred)
	}
	if !strings.Contains(result.Reason, "work budget") {
		t.Fatalf("expected bounded-work selection reason, got %#v", result)
	}
}

func TestControlLoopOperatorSelectDueOwnersRejectsDuplicateOwnerState(t *testing.T) {
	now := time.Date(2026, time.March, 15, 15, 35, 30, 0, time.UTC)
	state := ControlLoopOwnerState{
		OwnerKey:                "owner-a",
		LastOutcome:             ControlLoopOutcomeNoChange,
		ConsecutiveOutcomeCount: 1,
		LastRunAt:               now.Add(-30 * time.Second),
		NextRunAt:               now,
		LastReason:              "due owner",
	}

	_, err := (ControlLoopOperator{}).SelectDueOwners(ControlLoopSelectionInput{
		States: []ControlLoopOwnerState{state, state},
		Policy: testControlLoopOperationalPolicy(),
		Now:    now,
	})
	if err == nil || !strings.Contains(err.Error(), "duplicate control-loop owner state") {
		t.Fatalf("expected duplicate owner state to be rejected, got %v", err)
	}
}

func TestControlLoopOperatorProcessKeepsNoChangeStateBoundedAcrossLongRun(t *testing.T) {
	now := time.Date(2026, time.March, 15, 16, 0, 0, 0, time.UTC)
	plan := testManagedPlan(t, policy.TargetKindIP, DirectionUpload, 2048)
	desired, err := DesiredManagedState(plan)
	if err != nil {
		t.Fatalf("expected desired managed state to succeed, got %v", err)
	}

	var states []ControlLoopOwnerState
	for tick := 0; tick < 24; tick++ {
		var previous *ControlLoopOwnerState
		if len(states) == 1 {
			copy := states[0]
			previous = &copy
		}

		result, err := (ControlLoopOperator{}).Process(ControlLoopProcessInput{
			State: previous,
			Loop: ControlLoopInput{
				Desired:  desired,
				Observed: desired,
			},
			Policy: testControlLoopOperationalPolicy(),
			Now:    now,
		})
		if err != nil {
			t.Fatalf("expected long-run no-change processing to succeed at tick %d, got %v", tick, err)
		}

		states, err = UpsertControlLoopOwnerState(states, result.State)
		if err != nil {
			t.Fatalf("expected long-run no-change state upsert to succeed at tick %d, got %v", tick, err)
		}
		if len(states) != 1 {
			t.Fatalf("expected one stored owner state after tick %d, got %#v", tick, states)
		}
		if states[0].ConsecutiveOutcomeCount != 1 {
			t.Fatalf("expected no-change streak to stay bounded at tick %d, got %#v", tick, states[0])
		}

		now = now.Add(30 * time.Second)
	}
}

func TestControlLoopOperatorProcessKeepsRefreshAndDeferStreaksBoundedAcrossLongRun(t *testing.T) {
	now := time.Date(2026, time.March, 15, 16, 15, 0, 0, time.UTC)
	desired := testControlLoopUUIDManagedState(
		testPeriodicReconcileObject(ManagedObjectRootQDisc, "1:", true, false, true),
		testPeriodicReconcileObject(ManagedObjectUUIDAggregateClass, "1:2001", true, false, false),
	)
	refresh := testControlLoopRuntimeUUIDRefresh(
		t,
		correlation.UUIDMembershipRefreshRefreshRequired,
		discovery.RuntimeEvidenceFreshnessStale,
		true,
	)
	deferEvidence := discovery.RuntimeEvidenceChurnDecision{
		Action: discovery.RuntimeEvidenceChurnActionDefer,
		Reason: "runtime evidence is only partially trustworthy",
	}

	var refreshState *ControlLoopOwnerState
	for tick := 0; tick < 12; tick++ {
		result, err := (ControlLoopOperator{}).Process(ControlLoopProcessInput{
			State: refreshState,
			Loop: ControlLoopInput{
				Desired:  desired,
				Observed: ManagedStateSet{OwnerKey: desired.OwnerKey},
				RuntimeSignals: ControlLoopRuntimeSignals{
					UUIDMembershipRefresh: &refresh,
				},
			},
			Policy: testControlLoopOperationalPolicy(),
			Now:    now,
		})
		if err != nil {
			t.Fatalf("expected refresh-required processing to succeed at tick %d, got %v", tick, err)
		}
		if result.State.ConsecutiveOutcomeCount > 4 {
			t.Fatalf("expected refresh streak to stay within the saturated backoff bound, got %#v", result.State)
		}
		copy := result.State
		refreshState = &copy
		now = now.Add(40 * time.Second)
	}
	if refreshState == nil || refreshState.ConsecutiveOutcomeCount != 4 {
		t.Fatalf("expected refresh streak to settle at the saturated backoff count, got %#v", refreshState)
	}

	var deferState *ControlLoopOwnerState
	for tick := 0; tick < 12; tick++ {
		result, err := (ControlLoopOperator{}).Process(ControlLoopProcessInput{
			State: deferState,
			Loop: ControlLoopInput{
				Desired:  desired,
				Observed: ManagedStateSet{OwnerKey: desired.OwnerKey},
				RuntimeSignals: ControlLoopRuntimeSignals{
					RuntimeEvidence: &deferEvidence,
				},
			},
			Policy: testControlLoopOperationalPolicy(),
			Now:    now,
		})
		if err != nil {
			t.Fatalf("expected defer processing to succeed at tick %d, got %v", tick, err)
		}
		if result.State.ConsecutiveOutcomeCount > 4 {
			t.Fatalf("expected defer streak to stay within the saturated backoff bound, got %#v", result.State)
		}
		copy := result.State
		deferState = &copy
		now = now.Add(56 * time.Second)
	}
	if deferState == nil || deferState.ConsecutiveOutcomeCount != 4 {
		t.Fatalf("expected defer streak to settle at the saturated backoff count, got %#v", deferState)
	}
}

func TestControlLoopOperatorProcessKeepsGraceStateBoundedAcrossLongRun(t *testing.T) {
	now := time.Date(2026, time.March, 15, 16, 22, 0, 0, time.UTC)
	desired := testControlLoopUUIDManagedState(
		testPeriodicReconcileObject(ManagedObjectRootQDisc, "1:", true, false, true),
		testPeriodicReconcileObject(ManagedObjectUUIDAggregateClass, "1:2001", true, false, false),
	)

	var states []ControlLoopOwnerState
	for tick := 0; tick < 8; tick++ {
		graceUntil := now.Add(8 * time.Second)
		grace := testControlLoopRuntimeUUIDGrace(
			t,
			discovery.RuntimeEvidenceChurnActionGraceRetained,
			&graceUntil,
		)

		var previous *ControlLoopOwnerState
		if len(states) == 1 {
			copy := states[0]
			previous = &copy
		}

		result, err := (ControlLoopOperator{}).Process(ControlLoopProcessInput{
			State: previous,
			Loop: ControlLoopInput{
				Desired:  desired,
				Observed: desired,
				RuntimeSignals: ControlLoopRuntimeSignals{
					UUIDMembershipGrace: &grace,
				},
			},
			Policy: testControlLoopOperationalPolicy(),
			Now:    now,
		})
		if err != nil {
			t.Fatalf("expected grace-retained processing to succeed at tick %d, got %v", tick, err)
		}

		states, err = UpsertControlLoopOwnerState(states, result.State)
		if err != nil {
			t.Fatalf("expected grace-retained state upsert to succeed at tick %d, got %v", tick, err)
		}
		if len(states) != 1 {
			t.Fatalf("expected one stored grace owner state at tick %d, got %#v", tick, states)
		}
		if states[0].ConsecutiveOutcomeCount != 1 {
			t.Fatalf("expected grace streak to stay bounded at tick %d, got %#v", tick, states[0])
		}
		if states[0].GraceUntil == nil || !states[0].GraceUntil.Equal(graceUntil) {
			t.Fatalf("expected grace deadline to refresh cleanly at tick %d, got %#v", tick, states[0])
		}

		now = now.Add(8 * time.Second)
	}
}

func TestControlLoopOperatorProcessKeepsSingleOwnerStateAcrossAlternatingLifecycleOutcomes(t *testing.T) {
	now := time.Date(2026, time.March, 15, 16, 30, 0, 0, time.UTC)
	observed := testControlLoopUUIDManagedState(
		testPeriodicReconcileObject(ManagedObjectRootQDisc, "1:", true, false, true),
	)
	refresh := testControlLoopRuntimeUUIDRefresh(
		t,
		correlation.UUIDMembershipRefreshRefreshRequired,
		discovery.RuntimeEvidenceFreshnessStale,
		true,
	)
	graceUntil := now.Add(8 * time.Second)
	grace := testControlLoopRuntimeUUIDGrace(
		t,
		discovery.RuntimeEvidenceChurnActionGraceRetained,
		&graceUntil,
	)
	deferEvidence := discovery.RuntimeEvidenceChurnDecision{
		Action: discovery.RuntimeEvidenceChurnActionDefer,
		Reason: "runtime evidence is only partially trustworthy",
	}

	inputs := []ControlLoopInput{
		{
			Desired:  ManagedStateSet{OwnerKey: observed.OwnerKey},
			Observed: observed,
			RuntimeSignals: ControlLoopRuntimeSignals{
				UUIDMembershipRefresh: &refresh,
			},
		},
		{
			Desired:  observed,
			Observed: observed,
			RuntimeSignals: ControlLoopRuntimeSignals{
				UUIDMembershipGrace: &grace,
			},
		},
		{
			Desired:  observed,
			Observed: observed,
			RuntimeSignals: ControlLoopRuntimeSignals{
				RuntimeEvidence: &deferEvidence,
			},
		},
	}

	var states []ControlLoopOwnerState
	for index, loopInput := range inputs {
		var previous *ControlLoopOwnerState
		if len(states) == 1 {
			copy := states[0]
			previous = &copy
		}

		result, err := (ControlLoopOperator{}).Process(ControlLoopProcessInput{
			State:  previous,
			Loop:   loopInput,
			Policy: testControlLoopOperationalPolicy(),
			Now:    now,
		})
		if err != nil {
			t.Fatalf("expected alternating lifecycle processing to succeed at step %d, got %v", index, err)
		}

		states, err = UpsertControlLoopOwnerState(states, result.State)
		if err != nil {
			t.Fatalf("expected alternating lifecycle state upsert to succeed at step %d, got %v", index, err)
		}
		if len(states) != 1 {
			t.Fatalf("expected one stored owner state at step %d, got %#v", index, states)
		}

		now = now.Add(30 * time.Second)
	}

	if states[0].LastOutcome != ControlLoopOutcomeDefer {
		t.Fatalf("expected final stored state to reflect the latest defer outcome, got %#v", states[0])
	}
	if states[0].GraceUntil != nil {
		t.Fatalf("expected stale grace deadline to be cleared after leaving grace retention, got %#v", states[0])
	}
}

func TestRetainControlLoopOwnerStatesPrunesStrandedOwnerMemory(t *testing.T) {
	now := time.Date(2026, time.March, 15, 16, 45, 0, 0, time.UTC)
	states := []ControlLoopOwnerState{
		{
			OwnerKey:                "owner-c",
			LastOutcome:             ControlLoopOutcomeNoChange,
			ConsecutiveOutcomeCount: 1,
			LastRunAt:               now.Add(-30 * time.Second),
			NextRunAt:               now.Add(30 * time.Second),
			LastReason:              "retained later",
		},
		{
			OwnerKey:                "owner-a",
			LastOutcome:             ControlLoopOutcomeNoChange,
			ConsecutiveOutcomeCount: 1,
			LastRunAt:               now.Add(-30 * time.Second),
			NextRunAt:               now.Add(30 * time.Second),
			LastReason:              "keep",
		},
		{
			OwnerKey:                "owner-b",
			LastOutcome:             ControlLoopOutcomeNoChange,
			ConsecutiveOutcomeCount: 1,
			LastRunAt:               now.Add(-30 * time.Second),
			NextRunAt:               now.Add(30 * time.Second),
			LastReason:              "drop",
		},
	}

	retained, err := RetainControlLoopOwnerStates(states, []string{"owner-c", "owner-a"})
	if err != nil {
		t.Fatalf("expected retained owner-state filtering to succeed, got %v", err)
	}

	if len(retained) != 2 || retained[0].OwnerKey != "owner-a" || retained[1].OwnerKey != "owner-c" {
		t.Fatalf("expected stranded owner memory to be pruned and remaining owners sorted, got %#v", retained)
	}

	empty, err := RetainControlLoopOwnerStates(states, nil)
	if err != nil {
		t.Fatalf("expected empty retention to succeed, got %v", err)
	}
	if len(empty) != 0 {
		t.Fatalf("expected empty retention to clear all owner memory, got %#v", empty)
	}
}

func TestUpsertControlLoopOwnerStateRejectsDuplicateBaseState(t *testing.T) {
	now := time.Date(2026, time.March, 15, 17, 0, 0, 0, time.UTC)
	state := ControlLoopOwnerState{
		OwnerKey:                "owner-a",
		LastOutcome:             ControlLoopOutcomeNoChange,
		ConsecutiveOutcomeCount: 1,
		LastRunAt:               now.Add(-30 * time.Second),
		NextRunAt:               now.Add(30 * time.Second),
		LastReason:              "existing owner",
	}

	_, err := UpsertControlLoopOwnerState([]ControlLoopOwnerState{state, state}, state)
	if err == nil || !strings.Contains(err.Error(), "duplicate control-loop owner state") {
		t.Fatalf("expected duplicate stored owner state to be rejected, got %v", err)
	}
}

func TestControlLoopOperatorSelectDueOwnersStaysBoundedAcrossMultipleTicks(t *testing.T) {
	now := time.Date(2026, time.March, 15, 17, 15, 0, 0, time.UTC)
	states := []ControlLoopOwnerState{
		{
			OwnerKey:                "owner-d",
			LastOutcome:             ControlLoopOutcomeNoChange,
			ConsecutiveOutcomeCount: 1,
			LastRunAt:               now.Add(-30 * time.Second),
			NextRunAt:               now,
			LastReason:              "due",
		},
		{
			OwnerKey:                "owner-b",
			LastOutcome:             ControlLoopOutcomeNoChange,
			ConsecutiveOutcomeCount: 1,
			LastRunAt:               now.Add(-30 * time.Second),
			NextRunAt:               now,
			LastReason:              "due",
		},
		{
			OwnerKey:                "owner-c",
			LastOutcome:             ControlLoopOutcomeNoChange,
			ConsecutiveOutcomeCount: 1,
			LastRunAt:               now.Add(-30 * time.Second),
			NextRunAt:               now,
			LastReason:              "due",
		},
		{
			OwnerKey:                "owner-a",
			LastOutcome:             ControlLoopOutcomeNoChange,
			ConsecutiveOutcomeCount: 1,
			LastRunAt:               now.Add(-30 * time.Second),
			NextRunAt:               now,
			LastReason:              "due",
		},
	}

	first, err := (ControlLoopOperator{}).SelectDueOwners(ControlLoopSelectionInput{
		States: states,
		Policy: testControlLoopOperationalPolicy(),
		Now:    now,
	})
	if err != nil {
		t.Fatalf("expected first bounded scheduling tick to succeed, got %v", err)
	}
	if len(first.Scheduled) != 2 || first.Scheduled[0].OwnerKey != "owner-a" || first.Scheduled[1].OwnerKey != "owner-b" {
		t.Fatalf("expected first tick to schedule the first two deterministic owners, got %#v", first.Scheduled)
	}

	advanced := make([]ControlLoopOwnerState, 0, 4)
	for _, state := range first.Scheduled {
		state.LastRunAt = now
		state.NextRunAt = now.Add(30 * time.Second)
		advanced = append(advanced, state)
	}
	advanced = append(advanced, first.Deferred...)

	second, err := (ControlLoopOperator{}).SelectDueOwners(ControlLoopSelectionInput{
		States: advanced,
		Policy: testControlLoopOperationalPolicy(),
		Now:    now.Add(time.Second),
	})
	if err != nil {
		t.Fatalf("expected second bounded scheduling tick to succeed, got %v", err)
	}
	if len(second.Scheduled) != 2 || second.Scheduled[0].OwnerKey != "owner-c" || second.Scheduled[1].OwnerKey != "owner-d" {
		t.Fatalf("expected deferred owners to run on the next tick without duplication, got %#v", second.Scheduled)
	}
	if len(second.Deferred) != 0 {
		t.Fatalf("expected no deferred owners after the second tick, got %#v", second.Deferred)
	}
}
