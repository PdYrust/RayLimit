package tc

import (
	"testing"
	"time"

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
	desired := testControlLoopRuntimeDerivedState(
		testPeriodicReconcileObject(ManagedObjectRootQDisc, "1:", true, false, true),
		testPeriodicReconcileObject(ManagedObjectMarkAttachmentTable, "inet|raylimit_eth0_upload", true, false, false),
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
				RuntimeEvidence: &discovery.RuntimeEvidenceChurnDecision{
					Action: discovery.RuntimeEvidenceChurnActionRefreshRequired,
					Reason: "runtime-derived owner evidence requires a fresher refresh",
				},
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

func TestControlLoopOperatorSelectDueOwnersHonorsWorkBudget(t *testing.T) {
	now := time.Date(2026, time.March, 15, 15, 32, 0, 0, time.UTC)

	result, err := (ControlLoopOperator{}).SelectDueOwners(ControlLoopSelectionInput{
		States: []ControlLoopOwnerState{
			{
				OwnerKey:                "owner-c",
				LastOutcome:             ControlLoopOutcomeNoChange,
				ConsecutiveOutcomeCount: 1,
				LastRunAt:               now.Add(-10 * time.Second),
				NextRunAt:               now.Add(10 * time.Second),
				LastReason:              "not due yet",
			},
			{
				OwnerKey:                "owner-b",
				LastOutcome:             ControlLoopOutcomeRefreshRequired,
				ConsecutiveOutcomeCount: 2,
				LastRunAt:               now.Add(-20 * time.Second),
				NextRunAt:               now.Add(-1 * time.Second),
				LastReason:              "due second",
			},
			{
				OwnerKey:                "owner-a",
				LastOutcome:             ControlLoopOutcomeNoChange,
				ConsecutiveOutcomeCount: 1,
				LastRunAt:               now.Add(-30 * time.Second),
				NextRunAt:               now.Add(-5 * time.Second),
				LastReason:              "due first",
			},
			{
				OwnerKey:                "owner-d",
				LastOutcome:             ControlLoopOutcomeDefer,
				ConsecutiveOutcomeCount: 1,
				LastRunAt:               now.Add(-40 * time.Second),
				NextRunAt:               now,
				LastReason:              "due immediately",
			},
		},
		Policy: testControlLoopOperationalPolicy(),
		Now:    now,
	})
	if err != nil {
		t.Fatalf("expected owner selection to succeed, got %v", err)
	}

	if len(result.Scheduled) != 2 || len(result.Deferred) != 1 {
		t.Fatalf("expected two scheduled owners and one deferred owner, got %#v", result)
	}
	if result.Scheduled[0].OwnerKey != "owner-a" || result.Scheduled[1].OwnerKey != "owner-b" {
		t.Fatalf("expected due owners to be scheduled in deterministic order, got %#v", result.Scheduled)
	}
	if result.Deferred[0].OwnerKey != "owner-d" {
		t.Fatalf("expected the remaining due owner to be deferred, got %#v", result.Deferred)
	}
}
