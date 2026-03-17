package discovery

import (
	"testing"
	"time"
)

func testRuntimeEvidenceChurnPolicy() RuntimeEvidenceChurnPolicy {
	return RuntimeEvidenceChurnPolicy{DisconnectGraceTTL: 20 * time.Second}
}

func TestDecideRuntimeEvidenceChurnStableWhenFreshEvidenceDoesNotConfirmAbsence(t *testing.T) {
	decision, err := DecideRuntimeEvidenceChurn(RuntimeEvidenceChurnInput{
		Assessment: RuntimeEvidenceAssessment{
			Freshness: RuntimeEvidenceFreshnessFresh,
			Trusted:   true,
			Reason:    "fresh runtime evidence is available",
		},
		ConfirmedAbsent: false,
		Policy:          testRuntimeEvidenceChurnPolicy(),
		Now:             testRuntimeEvidenceNow(),
	})
	if err != nil {
		t.Fatalf("expected stable churn decision to succeed, got %v", err)
	}

	if decision.Action != RuntimeEvidenceChurnActionStable {
		t.Fatalf("expected stable churn action, got %#v", decision)
	}
}

func TestDecideRuntimeEvidenceChurnGraceRetainedForBriefFreshAbsence(t *testing.T) {
	now := testRuntimeEvidenceNow()
	decision, err := DecideRuntimeEvidenceChurn(RuntimeEvidenceChurnInput{
		Assessment: RuntimeEvidenceAssessment{
			Freshness: RuntimeEvidenceFreshnessFresh,
			Trusted:   true,
			Reason:    "fresh runtime evidence confirms temporary absence",
		},
		ConfirmedAbsent:     true,
		HadTrustedPresence:  true,
		LastTrustedPresence: now.Add(-5 * time.Second),
		Policy:              testRuntimeEvidenceChurnPolicy(),
		Now:                 now,
	})
	if err != nil {
		t.Fatalf("expected grace-retained churn decision to succeed, got %v", err)
	}

	if decision.Action != RuntimeEvidenceChurnActionGraceRetained || decision.GraceUntil == nil {
		t.Fatalf("expected grace-retained churn action, got %#v", decision)
	}
}

func TestDecideRuntimeEvidenceChurnImmediatelyRemovableAfterGraceExpires(t *testing.T) {
	now := testRuntimeEvidenceNow()
	decision, err := DecideRuntimeEvidenceChurn(RuntimeEvidenceChurnInput{
		Assessment: RuntimeEvidenceAssessment{
			Freshness: RuntimeEvidenceFreshnessFresh,
			Trusted:   true,
			Reason:    "fresh runtime evidence confirms absence",
		},
		ConfirmedAbsent:     true,
		HadTrustedPresence:  true,
		LastTrustedPresence: now.Add(-1 * time.Minute),
		Policy:              testRuntimeEvidenceChurnPolicy(),
		Now:                 now,
	})
	if err != nil {
		t.Fatalf("expected immediately-removable churn decision to succeed, got %v", err)
	}

	if decision.Action != RuntimeEvidenceChurnActionImmediatelyRemovable {
		t.Fatalf("expected immediately-removable churn action, got %#v", decision)
	}
}

func TestDecideRuntimeEvidenceChurnRefreshRequiredForStaleEvidence(t *testing.T) {
	decision, err := DecideRuntimeEvidenceChurn(RuntimeEvidenceChurnInput{
		Assessment: RuntimeEvidenceAssessment{
			Freshness:     RuntimeEvidenceFreshnessStale,
			RefreshNeeded: true,
			Reason:        "runtime evidence is stale",
		},
		ConfirmedAbsent: true,
		Policy:          testRuntimeEvidenceChurnPolicy(),
		Now:             testRuntimeEvidenceNow(),
	})
	if err != nil {
		t.Fatalf("expected refresh-required churn decision to succeed, got %v", err)
	}

	if decision.Action != RuntimeEvidenceChurnActionRefreshRequired {
		t.Fatalf("expected refresh-required churn action, got %#v", decision)
	}
}

func TestDecideRuntimeEvidenceChurnDefersOnPartialAndUnavailableEvidence(t *testing.T) {
	for _, freshness := range []RuntimeEvidenceFreshness{
		RuntimeEvidenceFreshnessPartial,
		RuntimeEvidenceFreshnessUnavailable,
	} {
		decision, err := DecideRuntimeEvidenceChurn(RuntimeEvidenceChurnInput{
			Assessment: RuntimeEvidenceAssessment{
				Freshness:     freshness,
				RefreshNeeded: true,
				Reason:        "runtime evidence is degraded",
			},
			ConfirmedAbsent: true,
			Policy:          testRuntimeEvidenceChurnPolicy(),
			Now:             testRuntimeEvidenceNow(),
		})
		if err != nil {
			t.Fatalf("expected deferred churn decision for %q to succeed, got %v", freshness, err)
		}

		if decision.Action != RuntimeEvidenceChurnActionDefer {
			t.Fatalf("expected defer churn action for %q, got %#v", freshness, decision)
		}
	}
}
