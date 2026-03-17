package discovery

import (
	"testing"
	"time"
)

func testRuntimeEvidencePolicy() RuntimeEvidencePolicy {
	return RuntimeEvidencePolicy{FreshTTL: 30 * time.Second}
}

func testRuntimeEvidenceNow() time.Time {
	return time.Date(2026, time.March, 15, 12, 0, 0, 0, time.UTC)
}

func testRuntimeEvidenceSnapshot(result SessionEvidenceResult, observedAt time.Time) RuntimeEvidenceSnapshot {
	return RuntimeEvidenceSnapshot{
		Result:     result,
		ObservedAt: observedAt,
	}
}

func TestAssessRuntimeEvidenceFreshAvailable(t *testing.T) {
	now := testRuntimeEvidenceNow()
	result := SessionEvidenceResult{
		Provider: "xray-api",
		Runtime:  testSessionEvidenceRuntime(),
		Evidence: []SessionEvidence{{
			Runtime:    testSessionEvidenceRuntime(),
			Session:    testSessionEvidenceSession(),
			Confidence: SessionEvidenceConfidenceHigh,
		}},
	}

	assessment, err := AssessRuntimeEvidence(testRuntimeEvidenceSnapshot(result, now.Add(-10*time.Second)), testRuntimeEvidencePolicy(), now)
	if err != nil {
		t.Fatalf("expected fresh runtime evidence assessment to succeed, got %v", err)
	}

	if assessment.Freshness != RuntimeEvidenceFreshnessFresh || assessment.RefreshNeeded || !assessment.Trusted {
		t.Fatalf("expected fresh trusted runtime evidence, got %#v", assessment)
	}
}

func TestAssessRuntimeEvidenceFreshNoSessions(t *testing.T) {
	now := testRuntimeEvidenceNow()
	result := SessionEvidenceResult{
		Provider: "xray-api",
		Runtime:  testSessionEvidenceRuntime(),
	}

	assessment, err := AssessRuntimeEvidence(testRuntimeEvidenceSnapshot(result, now.Add(-5*time.Second)), testRuntimeEvidencePolicy(), now)
	if err != nil {
		t.Fatalf("expected fresh no-session runtime evidence assessment to succeed, got %v", err)
	}

	if assessment.Freshness != RuntimeEvidenceFreshnessFresh || assessment.RefreshNeeded || !assessment.Trusted {
		t.Fatalf("expected fresh reusable no-session runtime evidence, got %#v", assessment)
	}
}

func TestAssessRuntimeEvidenceStale(t *testing.T) {
	now := testRuntimeEvidenceNow()
	result := SessionEvidenceResult{
		Provider: "xray-api",
		Runtime:  testSessionEvidenceRuntime(),
	}

	assessment, err := AssessRuntimeEvidence(testRuntimeEvidenceSnapshot(result, now.Add(-2*time.Minute)), testRuntimeEvidencePolicy(), now)
	if err != nil {
		t.Fatalf("expected stale runtime evidence assessment to succeed, got %v", err)
	}

	if assessment.Freshness != RuntimeEvidenceFreshnessStale || !assessment.RefreshNeeded || assessment.Trusted {
		t.Fatalf("expected stale runtime evidence classification, got %#v", assessment)
	}
}

func TestAssessRuntimeEvidenceUnavailable(t *testing.T) {
	now := testRuntimeEvidenceNow()
	result := SessionEvidenceResult{
		Provider: "xray-api",
		Runtime:  testSessionEvidenceRuntime(),
		Issues: []SessionEvidenceIssue{{
			Code:    SessionEvidenceIssueUnavailable,
			Message: "runtime control socket is unreachable",
		}},
	}

	assessment, err := AssessRuntimeEvidence(testRuntimeEvidenceSnapshot(result, now.Add(-5*time.Second)), testRuntimeEvidencePolicy(), now)
	if err != nil {
		t.Fatalf("expected unavailable runtime evidence assessment to succeed, got %v", err)
	}

	if assessment.Freshness != RuntimeEvidenceFreshnessUnavailable || !assessment.RefreshNeeded || assessment.Trusted {
		t.Fatalf("expected unavailable runtime evidence classification, got %#v", assessment)
	}
}

func TestAssessRuntimeEvidencePartial(t *testing.T) {
	now := testRuntimeEvidenceNow()
	result := SessionEvidenceResult{
		Provider: "xray-api",
		Runtime:  testSessionEvidenceRuntime(),
		Issues: []SessionEvidenceIssue{{
			Code:    SessionEvidenceIssueInsufficient,
			Message: "session rows were incomplete",
		}},
	}

	assessment, err := AssessRuntimeEvidence(testRuntimeEvidenceSnapshot(result, now.Add(-5*time.Second)), testRuntimeEvidencePolicy(), now)
	if err != nil {
		t.Fatalf("expected partial runtime evidence assessment to succeed, got %v", err)
	}

	if assessment.Freshness != RuntimeEvidenceFreshnessPartial || !assessment.RefreshNeeded || assessment.Trusted {
		t.Fatalf("expected partial runtime evidence classification, got %#v", assessment)
	}
}
