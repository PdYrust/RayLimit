package discovery

import (
	"testing"
	"time"
)

func testUUIDRoutingEvidenceNow() time.Time {
	return time.Date(2026, time.March, 15, 19, 0, 0, 0, time.UTC)
}

func testUUIDRoutingContext() UUIDRoutingContext {
	return UUIDRoutingContext{
		Runtime:      testSessionEvidenceRuntime(),
		UUID:         "user-a",
		Network:      "tcp",
		InboundTag:   "socks-in",
		OutboundTag:  "proxy-out",
		Protocol:     "bittorrent",
		TargetDomain: "example.net",
		SourceIPs:    []string{"2001:db8::10", "::ffff:203.0.113.10"},
		LocalIPs:     []string{"2001:db8::20"},
		TargetIPs:    []string{"2001:db8::30"},
		SourcePort:   43120,
		LocalPort:    8443,
		TargetPort:   443,
		Confidence:   SessionEvidenceConfidenceHigh,
	}
}

func testUUIDRoutingEvidenceSnapshot(result UUIDRoutingEvidenceResult, observedAt time.Time) UUIDRoutingEvidenceSnapshot {
	return UUIDRoutingEvidenceSnapshot{
		Result:     result,
		ObservedAt: observedAt,
	}
}

func TestUUIDRoutingContextValidateAllowsIPv6AwareFields(t *testing.T) {
	context := testUUIDRoutingContext()

	if err := context.Validate(); err != nil {
		t.Fatalf("expected ipv6-aware uuid routing context to validate, got %v", err)
	}

	if got := context.Key(); got == "" {
		t.Fatal("expected uuid routing context key to be populated")
	}
}

func TestUUIDRoutingEvidenceResultStateCandidate(t *testing.T) {
	result := UUIDRoutingEvidenceResult{
		Provider: "xray-routing-api",
		Runtime:  testSessionEvidenceRuntime(),
		UUID:     "user-a",
		Candidate: &UUIDNonIPBackendCandidate{
			Status: UUIDNonIPBackendStatusCandidate,
			Kind:   UUIDNonIPBackendKindRoutingStatsPortClassifier,
			Reason: "routing candidate exists",
		},
	}

	if err := result.Validate(); err != nil {
		t.Fatalf("expected candidate-only uuid routing evidence to validate, got %v", err)
	}
	if result.State() != UUIDRoutingEvidenceStateCandidate {
		t.Fatalf("expected candidate routing evidence state, got %q", result.State())
	}
}

func TestAssessUUIDRoutingEvidenceFreshLive(t *testing.T) {
	now := testUUIDRoutingEvidenceNow()
	result := UUIDRoutingEvidenceResult{
		Provider: "xray-routing-api",
		Runtime:  testSessionEvidenceRuntime(),
		UUID:     "user-a",
		Contexts: []UUIDRoutingContext{testUUIDRoutingContext()},
	}

	assessment, err := AssessUUIDRoutingEvidence(testUUIDRoutingEvidenceSnapshot(result, now.Add(-10*time.Second)), testRuntimeEvidencePolicy(), now)
	if err != nil {
		t.Fatalf("expected fresh uuid routing evidence assessment to succeed, got %v", err)
	}

	if assessment.Freshness != UUIDRoutingEvidenceFreshnessFresh || !assessment.Trusted || assessment.RefreshNeeded {
		t.Fatalf("expected fresh trusted uuid routing evidence, got %#v", assessment)
	}
}

func TestAssessUUIDRoutingEvidenceCandidate(t *testing.T) {
	now := testUUIDRoutingEvidenceNow()
	result := UUIDRoutingEvidenceResult{
		Provider: "xray-routing-api",
		Runtime:  testSessionEvidenceRuntime(),
		UUID:     "user-a",
		Candidate: &UUIDNonIPBackendCandidate{
			Status: UUIDNonIPBackendStatusCandidate,
			Kind:   UUIDNonIPBackendKindRoutingStatsPortClassifier,
			Reason: "routing candidate exists",
		},
	}

	assessment, err := AssessUUIDRoutingEvidence(testUUIDRoutingEvidenceSnapshot(result, now.Add(-5*time.Second)), testRuntimeEvidencePolicy(), now)
	if err != nil {
		t.Fatalf("expected candidate uuid routing evidence assessment to succeed, got %v", err)
	}

	if assessment.Freshness != UUIDRoutingEvidenceFreshnessCandidate || !assessment.RefreshNeeded || assessment.Trusted {
		t.Fatalf("expected candidate-only uuid routing evidence classification, got %#v", assessment)
	}
}

func TestAssessUUIDRoutingEvidenceStale(t *testing.T) {
	now := testUUIDRoutingEvidenceNow()
	result := UUIDRoutingEvidenceResult{
		Provider: "xray-routing-api",
		Runtime:  testSessionEvidenceRuntime(),
		UUID:     "user-a",
		Contexts: []UUIDRoutingContext{testUUIDRoutingContext()},
	}

	assessment, err := AssessUUIDRoutingEvidence(testUUIDRoutingEvidenceSnapshot(result, now.Add(-2*time.Minute)), testRuntimeEvidencePolicy(), now)
	if err != nil {
		t.Fatalf("expected stale uuid routing evidence assessment to succeed, got %v", err)
	}

	if assessment.Freshness != UUIDRoutingEvidenceFreshnessStale || !assessment.RefreshNeeded || assessment.Trusted {
		t.Fatalf("expected stale uuid routing evidence classification, got %#v", assessment)
	}
}

func TestAssessUUIDRoutingEvidencePartial(t *testing.T) {
	now := testUUIDRoutingEvidenceNow()
	result := UUIDRoutingEvidenceResult{
		Provider: "xray-routing-api",
		Runtime:  testSessionEvidenceRuntime(),
		UUID:     "user-a",
		Candidate: &UUIDNonIPBackendCandidate{
			Status: UUIDNonIPBackendStatusCandidate,
			Kind:   UUIDNonIPBackendKindRoutingStatsPortClassifier,
			Reason: "routing candidate exists",
		},
		Issues: []SessionEvidenceIssue{{
			Code:    SessionEvidenceIssueInsufficient,
			Message: "routing rows were incomplete",
		}},
	}

	assessment, err := AssessUUIDRoutingEvidence(testUUIDRoutingEvidenceSnapshot(result, now.Add(-5*time.Second)), testRuntimeEvidencePolicy(), now)
	if err != nil {
		t.Fatalf("expected partial uuid routing evidence assessment to succeed, got %v", err)
	}

	if assessment.Freshness != UUIDRoutingEvidenceFreshnessPartial || !assessment.RefreshNeeded || assessment.Trusted {
		t.Fatalf("expected partial uuid routing evidence classification, got %#v", assessment)
	}
}
