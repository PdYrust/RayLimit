package discovery

import "testing"

func testSessionEvidenceRuntime() SessionRuntime {
	return SessionRuntime{
		Source:   DiscoverySourceHostProcess,
		Provider: "xray-api",
		Name:     "edge-a",
		HostPID:  4242,
	}
}

func testSessionEvidenceSession() Session {
	return Session{
		ID:      "conn-1",
		Runtime: testSessionEvidenceRuntime(),
		Client: SessionClient{
			IP: "203.0.113.10",
		},
		Route: SessionRoute{
			InboundTag:  "api-in",
			OutboundTag: "proxy-out",
		},
	}
}

func TestSessionEvidenceResultValidateAvailableEvidence(t *testing.T) {
	result := SessionEvidenceResult{
		Provider: "xray-api",
		Runtime:  testSessionEvidenceRuntime(),
		Evidence: []SessionEvidence{
			{
				Runtime:    testSessionEvidenceRuntime(),
				Session:    testSessionEvidenceSession(),
				Confidence: SessionEvidenceConfidenceHigh,
			},
		},
	}

	if err := result.Validate(); err != nil {
		t.Fatalf("expected session evidence result to validate, got %v", err)
	}
	if result.State() != SessionEvidenceStateAvailable {
		t.Fatalf("expected available evidence state, got %q", result.State())
	}
	if sessions := result.Sessions(); len(sessions) != 1 || sessions[0].ID != "conn-1" {
		t.Fatalf("unexpected observed sessions: %#v", sessions)
	}
}

func TestSessionEvidenceResultStateNoSessions(t *testing.T) {
	result := SessionEvidenceResult{
		Provider: "xray-api",
		Runtime:  testSessionEvidenceRuntime(),
	}

	if err := result.Validate(); err != nil {
		t.Fatalf("expected empty evidence result to validate, got %v", err)
	}
	if result.State() != SessionEvidenceStateNoSessions {
		t.Fatalf("expected no-sessions evidence state, got %q", result.State())
	}
}

func TestSessionEvidenceResultStateUnavailable(t *testing.T) {
	result := SessionEvidenceResult{
		Provider: "xray-api",
		Runtime:  testSessionEvidenceRuntime(),
		Issues: []SessionEvidenceIssue{
			{
				Code:    SessionEvidenceIssuePermissionDenied,
				Message: "access denied to the runtime control socket",
			},
		},
	}

	if err := result.Validate(); err != nil {
		t.Fatalf("expected unavailable evidence result to validate, got %v", err)
	}
	if result.State() != SessionEvidenceStateUnavailable {
		t.Fatalf("expected unavailable evidence state, got %q", result.State())
	}
}

func TestSessionEvidenceResultStateInsufficient(t *testing.T) {
	result := SessionEvidenceResult{
		Provider: "xray-api",
		Runtime:  testSessionEvidenceRuntime(),
		Issues: []SessionEvidenceIssue{
			{
				Code:    SessionEvidenceIssueInsufficient,
				Message: "provider returned session rows without stable identifiers",
			},
		},
	}

	if err := result.Validate(); err != nil {
		t.Fatalf("expected insufficient evidence result to validate, got %v", err)
	}
	if result.State() != SessionEvidenceStateInsufficient {
		t.Fatalf("expected insufficient evidence state, got %q", result.State())
	}
}

func TestSessionEvidenceResultValidateRejectsMismatchedRuntime(t *testing.T) {
	otherRuntime := testSessionEvidenceRuntime()
	otherRuntime.HostPID = 5252

	result := SessionEvidenceResult{
		Provider: "xray-api",
		Runtime:  testSessionEvidenceRuntime(),
		Evidence: []SessionEvidence{
			{
				Runtime:    otherRuntime,
				Session:    Session{ID: "conn-1", Runtime: otherRuntime},
				Confidence: SessionEvidenceConfidenceMedium,
			},
		},
	}

	if err := result.Validate(); err == nil {
		t.Fatal("expected mismatched evidence runtime to fail validation")
	}
}

func TestSessionEvidenceResultIssueSummary(t *testing.T) {
	result := SessionEvidenceResult{
		Provider: "xray-api",
		Runtime:  testSessionEvidenceRuntime(),
		Issues: []SessionEvidenceIssue{
			{
				Code:    SessionEvidenceIssueUnavailable,
				Message: "socket not reachable",
			},
			{
				Code:    SessionEvidenceIssueInsufficient,
				Message: "session rows were incomplete",
			},
		},
	}

	if got := result.IssueSummary(); got != "socket not reachable; session rows were incomplete" {
		t.Fatalf("unexpected issue summary %q", got)
	}
}
