package correlation

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/PdYrust/RayLimit/internal/discovery"
)

type stubUUIDSessionProvider struct {
	result discovery.SessionEvidenceResult
	err    error
}

type stubRuntimeTargetDiscoverer struct {
	result discovery.Result
	err    error
}

func (p stubUUIDSessionProvider) Name() string {
	return "stub"
}

func (p stubUUIDSessionProvider) ObserveSessions(_ context.Context, _ discovery.SessionRuntime) (discovery.SessionEvidenceResult, error) {
	return p.result, p.err
}

func (d stubRuntimeTargetDiscoverer) Discover(context.Context, discovery.Request) (discovery.Result, error) {
	return d.result, d.err
}

func testUUIDRuntime() discovery.SessionRuntime {
	return discovery.SessionRuntime{
		Source:  discovery.DiscoverySourceHostProcess,
		Name:    "edge-a",
		HostPID: 1001,
	}
}

func testUUIDSession(id string, uuid string) discovery.Session {
	return discovery.Session{
		ID: id,
		Runtime: discovery.SessionRuntime{
			Source:  discovery.DiscoverySourceHostProcess,
			Name:    "edge-a",
			HostPID: 1001,
		},
		Policy: discovery.SessionPolicyIdentity{
			UUID: uuid,
		},
		Client: discovery.SessionClient{
			IP: "203.0.113.10",
		},
		Route: discovery.SessionRoute{
			InboundTag:  "api-in",
			OutboundTag: "proxy-out",
		},
	}
}

func TestUUIDResolverCorrelateUnavailableWithoutProvider(t *testing.T) {
	result, err := (UUIDResolver{}).Correlate(context.Background(), UUIDRequest{
		UUID:    "user-a",
		Runtime: testUUIDRuntime(),
	})
	if err != nil {
		t.Fatalf("expected correlation to succeed, got %v", err)
	}

	if result.Status != UUIDStatusUnavailable {
		t.Fatalf("expected unavailable status, got %#v", result)
	}
	if !strings.Contains(result.Note, "no live session provider is configured") {
		t.Fatalf("unexpected correlation note: %#v", result)
	}
}

func TestUUIDResolverCorrelateUnavailableOnProviderError(t *testing.T) {
	result, err := (UUIDResolver{
		Provider: stubUUIDSessionProvider{
			err: errors.New("permission denied"),
		},
	}).Correlate(context.Background(), UUIDRequest{
		UUID:    "user-a",
		Runtime: testUUIDRuntime(),
	})
	if err != nil {
		t.Fatalf("expected correlation to succeed, got %v", err)
	}

	if result.Status != UUIDStatusUnavailable {
		t.Fatalf("expected unavailable status, got %#v", result)
	}
	if !strings.Contains(result.Note, "permission denied") {
		t.Fatalf("unexpected correlation note: %#v", result)
	}
}

func TestUUIDResolverCorrelateZeroMatch(t *testing.T) {
	result, err := (UUIDResolver{
		Provider: stubUUIDSessionProvider{
			result: discovery.SessionEvidenceResult{
				Provider: "xray-api",
				Runtime:  testUUIDRuntime(),
				Evidence: []discovery.SessionEvidence{
					{
						Runtime:    testUUIDRuntime(),
						Session:    testUUIDSession("conn-1", "other-user"),
						Confidence: discovery.SessionEvidenceConfidenceHigh,
					},
				},
			},
		},
	}).Correlate(context.Background(), UUIDRequest{
		UUID:    "user-a",
		Runtime: testUUIDRuntime(),
	})
	if err != nil {
		t.Fatalf("expected correlation to succeed, got %v", err)
	}

	if result.Status != UUIDStatusZeroSessions {
		t.Fatalf("expected zero-session status, got %#v", result)
	}
	if result.MatchedSessionCount() != 0 {
		t.Fatalf("expected zero matched sessions, got %#v", result)
	}
}

func TestUUIDResolverCorrelateSingleMatch(t *testing.T) {
	result, err := (UUIDResolver{
		Provider: stubUUIDSessionProvider{
			result: discovery.SessionEvidenceResult{
				Provider: "xray-api",
				Runtime:  testUUIDRuntime(),
				Evidence: []discovery.SessionEvidence{
					{
						Runtime:    testUUIDRuntime(),
						Session:    testUUIDSession("conn-1", "user-a"),
						Confidence: discovery.SessionEvidenceConfidenceHigh,
					},
				},
			},
		},
	}).Correlate(context.Background(), UUIDRequest{
		UUID:    "USER-A",
		Runtime: testUUIDRuntime(),
	})
	if err != nil {
		t.Fatalf("expected correlation to succeed, got %v", err)
	}

	if result.Status != UUIDStatusSingleSession {
		t.Fatalf("expected single-session status, got %#v", result)
	}
	if result.Provider != "xray-api" {
		t.Fatalf("expected correlation provider to be preserved, got %#v", result)
	}
	if result.Confidence != discovery.SessionEvidenceConfidenceHigh {
		t.Fatalf("expected high-confidence single-session correlation, got %#v", result)
	}
	if result.MatchedSessionCount() != 1 || result.Sessions[0].ID != "conn-1" {
		t.Fatalf("unexpected matched sessions: %#v", result)
	}
}

func TestUUIDResolverCorrelateMultipleMatches(t *testing.T) {
	result, err := (UUIDResolver{
		Provider: stubUUIDSessionProvider{
			result: discovery.SessionEvidenceResult{
				Provider: "xray-api",
				Runtime:  testUUIDRuntime(),
				Evidence: []discovery.SessionEvidence{
					{
						Runtime:    testUUIDRuntime(),
						Session:    testUUIDSession("conn-1", "user-a"),
						Confidence: discovery.SessionEvidenceConfidenceHigh,
					},
					{
						Runtime:    testUUIDRuntime(),
						Session:    testUUIDSession("conn-2", "user-a"),
						Confidence: discovery.SessionEvidenceConfidenceHigh,
					},
				},
			},
		},
	}).Correlate(context.Background(), UUIDRequest{
		UUID:    "user-a",
		Runtime: testUUIDRuntime(),
	})
	if err != nil {
		t.Fatalf("expected correlation to succeed, got %v", err)
	}

	if result.Status != UUIDStatusMultipleSessions {
		t.Fatalf("expected multiple-session status, got %#v", result)
	}
	if result.Confidence != discovery.SessionEvidenceConfidenceHigh {
		t.Fatalf("expected high-confidence multi-session correlation, got %#v", result)
	}
	if result.MatchedSessionCount() != 2 {
		t.Fatalf("unexpected matched sessions: %#v", result)
	}
}

func TestUUIDResolverCorrelateFlagsIncompleteEvidence(t *testing.T) {
	result, err := (UUIDResolver{
		Provider: stubUUIDSessionProvider{
			result: discovery.SessionEvidenceResult{
				Provider: "xray-api",
				Runtime:  testUUIDRuntime(),
				Evidence: []discovery.SessionEvidence{
					{
						Runtime:    testUUIDRuntime(),
						Session:    testUUIDSession("conn-1", "user-a"),
						Confidence: discovery.SessionEvidenceConfidenceHigh,
					},
				},
				Issues: []discovery.SessionEvidenceIssue{
					{
						Code:    discovery.SessionEvidenceIssueInsufficient,
						Message: "provider returned partially invalid or unrelated session evidence",
					},
				},
			},
		},
	}).Correlate(context.Background(), UUIDRequest{
		UUID:    "user-a",
		Runtime: testUUIDRuntime(),
	})
	if err != nil {
		t.Fatalf("expected correlation to succeed, got %v", err)
	}

	if result.Status != UUIDStatusSingleSession {
		t.Fatalf("expected single-session status, got %#v", result)
	}
	if !strings.Contains(result.Note, "partially invalid or unrelated") {
		t.Fatalf("expected incomplete-evidence note, got %#v", result)
	}
}

func TestUUIDResolverCorrelateTreatsLowConfidenceMatchesAsUnavailable(t *testing.T) {
	result, err := (UUIDResolver{
		Provider: stubUUIDSessionProvider{
			result: discovery.SessionEvidenceResult{
				Provider: "xray-api",
				Runtime:  testUUIDRuntime(),
				Evidence: []discovery.SessionEvidence{
					{
						Runtime:    testUUIDRuntime(),
						Session:    testUUIDSession("conn-1", "user-a"),
						Confidence: discovery.SessionEvidenceConfidenceLow,
					},
				},
			},
		},
	}).Correlate(context.Background(), UUIDRequest{
		UUID:    "user-a",
		Runtime: testUUIDRuntime(),
	})
	if err != nil {
		t.Fatalf("expected correlation to succeed, got %v", err)
	}

	if result.Status != UUIDStatusUnavailable {
		t.Fatalf("expected low-confidence evidence to remain unavailable, got %#v", result)
	}
	if result.MatchedSessionCount() != 0 {
		t.Fatalf("expected low-confidence matches to stay unresolved, got %#v", result)
	}
	if !strings.Contains(result.Note, "low-confidence live session evidence") {
		t.Fatalf("expected low-confidence note, got %#v", result)
	}
}

func TestUUIDResolverCorrelateDeduplicatesTrustedMatches(t *testing.T) {
	duplicate := discovery.SessionEvidence{
		Runtime:    testUUIDRuntime(),
		Session:    testUUIDSession("conn-1", "user-a"),
		Confidence: discovery.SessionEvidenceConfidenceHigh,
	}

	result, err := (UUIDResolver{
		Provider: stubUUIDSessionProvider{
			result: discovery.SessionEvidenceResult{
				Provider: "xray-api",
				Runtime:  testUUIDRuntime(),
				Evidence: []discovery.SessionEvidence{
					duplicate,
					duplicate,
				},
			},
		},
	}).Correlate(context.Background(), UUIDRequest{
		UUID:    "user-a",
		Runtime: testUUIDRuntime(),
	})
	if err != nil {
		t.Fatalf("expected correlation to succeed, got %v", err)
	}

	if result.Status != UUIDStatusSingleSession {
		t.Fatalf("expected duplicate trusted evidence to collapse to one session, got %#v", result)
	}
	if result.MatchedSessionCount() != 1 {
		t.Fatalf("expected one matched session after dedupe, got %#v", result)
	}
}

func TestUUIDResolverCorrelateRejectsMismatchedEvidenceRuntime(t *testing.T) {
	result, err := (UUIDResolver{
		Provider: stubUUIDSessionProvider{
			result: discovery.SessionEvidenceResult{
				Provider: "xray-api",
				Runtime: discovery.SessionRuntime{
					Source:  discovery.DiscoverySourceHostProcess,
					Name:    "other-edge",
					HostPID: 5252,
				},
			},
		},
	}).Correlate(context.Background(), UUIDRequest{
		UUID:    "user-a",
		Runtime: testUUIDRuntime(),
	})
	if err != nil {
		t.Fatalf("expected correlation to succeed, got %v", err)
	}

	if result.Status != UUIDStatusUnavailable {
		t.Fatalf("expected mismatched runtime evidence to remain unavailable, got %#v", result)
	}
	if !strings.Contains(result.Note, "did not match the requested runtime") {
		t.Fatalf("unexpected mismatched-runtime note: %#v", result)
	}
}

func TestUUIDResolverCorrelateTreatsInsufficientEvidenceAsUnavailable(t *testing.T) {
	result, err := (UUIDResolver{
		Provider: stubUUIDSessionProvider{
			result: discovery.SessionEvidenceResult{
				Provider: "xray-api",
				Runtime:  testUUIDRuntime(),
				Issues: []discovery.SessionEvidenceIssue{
					{
						Code:    discovery.SessionEvidenceIssueInsufficient,
						Message: "session rows were incomplete",
					},
				},
			},
		},
	}).Correlate(context.Background(), UUIDRequest{
		UUID:    "user-a",
		Runtime: testUUIDRuntime(),
	})
	if err != nil {
		t.Fatalf("expected correlation to succeed, got %v", err)
	}

	if result.Status != UUIDStatusUnavailable {
		t.Fatalf("expected insufficient evidence to remain unavailable, got %#v", result)
	}
	if !strings.Contains(result.Note, "session rows were incomplete") {
		t.Fatalf("unexpected insufficient-evidence note: %#v", result)
	}
}

func TestUUIDResolverCorrelateRejectsInvalidEvidenceResult(t *testing.T) {
	result, err := (UUIDResolver{
		Provider: stubUUIDSessionProvider{
			result: discovery.SessionEvidenceResult{
				Provider: "xray-api",
				Runtime:  testUUIDRuntime(),
				Evidence: []discovery.SessionEvidence{
					{
						Runtime: testUUIDRuntime(),
						Session: discovery.Session{
							ID:      "broken",
							Runtime: testUUIDRuntime(),
							Client: discovery.SessionClient{
								IP: "not-an-ip",
							},
						},
						Confidence: discovery.SessionEvidenceConfidenceHigh,
					},
				},
			},
		},
	}).Correlate(context.Background(), UUIDRequest{
		UUID:    "user-a",
		Runtime: testUUIDRuntime(),
	})
	if err != nil {
		t.Fatalf("expected correlation to succeed, got %v", err)
	}

	if result.Status != UUIDStatusUnavailable {
		t.Fatalf("expected invalid evidence to remain unavailable, got %#v", result)
	}
	if !strings.Contains(result.Note, "invalid") {
		t.Fatalf("expected invalid-evidence note, got %#v", result)
	}
}

func TestUUIDResolverCorrelateWithXraySessionEvidenceProviderSingleMatch(t *testing.T) {
	target := discovery.RuntimeTarget{
		Source:   discovery.DiscoverySourceHostProcess,
		Identity: discovery.RuntimeIdentity{Name: "edge-a", Binary: "xray"},
		HostProcess: &discovery.HostProcessCandidate{
			PID: 1001,
		},
		APICapability: &discovery.APICapability{
			Status: discovery.APICapabilityStatusLikelyConfigured,
			Reason: "Existing runtime metadata already includes API endpoint hints.",
		},
		APIEndpoints: []discovery.APIEndpoint{
			{
				Name:    "api",
				Network: discovery.EndpointNetworkTCP,
				Address: "127.0.0.1",
				Port:    10085,
			},
		},
	}

	provider := discovery.NewXraySessionEvidenceProvider(stubRuntimeTargetDiscoverer{
		result: discovery.Result{Targets: []discovery.RuntimeTarget{target}},
	})
	provider.ProbeEndpoint = func(context.Context, discovery.APIEndpoint) error { return nil }
	provider.QuerySessions = func(context.Context, discovery.RuntimeTarget, discovery.APIEndpoint) ([]discovery.SessionEvidence, error) {
		return []discovery.SessionEvidence{
			{
				Session:    testUUIDSession("conn-1", "user-a"),
				Confidence: discovery.SessionEvidenceConfidenceHigh,
			},
		}, nil
	}

	result, err := (UUIDResolver{Provider: provider}).Correlate(context.Background(), UUIDRequest{
		UUID:    "user-a",
		Runtime: testUUIDRuntime(),
	})
	if err != nil {
		t.Fatalf("expected correlation to succeed, got %v", err)
	}

	if result.Status != UUIDStatusSingleSession {
		t.Fatalf("expected single-session status, got %#v", result)
	}
	if result.Confidence != discovery.SessionEvidenceConfidenceHigh {
		t.Fatalf("expected high-confidence single-session correlation, got %#v", result)
	}
	if result.MatchedSessionCount() != 1 || result.Sessions[0].ID != "conn-1" {
		t.Fatalf("unexpected matched sessions: %#v", result)
	}
}

func TestUUIDResolverCorrelateWithXraySessionEvidenceProviderReportsUnavailableWhenQueryFails(t *testing.T) {
	target := discovery.RuntimeTarget{
		Source:   discovery.DiscoverySourceHostProcess,
		Identity: discovery.RuntimeIdentity{Name: "edge-a", Binary: "xray"},
		HostProcess: &discovery.HostProcessCandidate{
			PID: 1001,
		},
		APICapability: &discovery.APICapability{
			Status: discovery.APICapabilityStatusLikelyConfigured,
			Reason: "Existing runtime metadata already includes API endpoint hints.",
		},
		APIEndpoints: []discovery.APIEndpoint{
			{
				Name:    "api",
				Network: discovery.EndpointNetworkTCP,
				Address: "127.0.0.1",
				Port:    10085,
			},
		},
	}

	provider := discovery.NewXraySessionEvidenceProvider(stubRuntimeTargetDiscoverer{
		result: discovery.Result{Targets: []discovery.RuntimeTarget{target}},
	})
	provider.ProbeEndpoint = func(context.Context, discovery.APIEndpoint) error { return nil }
	provider.RunAPICommand = func(context.Context, string, string, ...string) ([]byte, error) {
		return nil, errors.New("xray api query failed in test")
	}

	result, err := (UUIDResolver{Provider: provider}).Correlate(context.Background(), UUIDRequest{
		UUID:    "user-a",
		Runtime: testUUIDRuntime(),
	})
	if err != nil {
		t.Fatalf("expected correlation to succeed, got %v", err)
	}

	if result.Status != UUIDStatusUnavailable {
		t.Fatalf("expected unavailable status, got %#v", result)
	}
	if !strings.Contains(result.Note, "query failed") {
		t.Fatalf("unexpected unavailable note: %#v", result)
	}
}

func TestUUIDResolverCorrelateUsesUUIDTargetedEvidenceWhenGenericRuntimeEvidenceHasNoMatch(t *testing.T) {
	target := discovery.RuntimeTarget{
		Source:   discovery.DiscoverySourceHostProcess,
		Identity: discovery.RuntimeIdentity{Name: "edge-a", Binary: "xray"},
		HostProcess: &discovery.HostProcessCandidate{
			PID: 1001,
		},
		APICapability: &discovery.APICapability{
			Status: discovery.APICapabilityStatusLikelyConfigured,
			Reason: "Existing runtime metadata already includes API endpoint hints.",
		},
		APIEndpoints: []discovery.APIEndpoint{
			{
				Name:    "api",
				Network: discovery.EndpointNetworkTCP,
				Address: "127.0.0.1",
				Port:    10085,
			},
		},
	}

	provider := discovery.NewXraySessionEvidenceProvider(stubRuntimeTargetDiscoverer{
		result: discovery.Result{Targets: []discovery.RuntimeTarget{target}},
	})
	provider.ProbeEndpoint = func(context.Context, discovery.APIEndpoint) error { return nil }
	provider.QuerySessions = func(context.Context, discovery.RuntimeTarget, discovery.APIEndpoint) ([]discovery.SessionEvidence, error) {
		return nil, nil
	}
	provider.QueryUUIDSessions = func(context.Context, discovery.RuntimeTarget, discovery.APIEndpoint, string) ([]discovery.SessionEvidence, error) {
		return []discovery.SessionEvidence{
			{
				Session: discovery.Session{
					ID:      "xray-online-user:user-a",
					Runtime: testUUIDRuntime(),
					Policy: discovery.SessionPolicyIdentity{
						UUID: "user-a",
					},
				},
				Confidence: discovery.SessionEvidenceConfidenceMedium,
			},
		}, nil
	}

	result, err := (UUIDResolver{Provider: provider}).Correlate(context.Background(), UUIDRequest{
		UUID:    "user-a",
		Runtime: testUUIDRuntime(),
	})
	if err != nil {
		t.Fatalf("expected correlation to succeed, got %v", err)
	}

	if result.Status != UUIDStatusSingleSession {
		t.Fatalf("expected single-session status from targeted evidence, got %#v", result)
	}
	if result.Confidence != discovery.SessionEvidenceConfidenceMedium {
		t.Fatalf("expected medium confidence from targeted evidence, got %#v", result)
	}
	if len(result.Sessions) != 1 || result.Sessions[0].ID != "xray-online-user:user-a" {
		t.Fatalf("unexpected targeted matched sessions: %#v", result.Sessions)
	}
}
