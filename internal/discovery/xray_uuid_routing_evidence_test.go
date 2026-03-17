package discovery

import (
	"context"
	"strings"
	"testing"
)

func TestXrayUUIDRoutingEvidenceProviderReturnsCandidateWithoutQueryHook(t *testing.T) {
	configPath := writeXrayAPIConfig(t, `{
  "api": {"tag":"api","services":["RoutingService"]},
  "inbounds": [{"tag":"api","listen":"127.0.0.1","port":10085}],
  "routing": {
    "rules": [
      {"type":"field","user":["user-a"],"outboundTag":"proxy-out"}
    ]
  }
}`)

	provider := NewXrayUUIDRoutingEvidenceProvider(stubRuntimeTargetDiscoverer{
		result: Result{
			Targets: []RuntimeTarget{testXrayEvidenceTarget(t, configPath)},
		},
	})
	provider.ProbeEndpoint = func(context.Context, APIEndpoint) error { return nil }
	provider.QueryRoutingContext = func(context.Context, SessionRuntime, RuntimeTarget, APIEndpoint, string) (xrayUUIDRoutingContextQueryResult, error) {
		return xrayUUIDRoutingContextQueryResult{}, nil
	}

	result, err := provider.ObserveUUIDRoutingEvidence(context.Background(), testXrayEvidenceRuntime(), "user-a")
	if err != nil {
		t.Fatalf("expected candidate-only routing evidence observation to succeed, got %v", err)
	}

	if result.State() != UUIDRoutingEvidenceStateCandidate {
		t.Fatalf("expected candidate-only routing evidence state, got %#v", result)
	}
	if result.Candidate == nil || result.Candidate.Kind != UUIDNonIPBackendKindRoutingStatsPortClassifier {
		t.Fatalf("expected routing-stats candidate, got %#v", result.Candidate)
	}
	if len(result.Contexts) != 0 || len(result.Issues) != 0 {
		t.Fatalf("expected no ingested contexts or issues without query hook, got %#v", result)
	}
}

func TestXrayUUIDRoutingEvidenceProviderIngestsLiveRoutingContexts(t *testing.T) {
	configPath := writeXrayAPIConfig(t, `{
  "api": {"tag":"api","services":["RoutingService"]},
  "inbounds": [{"tag":"api","listen":"127.0.0.1","port":10085}],
  "routing": {
    "rules": [
      {"type":"field","user":["user-a"],"outboundTag":"proxy-out"}
    ]
  }
}`)

	provider := NewXrayUUIDRoutingEvidenceProvider(stubRuntimeTargetDiscoverer{
		result: Result{
			Targets: []RuntimeTarget{testXrayEvidenceTarget(t, configPath)},
		},
	})
	provider.ProbeEndpoint = func(context.Context, APIEndpoint) error { return nil }
	provider.QueryRoutingContext = func(context.Context, SessionRuntime, RuntimeTarget, APIEndpoint, string) (xrayUUIDRoutingContextQueryResult, error) {
		return xrayUUIDRoutingContextQueryResult{Contexts: []UUIDRoutingContext{
			{
				Network:      "TCP",
				InboundTag:   "socks-in",
				OutboundTag:  "proxy-out",
				Protocol:     "Bittorrent",
				TargetDomain: "example.net",
				SourceIPs:    []string{"::ffff:203.0.113.10", "2001:db8::10"},
				LocalIPs:     []string{"2001:db8::20"},
				TargetIPs:    []string{"2001:db8::30"},
				SourcePort:   43120,
				LocalPort:    8443,
				TargetPort:   443,
				Confidence:   SessionEvidenceConfidenceHigh,
			},
			{
				UUID:         "USER-A",
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
			},
		}}, nil
	}

	result, err := provider.ObserveUUIDRoutingEvidence(context.Background(), testXrayEvidenceRuntime(), "user-a")
	if err != nil {
		t.Fatalf("expected live routing evidence observation to succeed, got %v", err)
	}

	if result.State() != UUIDRoutingEvidenceStateLive {
		t.Fatalf("expected live routing evidence state, got %#v", result)
	}
	if len(result.Contexts) != 1 {
		t.Fatalf("expected one normalized routing context, got %#v", result.Contexts)
	}
	context := result.Contexts[0]
	if context.UUID != "user-a" {
		t.Fatalf("expected normalized uuid, got %#v", context)
	}
	if context.Runtime.HostPID != 1001 {
		t.Fatalf("expected runtime to be backfilled from the requested target, got %#v", context)
	}
	if context.Protocol != "bittorrent" || context.Network != "tcp" {
		t.Fatalf("expected lowercase protocol/network normalization, got %#v", context)
	}
	if len(context.SourceIPs) != 2 || context.SourceIPs[0] != "2001:db8::10" || context.SourceIPs[1] != "203.0.113.10" {
		t.Fatalf("expected ipv6-aware source ip normalization, got %#v", context.SourceIPs)
	}
	if len(context.LocalIPs) != 1 || context.LocalIPs[0] != "2001:db8::20" {
		t.Fatalf("expected ipv6 local ip preservation, got %#v", context.LocalIPs)
	}
	if len(result.Issues) != 0 {
		t.Fatalf("expected no issues for valid routing evidence ingestion, got %#v", result.Issues)
	}
}

func TestXrayUUIDRoutingEvidenceProviderDropsMismatchedUserContexts(t *testing.T) {
	configPath := writeXrayAPIConfig(t, `{
  "api": {"tag":"api","services":["RoutingService"]},
  "inbounds": [{"tag":"api","listen":"127.0.0.1","port":10085}],
  "routing": {
    "rules": [
      {"type":"field","user":["user-a"],"outboundTag":"proxy-out"}
    ]
  }
}`)

	provider := NewXrayUUIDRoutingEvidenceProvider(stubRuntimeTargetDiscoverer{
		result: Result{
			Targets: []RuntimeTarget{testXrayEvidenceTarget(t, configPath)},
		},
	})
	provider.ProbeEndpoint = func(context.Context, APIEndpoint) error { return nil }
	provider.QueryRoutingContext = func(context.Context, SessionRuntime, RuntimeTarget, APIEndpoint, string) (xrayUUIDRoutingContextQueryResult, error) {
		return xrayUUIDRoutingContextQueryResult{Contexts: []UUIDRoutingContext{{
			UUID:        "other-user",
			Runtime:     testXrayEvidenceRuntime(),
			Network:     "tcp",
			OutboundTag: "proxy-out",
			SourcePort:  43120,
			LocalPort:   8443,
			Confidence:  SessionEvidenceConfidenceHigh,
		}}}, nil
	}

	result, err := provider.ObserveUUIDRoutingEvidence(context.Background(), testXrayEvidenceRuntime(), "user-a")
	if err != nil {
		t.Fatalf("expected routing evidence observation to succeed, got %v", err)
	}

	if result.State() != UUIDRoutingEvidenceStatePartial {
		t.Fatalf("expected partial routing evidence state after mismatched user rows, got %#v", result)
	}
	if len(result.Contexts) != 0 {
		t.Fatalf("expected mismatched user routing contexts to be dropped, got %#v", result.Contexts)
	}
	if len(result.Issues) != 1 || !strings.Contains(result.Issues[0].Message, "ignored 1 invalid live uuid routing evidence entries") {
		t.Fatalf("expected invalid-entry issue, got %#v", result.Issues)
	}
}

func TestXrayUUIDRoutingEvidenceProviderReturnsUnavailableWhenRoutingServiceIsMissing(t *testing.T) {
	configPath := writeXrayAPIConfig(t, `{
  "api": {"tag":"api","services":["StatsService"]},
  "inbounds": [{"tag":"api","listen":"127.0.0.1","port":10085}],
  "routing": {
    "rules": [
      {"type":"field","user":["user-a"],"outboundTag":"proxy-out"}
    ]
  }
}`)

	provider := NewXrayUUIDRoutingEvidenceProvider(stubRuntimeTargetDiscoverer{
		result: Result{
			Targets: []RuntimeTarget{testXrayEvidenceTarget(t, configPath)},
		},
	})

	result, err := provider.ObserveUUIDRoutingEvidence(context.Background(), testXrayEvidenceRuntime(), "user-a")
	if err != nil {
		t.Fatalf("expected unavailable routing evidence observation to succeed, got %v", err)
	}

	if result.State() != UUIDRoutingEvidenceStateUnavailable {
		t.Fatalf("expected unavailable routing evidence state, got %#v", result)
	}
	if result.Candidate == nil || result.Candidate.Status != UUIDNonIPBackendStatusUnavailable {
		t.Fatalf("expected unavailable routing candidate, got %#v", result.Candidate)
	}
	if len(result.Contexts) != 0 {
		t.Fatalf("expected no live routing contexts without routing service, got %#v", result.Contexts)
	}
}
