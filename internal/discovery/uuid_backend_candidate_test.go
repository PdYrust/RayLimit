package discovery

import (
	"context"
	"strings"
	"testing"
)

func TestUUIDNonIPBackendCandidateDeriverReportsRoutingStatsCandidate(t *testing.T) {
	configPath := writeXrayAPIConfig(t, `{
  "api": {"tag":"api","services":["StatsService","RoutingService"]},
  "routing": {
    "rules": [
      {"type":"field","user":["user-a"],"outboundTag":"proxy-out"}
    ]
  }
}`)

	result, err := NewUUIDNonIPBackendCandidateDeriver().Derive(context.Background(), testXrayEvidenceTarget(t, configPath), "user-a")
	if err != nil {
		t.Fatalf("expected candidate derivation to succeed, got %v", err)
	}

	if result.Status != UUIDNonIPBackendStatusCandidate || result.Kind != UUIDNonIPBackendKindRoutingStatsPortClassifier {
		t.Fatalf("expected routing-stats candidate, got %#v", result)
	}
	if len(result.OutboundTags) != 1 || result.OutboundTags[0] != "proxy-out" {
		t.Fatalf("expected matching outbound tag in candidate, got %#v", result)
	}
	if !strings.Contains(result.Reason, "RoutingService") || !strings.Contains(result.Reason, "remote-socket classifier") {
		t.Fatalf("expected routing-stats reason, got %#v", result)
	}
}

func TestUUIDNonIPBackendCandidateDeriverRequiresRoutingService(t *testing.T) {
	configPath := writeXrayAPIConfig(t, `{
  "api": {"tag":"api","services":["StatsService"]},
  "routing": {
    "rules": [
      {"type":"field","user":["user-a"],"outboundTag":"proxy-out"}
    ]
  }
}`)

	result, err := NewUUIDNonIPBackendCandidateDeriver().Derive(context.Background(), testXrayEvidenceTarget(t, configPath), "user-a")
	if err != nil {
		t.Fatalf("expected candidate derivation to succeed, got %v", err)
	}

	if result.Status != UUIDNonIPBackendStatusUnavailable || result.Kind != "" {
		t.Fatalf("expected unavailable result without routing service, got %#v", result)
	}
	if !strings.Contains(result.Reason, "RoutingService is not enabled") {
		t.Fatalf("expected routing-service blocker reason, got %#v", result)
	}
}

func TestUUIDNonIPBackendCandidateDeriverRequiresExactUserRouting(t *testing.T) {
	configPath := writeXrayAPIConfig(t, `{
  "api": {"tag":"api","services":["RoutingService"]},
  "routing": {
    "rules": [
      {"type":"field","user":["regexp:user-.*"],"outboundTag":"proxy-out"}
    ]
  }
}`)

	result, err := NewUUIDNonIPBackendCandidateDeriver().Derive(context.Background(), testXrayEvidenceTarget(t, configPath), "user-a")
	if err != nil {
		t.Fatalf("expected candidate derivation to succeed, got %v", err)
	}

	if result.Status != UUIDNonIPBackendStatusUnavailable {
		t.Fatalf("expected unavailable result without exact user rule, got %#v", result)
	}
	if !strings.Contains(result.Reason, "no exact readable Xray user-routing rule matched UUID") {
		t.Fatalf("expected exact-user blocker reason, got %#v", result)
	}
}
