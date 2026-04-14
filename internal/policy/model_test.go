package policy

import (
	"strings"
	"testing"

	"github.com/PdYrust/RayLimit/internal/discovery"
)

func testSession() discovery.Session {
	return discovery.Session{
		ID: "conn-1",
		Runtime: discovery.SessionRuntime{
			Source:  discovery.DiscoverySourceHostProcess,
			HostPID: 4242,
			Name:    "edge-a",
		},
		Client: discovery.SessionClient{
			IP: "203.0.113.10",
		},
		Route: discovery.SessionRoute{
			InboundTag:  "api-in",
			OutboundTag: "direct",
		},
	}
}

func TestTargetKindValid(t *testing.T) {
	for _, kind := range []TargetKind{
		TargetKindIP,
		TargetKindInbound,
		TargetKindOutbound,
	} {
		if !kind.Valid() {
			t.Fatalf("expected target kind %q to be valid", kind)
		}
	}
}

func TestTargetKindPrecedence(t *testing.T) {
	if TargetKindIP.Precedence() <= TargetKindInbound.Precedence() {
		t.Fatal("expected ip precedence to be higher than inbound")
	}
	if TargetKindInbound.Precedence() <= TargetKindOutbound.Precedence() {
		t.Fatal("expected inbound precedence to be higher than outbound")
	}
}

func TestDescribeTargetKindPrecedence(t *testing.T) {
	if DescribeTargetKindPrecedence() != "ip > inbound > outbound" {
		t.Fatalf("unexpected precedence description %q", DescribeTargetKindPrecedence())
	}
}

func TestPolicyValidateSupportedTargets(t *testing.T) {
	policies := []Policy{
		{
			Name: "ip-limit",
			Target: Target{
				Kind:  TargetKindIP,
				Value: "203.0.113.10",
			},
			Limits: LimitPolicy{
				Upload: &RateLimit{BytesPerSecond: 1024},
			},
		},
		{
			Name: "ip-all-limit",
			Target: Target{
				Kind: TargetKindIP,
				All:  true,
			},
			Limits: LimitPolicy{
				Download: &RateLimit{BytesPerSecond: 1536},
			},
		},
		{
			Name: "inbound-limit",
			Target: Target{
				Kind:  TargetKindInbound,
				Value: "api-in",
			},
			Limits: LimitPolicy{
				Download: &RateLimit{BytesPerSecond: 2048},
			},
		},
		{
			Name: "outbound-limit",
			Target: Target{
				Kind:  TargetKindOutbound,
				Value: "direct",
			},
			Limits: LimitPolicy{
				Download: &RateLimit{BytesPerSecond: 4096},
			},
		},
	}

	for _, policy := range policies {
		if err := policy.Validate(); err != nil {
			t.Fatalf("expected policy %+v to validate, got %v", policy, err)
		}
	}
}

func TestPolicyValidateRejectsIncompleteDefinitions(t *testing.T) {
	policies := []Policy{
		{
			Target: Target{
				Kind: TargetKindIP,
			},
			Limits: LimitPolicy{
				Upload: &RateLimit{BytesPerSecond: 1024},
			},
		},
		{
			Target: Target{
				Kind:  TargetKindIP,
				Value: "not-an-ip",
			},
			Limits: LimitPolicy{
				Upload: &RateLimit{BytesPerSecond: 1024},
			},
		},
		{
			Target: Target{
				Kind:  TargetKindIP,
				All:   true,
				Value: "203.0.113.10",
			},
			Limits: LimitPolicy{
				Upload: &RateLimit{BytesPerSecond: 1024},
			},
		},
		{
			Target: Target{
				Kind: TargetKindInbound,
			},
			Limits: LimitPolicy{
				Download: &RateLimit{BytesPerSecond: 1024},
			},
		},
	}

	for _, policy := range policies {
		if err := policy.Validate(); err == nil {
			t.Fatalf("expected invalid policy to fail validation: %+v", policy)
		}
	}
}

func TestTargetMatchesSessionAcrossSupportedKinds(t *testing.T) {
	session := testSession()

	targets := []Target{
		{Kind: TargetKindIP, All: true},
		{Kind: TargetKindIP, Value: "203.0.113.10"},
		{Kind: TargetKindInbound, Value: "api-in"},
		{Kind: TargetKindOutbound, Value: "direct"},
	}

	for _, target := range targets {
		if !target.MatchesSession(session) {
			t.Fatalf("expected target %+v to match session %+v", target, session)
		}
	}
}

func TestResolveReturnsHighestPrecedenceMatch(t *testing.T) {
	selection, err := Resolve([]Policy{
		{
			Name: "outbound-limit",
			Target: Target{
				Kind:  TargetKindOutbound,
				Value: "direct",
			},
			Limits: LimitPolicy{
				Download: &RateLimit{BytesPerSecond: 1024},
			},
		},
		{
			Name: "ip-limit",
			Target: Target{
				Kind:  TargetKindIP,
				Value: "203.0.113.10",
			},
			Limits: LimitPolicy{
				Download: &RateLimit{BytesPerSecond: 2048},
			},
		},
		{
			Name: "inbound-limit",
			Target: Target{
				Kind:  TargetKindInbound,
				Value: "api-in",
			},
			Limits: LimitPolicy{
				Download: &RateLimit{BytesPerSecond: 4096},
			},
		},
	}, testSession())
	if err != nil {
		t.Fatalf("expected policies to resolve, got %v", err)
	}

	if selection.Kind != TargetKindIP {
		t.Fatalf("expected ip precedence to win, got %q", selection.Kind)
	}
	if selection.Excluded() {
		t.Fatalf("expected limiting selection, got %#v", selection)
	}
	if len(selection.Limits) != 1 || selection.Limits[0].Name != "ip-limit" {
		t.Fatalf("unexpected selected policies: %#v", selection)
	}
}

func TestResolveExcludeBeatsLimitsAtSamePrecedence(t *testing.T) {
	selection, err := Resolve([]Policy{
		{
			Name: "ip-limit",
			Target: Target{
				Kind:  TargetKindIP,
				Value: "203.0.113.10",
			},
			Limits: LimitPolicy{
				Upload: &RateLimit{BytesPerSecond: 1024},
			},
		},
		{
			Name:   "ip-exclude",
			Effect: EffectExclude,
			Target: Target{
				Kind:  TargetKindIP,
				Value: "203.0.113.10",
			},
		},
	}, testSession())
	if err != nil {
		t.Fatalf("expected policies to resolve, got %v", err)
	}

	if selection.Kind != TargetKindIP {
		t.Fatalf("expected ip precedence, got %q", selection.Kind)
	}
	if !selection.Excluded() {
		t.Fatalf("expected exclusion to win, got %#v", selection)
	}
	if len(selection.Excludes) != 1 || selection.Excludes[0].Name != "ip-exclude" {
		t.Fatalf("unexpected exclude selection: %#v", selection)
	}
}

func TestResolveSpecificIPBeatsMatchingIPBaseline(t *testing.T) {
	selection, err := Resolve([]Policy{
		{
			Name: "ip-all-limit",
			Target: Target{
				Kind: TargetKindIP,
				All:  true,
			},
			Limits: LimitPolicy{
				Upload: &RateLimit{BytesPerSecond: 4096},
			},
		},
		{
			Name: "ip-override",
			Target: Target{
				Kind:  TargetKindIP,
				Value: "203.0.113.10",
			},
			Limits: LimitPolicy{
				Upload: &RateLimit{BytesPerSecond: 2048},
			},
		},
	}, testSession())
	if err != nil {
		t.Fatalf("expected policies to resolve, got %v", err)
	}

	if selection.Kind != TargetKindIP || selection.Target.All {
		t.Fatalf("expected specific ip selection to beat the baseline, got %#v", selection)
	}
	if len(selection.Limits) != 1 || selection.Limits[0].Name != "ip-override" {
		t.Fatalf("unexpected winning ip override selection: %#v", selection)
	}
}

func TestResolveSpecificIPExcludeBeatsMatchingIPBaselineLimit(t *testing.T) {
	selection, err := Resolve([]Policy{
		{
			Name: "ip-all-limit",
			Target: Target{
				Kind: TargetKindIP,
				All:  true,
			},
			Limits: LimitPolicy{
				Upload: &RateLimit{BytesPerSecond: 4096},
			},
		},
		{
			Name:   "ip-unlimited",
			Effect: EffectExclude,
			Target: Target{
				Kind:  TargetKindIP,
				Value: "203.0.113.10",
			},
		},
	}, testSession())
	if err != nil {
		t.Fatalf("expected policies to resolve, got %v", err)
	}

	if selection.Kind != TargetKindIP || selection.Target.All || !selection.Excluded() {
		t.Fatalf("expected specific ip exclusion to beat the baseline, got %#v", selection)
	}
	if len(selection.Excludes) != 1 || selection.Excludes[0].Name != "ip-unlimited" {
		t.Fatalf("unexpected winning exclusion selection: %#v", selection)
	}
}

func TestResolveRejectsInvalidPolicyDefinitions(t *testing.T) {
	_, err := Resolve([]Policy{
		{
			Name: "outbound-limit",
			Target: Target{
				Kind:  TargetKindOutbound,
				Value: "direct",
			},
			Limits: LimitPolicy{
				Download: &RateLimit{BytesPerSecond: 1024},
			},
		},
		{
			Target: Target{
				Kind: TargetKindInbound,
			},
			Limits: LimitPolicy{
				Upload: &RateLimit{BytesPerSecond: 1024},
			},
		},
	}, testSession())
	if err == nil {
		t.Fatal("expected invalid policy set to fail resolution")
	}
	if !strings.Contains(err.Error(), "invalid policy at index 1") {
		t.Fatalf("unexpected error: %v", err)
	}
}
