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
		Policy: discovery.SessionPolicyIdentity{
			UUID: "f47ac10b-58cc-4372-a567-0e02b2c3d479",
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

func testConnectionRef() *ConnectionRef {
	return &ConnectionRef{
		SessionID: "conn-1",
		Runtime: &discovery.SessionRuntime{
			Source:  discovery.DiscoverySourceHostProcess,
			HostPID: 4242,
		},
	}
}

func TestTargetKindValid(t *testing.T) {
	for _, kind := range []TargetKind{
		TargetKindUUID,
		TargetKindIP,
		TargetKindInbound,
		TargetKindOutbound,
		TargetKindConnection,
	} {
		if !kind.Valid() {
			t.Fatalf("expected target kind %q to be valid", kind)
		}
	}
}

func TestTargetKindPrecedence(t *testing.T) {
	if TargetKindConnection.Precedence() <= TargetKindUUID.Precedence() {
		t.Fatal("expected connection precedence to be higher than uuid")
	}
	if TargetKindUUID.Precedence() <= TargetKindIP.Precedence() {
		t.Fatal("expected uuid precedence to be higher than ip")
	}
	if TargetKindIP.Precedence() <= TargetKindInbound.Precedence() {
		t.Fatal("expected ip precedence to be higher than inbound")
	}
	if TargetKindInbound.Precedence() <= TargetKindOutbound.Precedence() {
		t.Fatal("expected inbound precedence to be higher than outbound")
	}
}

func TestDescribeTargetKindPrecedence(t *testing.T) {
	if DescribeTargetKindPrecedence() != "connection > uuid > ip > inbound > outbound" {
		t.Fatalf("unexpected precedence description %q", DescribeTargetKindPrecedence())
	}
}

func TestPolicyValidateUUIDPolicy(t *testing.T) {
	policy := Policy{
		Name: "uuid-limit",
		Target: Target{
			Kind:  TargetKindUUID,
			Value: "f47ac10b-58cc-4372-a567-0e02b2c3d479",
		},
		Limits: LimitPolicy{
			Upload: &RateLimit{BytesPerSecond: 1024},
		},
	}

	if err := policy.Validate(); err != nil {
		t.Fatalf("expected uuid policy to validate, got %v", err)
	}
}

func TestPolicyValidateIPInboundAndOutboundTargets(t *testing.T) {
	policies := []Policy{
		{
			Target: Target{
				Kind:  TargetKindIP,
				Value: "203.0.113.10",
			},
			Limits: LimitPolicy{
				Download: &RateLimit{BytesPerSecond: 4096},
			},
		},
		{
			Target: Target{
				Kind:  TargetKindInbound,
				Value: "api-in",
			},
			Limits: LimitPolicy{
				Upload:   &RateLimit{BytesPerSecond: 2048},
				Download: &RateLimit{BytesPerSecond: 2048},
			},
		},
		{
			Target: Target{
				Kind:  TargetKindOutbound,
				Value: "direct",
			},
			Limits: LimitPolicy{
				Download: &RateLimit{BytesPerSecond: 8192},
			},
		},
	}

	for _, policy := range policies {
		if err := policy.Validate(); err != nil {
			t.Fatalf("expected policy %+v to validate, got %v", policy, err)
		}
	}
}

func TestPolicyValidateConnectionTargetedPolicy(t *testing.T) {
	policy := Policy{
		Target: Target{
			Kind:       TargetKindConnection,
			Connection: testConnectionRef(),
		},
		Limits: LimitPolicy{
			Upload:   &RateLimit{BytesPerSecond: 1024},
			Download: &RateLimit{BytesPerSecond: 2048},
		},
	}

	if err := policy.Validate(); err != nil {
		t.Fatalf("expected connection policy to validate, got %v", err)
	}

	session := testSession()

	if !policy.Target.MatchesSession(session) {
		t.Fatalf("expected connection target to match session, got %#v", session)
	}
}

func TestPolicyValidateRejectsIncompleteDefinitions(t *testing.T) {
	policies := []Policy{
		{
			Target: Target{
				Kind: TargetKindUUID,
			},
			Limits: LimitPolicy{
				Upload: &RateLimit{BytesPerSecond: 1024},
			},
		},
		{
			Target: Target{
				Kind:  TargetKindUUID,
				Value: "f47ac10b-58cc-4372-a567-0e02b2c3d479",
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
				Kind: TargetKindConnection,
				Connection: &ConnectionRef{
					SessionID: "conn-1",
				},
			},
			Limits: LimitPolicy{
				Download: &RateLimit{BytesPerSecond: 1024},
			},
		},
		{
			Name: "   ",
			Target: Target{
				Kind:  TargetKindOutbound,
				Value: "direct",
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

func TestLimitPolicyValidateRejectsInvalidRateLimits(t *testing.T) {
	limits := LimitPolicy{
		Upload: &RateLimit{BytesPerSecond: 0},
	}

	err := limits.Validate()
	if err == nil {
		t.Fatal("expected invalid rate limit to fail validation")
	}

	if !strings.Contains(err.Error(), "bytes_per_second must be greater than zero") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestPolicyValidateRejectsExcludePolicyWithLimits(t *testing.T) {
	policy := Policy{
		Effect: EffectExclude,
		Target: Target{
			Kind:  TargetKindInbound,
			Value: "api-in",
		},
		Limits: LimitPolicy{
			Upload: &RateLimit{BytesPerSecond: 1024},
		},
	}

	err := policy.Validate()
	if err == nil {
		t.Fatal("expected exclude policy with limits to fail validation")
	}

	if !strings.Contains(err.Error(), "exclude policy cannot define limits") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestTargetMatchesSessionAcrossSupportedIdentityKinds(t *testing.T) {
	session := testSession()

	targets := []Target{
		{Kind: TargetKindUUID, Value: "F47AC10B-58CC-4372-A567-0E02B2C3D479"},
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

func TestIPTargetMatchesSessionAcrossCanonicalForms(t *testing.T) {
	session := testSession()
	session.Client.IP = "2001:db8::10"

	targets := []Target{
		{Kind: TargetKindIP, Value: "2001:0db8::0010"},
		{Kind: TargetKindIP, Value: "::ffff:203.0.113.10"},
	}

	if !targets[0].MatchesSession(session) {
		t.Fatalf("expected canonical ipv6 target to match session %+v", session)
	}

	session.Client.IP = "203.0.113.10"
	if !targets[1].MatchesSession(session) {
		t.Fatalf("expected mapped ipv4 target to match session %+v", session)
	}
}

func TestResolveReturnsHighestPrecedenceMatch(t *testing.T) {
	session := testSession()
	policies := []Policy{
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
			Name: "ip-limit",
			Target: Target{
				Kind:  TargetKindIP,
				Value: "203.0.113.10",
			},
			Limits: LimitPolicy{
				Download: &RateLimit{BytesPerSecond: 4096},
			},
		},
		{
			Name: "uuid-limit",
			Target: Target{
				Kind:  TargetKindUUID,
				Value: "f47ac10b-58cc-4372-a567-0e02b2c3d479",
			},
			Limits: LimitPolicy{
				Download: &RateLimit{BytesPerSecond: 8192},
			},
		},
		{
			Name: "connection-limit",
			Target: Target{
				Kind:       TargetKindConnection,
				Connection: testConnectionRef(),
			},
			Limits: LimitPolicy{
				Download: &RateLimit{BytesPerSecond: 16384},
			},
		},
	}

	selection, err := Resolve(policies, session)
	if err != nil {
		t.Fatalf("expected policies to resolve, got %v", err)
	}

	if selection.Kind != TargetKindConnection {
		t.Fatalf("expected connection precedence to win, got %q", selection.Kind)
	}
	if selection.Excluded() {
		t.Fatalf("expected connection selection to remain limiting, got %#v", selection)
	}
	if len(selection.Limits) != 1 || selection.Limits[0].Name != "connection-limit" {
		t.Fatalf("unexpected selected policies: %#v", selection)
	}
}

func TestResolveExcludeBeatsLimitsAtSamePrecedence(t *testing.T) {
	session := testSession()
	policies := []Policy{
		{
			Name:   "uuid-limit",
			Effect: EffectLimit,
			Target: Target{
				Kind:  TargetKindUUID,
				Value: "f47ac10b-58cc-4372-a567-0e02b2c3d479",
			},
			Limits: LimitPolicy{
				Upload: &RateLimit{BytesPerSecond: 1024},
			},
		},
		{
			Name:   "uuid-exclude",
			Effect: EffectExclude,
			Target: Target{
				Kind:  TargetKindUUID,
				Value: "f47ac10b-58cc-4372-a567-0e02b2c3d479",
			},
		},
	}

	selection, err := Resolve(policies, session)
	if err != nil {
		t.Fatalf("expected policies to resolve, got %v", err)
	}

	if selection.Kind != TargetKindUUID {
		t.Fatalf("expected uuid precedence, got %q", selection.Kind)
	}
	if !selection.Excluded() {
		t.Fatalf("expected exclude to short-circuit limits, got %#v", selection)
	}
	if len(selection.Limits) != 0 {
		t.Fatalf("expected excludes to clear limits, got %#v", selection)
	}
	if len(selection.Excludes) != 1 || selection.Excludes[0].Name != "uuid-exclude" {
		t.Fatalf("unexpected exclude selection: %#v", selection)
	}
}

func TestResolveHigherPrecedenceLimitBeatsBroaderExclude(t *testing.T) {
	session := testSession()
	policies := []Policy{
		{
			Name:   "uuid-exclude",
			Effect: EffectExclude,
			Target: Target{
				Kind:  TargetKindUUID,
				Value: "f47ac10b-58cc-4372-a567-0e02b2c3d479",
			},
		},
		{
			Name: "connection-limit",
			Target: Target{
				Kind:       TargetKindConnection,
				Connection: testConnectionRef(),
			},
			Limits: LimitPolicy{
				Upload: &RateLimit{BytesPerSecond: 2048},
			},
		},
	}

	selection, err := Resolve(policies, session)
	if err != nil {
		t.Fatalf("expected policies to resolve, got %v", err)
	}

	if selection.Kind != TargetKindConnection {
		t.Fatalf("expected connection precedence, got %q", selection.Kind)
	}
	if selection.Excluded() {
		t.Fatalf("expected broader exclude to be ignored by higher-precedence match, got %#v", selection)
	}
	if len(selection.Limits) != 1 || selection.Limits[0].Name != "connection-limit" {
		t.Fatalf("unexpected limit selection: %#v", selection)
	}
}

func TestResolveRejectsInvalidPolicyDefinitions(t *testing.T) {
	session := testSession()
	policies := []Policy{
		{
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
				Kind: TargetKindConnection,
				Connection: &ConnectionRef{
					SessionID: "conn-1",
				},
			},
			Limits: LimitPolicy{
				Upload: &RateLimit{BytesPerSecond: 1024},
			},
		},
	}

	_, err := Resolve(policies, session)
	if err == nil {
		t.Fatal("expected invalid policy set to fail resolution")
	}

	if !strings.Contains(err.Error(), "invalid policy at index 1") {
		t.Fatalf("unexpected error: %v", err)
	}
}
