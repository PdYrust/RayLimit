package cli

import (
	"strings"
	"testing"

	"github.com/PdYrust/RayLimit/internal/discovery"
	"github.com/PdYrust/RayLimit/internal/policy"
)

func TestLimitTargetSelectionValidateAcceptsSupportedKinds(t *testing.T) {
	tests := []struct {
		name      string
		selection limitTargetSelection
		wantKind  policy.TargetKind
		wantValue string
	}{
		{
			name:      "connection",
			selection: limitTargetSelection{Connection: "conn-1"},
			wantKind:  policy.TargetKindConnection,
			wantValue: "conn-1",
		},
		{
			name:      "uuid",
			selection: limitTargetSelection{UUID: "user-a"},
			wantKind:  policy.TargetKindUUID,
			wantValue: "user-a",
		},
		{
			name:      "ip",
			selection: limitTargetSelection{IP: "203.0.113.10"},
			wantKind:  policy.TargetKindIP,
			wantValue: "203.0.113.10",
		},
		{
			name:      "ipv6",
			selection: limitTargetSelection{IP: "2001:0db8::0010"},
			wantKind:  policy.TargetKindIP,
			wantValue: "2001:db8::10",
		},
		{
			name:      "mapped-ipv4",
			selection: limitTargetSelection{IP: "::ffff:203.0.113.10"},
			wantKind:  policy.TargetKindIP,
			wantValue: "203.0.113.10",
		},
		{
			name:      "inbound",
			selection: limitTargetSelection{Inbound: "api-in"},
			wantKind:  policy.TargetKindInbound,
			wantValue: "api-in",
		},
		{
			name:      "outbound",
			selection: limitTargetSelection{Outbound: "proxy-out"},
			wantKind:  policy.TargetKindOutbound,
			wantValue: "proxy-out",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := tt.selection.Validate(); err != nil {
				t.Fatalf("expected selection to validate, got %v", err)
			}
			if tt.selection.Kind() != tt.wantKind {
				t.Fatalf("expected kind %q, got %q", tt.wantKind, tt.selection.Kind())
			}
			if tt.selection.Value() != tt.wantValue {
				t.Fatalf("expected value %q, got %q", tt.wantValue, tt.selection.Value())
			}
		})
	}
}

func TestLimitTargetSelectionValidateRejectsMultipleTargets(t *testing.T) {
	selection := limitTargetSelection{
		Connection: "conn-1",
		UUID:       "user-a",
	}

	err := selection.Validate()
	if err == nil {
		t.Fatal("expected selection validation to fail")
	}
	if !strings.Contains(err.Error(), "select exactly one limit target") {
		t.Fatalf("unexpected validation error: %v", err)
	}
}

func TestLimitTargetSelectionValidateRejectsMissingTarget(t *testing.T) {
	selection := limitTargetSelection{}

	err := selection.Validate()
	if err == nil {
		t.Fatal("expected selection validation to fail")
	}
	if !strings.Contains(err.Error(), "select one limit target") {
		t.Fatalf("unexpected validation error: %v", err)
	}
}

func TestLimitTargetSelectionValidateRejectsInvalidIP(t *testing.T) {
	selection := limitTargetSelection{IP: "not-an-ip"}

	err := selection.Validate()
	if err == nil {
		t.Fatal("expected selection validation to fail")
	}
	if !strings.Contains(err.Error(), `invalid IP address "not-an-ip" for --ip`) {
		t.Fatalf("unexpected validation error: %v", err)
	}
}

func TestLimitTargetSelectionApplyPopulatesSessionIdentity(t *testing.T) {
	tests := []struct {
		name      string
		selection limitTargetSelection
		verify    func(t *testing.T, session discovery.Session)
	}{
		{
			name:      "connection",
			selection: limitTargetSelection{Connection: "conn-1"},
			verify: func(t *testing.T, session discovery.Session) {
				if session.ID != "conn-1" {
					t.Fatalf("expected session id to be populated, got %#v", session)
				}
			},
		},
		{
			name:      "uuid",
			selection: limitTargetSelection{UUID: "user-a"},
			verify: func(t *testing.T, session discovery.Session) {
				if session.Policy.UUID != "user-a" {
					t.Fatalf("expected policy uuid to be populated, got %#v", session)
				}
			},
		},
		{
			name:      "ip",
			selection: limitTargetSelection{IP: "::ffff:203.0.113.10"},
			verify: func(t *testing.T, session discovery.Session) {
				if session.Client.IP != "203.0.113.10" {
					t.Fatalf("expected client ip to be populated, got %#v", session)
				}
			},
		},
		{
			name:      "inbound",
			selection: limitTargetSelection{Inbound: "api-in"},
			verify: func(t *testing.T, session discovery.Session) {
				if session.Route.InboundTag != "api-in" {
					t.Fatalf("expected inbound tag to be populated, got %#v", session)
				}
			},
		},
		{
			name:      "outbound",
			selection: limitTargetSelection{Outbound: "proxy-out"},
			verify: func(t *testing.T, session discovery.Session) {
				if session.Route.OutboundTag != "proxy-out" {
					t.Fatalf("expected outbound tag to be populated, got %#v", session)
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			session := discovery.Session{}
			tt.selection.apply(&session)
			tt.verify(t, session)
		})
	}
}

func TestLimitTargetSelectionPolicyTargetBuildsGenericTarget(t *testing.T) {
	runtime := discovery.SessionRuntime{
		Source:  discovery.DiscoverySourceHostProcess,
		HostPID: 1001,
	}

	target, err := (limitTargetSelection{UUID: "user-a"}).policyTarget(runtime)
	if err != nil {
		t.Fatalf("expected policy target construction to succeed, got %v", err)
	}

	if target.Kind != policy.TargetKindUUID {
		t.Fatalf("expected uuid target kind, got %#v", target)
	}
	if target.Value != "user-a" {
		t.Fatalf("expected uuid target value, got %#v", target)
	}
	if target.Connection != nil {
		t.Fatalf("expected generic target to omit connection details, got %#v", target)
	}
}
