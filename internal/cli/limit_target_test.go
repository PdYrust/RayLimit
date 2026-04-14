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
			name:      "ip",
			selection: limitTargetSelection{IP: "203.0.113.10"},
			wantKind:  policy.TargetKindIP,
			wantValue: "203.0.113.10",
		},
		{
			name:      "mapped-ipv4",
			selection: limitTargetSelection{IP: "::ffff:203.0.113.10"},
			wantKind:  policy.TargetKindIP,
			wantValue: "203.0.113.10",
		},
		{
			name:      "ip-all",
			selection: limitTargetSelection{IP: "all"},
			wantKind:  policy.TargetKindIP,
			wantValue: "all",
		},
		{
			name:      "ip-all-uppercase",
			selection: limitTargetSelection{IP: "ALL"},
			wantKind:  policy.TargetKindIP,
			wantValue: "all",
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

func TestLimitTargetSelectionValidateRejectsMissingOrMultipleTargets(t *testing.T) {
	cases := []struct {
		name      string
		selection limitTargetSelection
		want      string
	}{
		{
			name:      "missing",
			selection: limitTargetSelection{},
			want:      "select one limit target",
		},
		{
			name: "multiple",
			selection: limitTargetSelection{
				IP:      "203.0.113.10",
				Inbound: "api-in",
			},
			want: "select exactly one limit target",
		},
	}

	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.selection.Validate()
			if err == nil {
				t.Fatal("expected selection validation to fail")
			}
			if !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("unexpected validation error: %v", err)
			}
		})
	}
}

func TestLimitTargetSelectionApplyPopulatesSessionIdentity(t *testing.T) {
	tests := []struct {
		name      string
		selection limitTargetSelection
		verify    func(t *testing.T, session discovery.Session)
	}{
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
			name:      "ip-all",
			selection: limitTargetSelection{IP: "all"},
			verify: func(t *testing.T, session discovery.Session) {
				if session.Client.IP != "" {
					t.Fatalf("expected ip all to leave the synthetic session client ip unset, got %#v", session)
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

func TestLimitTargetSelectionPolicyTargetBuildsExpectedTarget(t *testing.T) {
	ipTarget, err := (limitTargetSelection{IP: "203.0.113.10"}).policyTarget()
	if err != nil {
		t.Fatalf("expected ip policy target construction to succeed, got %v", err)
	}
	if ipTarget.Kind != policy.TargetKindIP || ipTarget.Value != "203.0.113.10" {
		t.Fatalf("unexpected ip target: %#v", ipTarget)
	}

	allTarget, err := (limitTargetSelection{IP: "all"}).policyTarget()
	if err != nil {
		t.Fatalf("expected ip baseline target construction to succeed, got %v", err)
	}
	if allTarget.Kind != policy.TargetKindIP || !allTarget.All || allTarget.Value != "" {
		t.Fatalf("unexpected ip all target: %#v", allTarget)
	}
}
