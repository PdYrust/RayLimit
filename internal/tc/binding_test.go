package tc

import (
	"strings"
	"testing"

	"github.com/PdYrust/RayLimit/internal/discovery"
	"github.com/PdYrust/RayLimit/internal/limiter"
	"github.com/PdYrust/RayLimit/internal/policy"
)

func bindingTestSession() discovery.Session {
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

func bindingTestSubject(t *testing.T, kind policy.TargetKind) limiter.Subject {
	t.Helper()

	subject, err := limiter.SubjectFromSession(kind, bindingTestSession())
	if err != nil {
		t.Fatalf("expected subject construction to succeed, got %v", err)
	}

	return subject
}

func TestBindSubjectConnection(t *testing.T) {
	subject := bindingTestSubject(t, policy.TargetKindConnection)

	binding, err := BindSubject(subject)
	if err != nil {
		t.Fatalf("expected connection binding to succeed, got %v", err)
	}

	if binding.Readiness != BindingReadinessPartial {
		t.Fatalf("expected partial connection readiness, got %q", binding.Readiness)
	}
	if binding.Confidence != BindingConfidenceMedium {
		t.Fatalf("expected medium connection confidence, got %q", binding.Confidence)
	}
	if binding.Identity == nil || binding.Identity.Kind != IdentityKindSession || binding.Identity.Value != "conn-1" {
		t.Fatalf("expected session traffic identity, got %#v", binding.Identity)
	}
	if !binding.RequestedSubject.Equal(binding.EffectiveSubject) {
		t.Fatalf("expected direct binding subjects to match, got %#v", binding)
	}
	if !strings.Contains(binding.Reason, "session-scoped") && !strings.Contains(binding.Reason, "class-oriented") {
		t.Fatalf("expected connection binding reason to describe the current class-oriented scope, got %q", binding.Reason)
	}
}

func TestBindSubjectIP(t *testing.T) {
	subject := bindingTestSubject(t, policy.TargetKindIP)

	binding, err := BindSubject(subject)
	if err != nil {
		t.Fatalf("expected ip binding to succeed, got %v", err)
	}

	if binding.Readiness != BindingReadinessReady {
		t.Fatalf("expected ready ip binding, got %q", binding.Readiness)
	}
	if binding.Confidence != BindingConfidenceHigh {
		t.Fatalf("expected high ip confidence, got %q", binding.Confidence)
	}
	if binding.Identity == nil || binding.Identity.Kind != IdentityKindClientIP || binding.Identity.Value != "203.0.113.10" {
		t.Fatalf("expected client ip traffic identity, got %#v", binding.Identity)
	}
}

func TestBindSubjectIPCanonicalizesMappedIPv4Identity(t *testing.T) {
	subject := limiter.Subject{
		Kind:  policy.TargetKindIP,
		Value: "::ffff:203.0.113.10",
		Binding: limiter.RuntimeBinding{
			Runtime: bindingTestSession().Runtime,
		},
	}

	binding, err := BindSubject(subject)
	if err != nil {
		t.Fatalf("expected mapped ipv4 binding to succeed, got %v", err)
	}

	if binding.Identity == nil || binding.Identity.Value != "203.0.113.10" {
		t.Fatalf("expected mapped ipv4 identity to normalize, got %#v", binding.Identity)
	}
}

func TestBindSubjectInboundAndOutbound(t *testing.T) {
	tests := []struct {
		name  string
		kind  policy.TargetKind
		id    IdentityKind
		value string
	}{
		{
			name:  "inbound",
			kind:  policy.TargetKindInbound,
			id:    IdentityKindInbound,
			value: "api-in",
		},
		{
			name:  "outbound",
			kind:  policy.TargetKindOutbound,
			id:    IdentityKindOutbound,
			value: "direct",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			subject := bindingTestSubject(t, test.kind)

			binding, err := BindSubject(subject)
			if err != nil {
				t.Fatalf("expected %s binding to succeed, got %v", test.kind, err)
			}

			if binding.Readiness != BindingReadinessPartial {
				t.Fatalf("expected partial readiness, got %q", binding.Readiness)
			}
			if binding.Identity == nil || binding.Identity.Kind != test.id || binding.Identity.Value != test.value {
				t.Fatalf("expected %#v identity, got %#v", test.id, binding.Identity)
			}
			if test.kind == policy.TargetKindInbound {
				if !strings.Contains(binding.Reason, "trustworthy runtime-aware traffic marking") || !strings.Contains(binding.Reason, "concrete TCP listener") {
					t.Fatalf("expected inbound binding reason to describe the concrete-selector requirement, got %q", binding.Reason)
				}
			} else if !strings.Contains(binding.Reason, "socket mark") || !strings.Contains(binding.Reason, "tc fw") {
				t.Fatalf("expected %s binding reason to describe the socket-mark selector requirement, got %q", test.kind, binding.Reason)
			}
		})
	}
}

func TestBindSubjectUUIDReportsUnavailableBinding(t *testing.T) {
	subject := bindingTestSubject(t, policy.TargetKindUUID)

	binding, err := BindSubject(subject)
	if err != nil {
		t.Fatalf("expected uuid binding to succeed, got %v", err)
	}

	if binding.Readiness != BindingReadinessUnavailable {
		t.Fatalf("expected unavailable binding readiness, got %q", binding.Readiness)
	}
	if binding.Identity != nil {
		t.Fatalf("expected uuid binding to avoid traffic identity, got %#v", binding.Identity)
	}
}

func TestBindUUIDSessionBridge(t *testing.T) {
	session := bindingTestSession()
	requested, err := limiter.SubjectFromSession(policy.TargetKindUUID, session)
	if err != nil {
		t.Fatalf("expected uuid subject construction to succeed, got %v", err)
	}

	binding, err := BindUUIDSessionBridge(requested, session)
	if err != nil {
		t.Fatalf("expected uuid bridge binding to succeed, got %v", err)
	}

	if binding.RequestedSubject.Kind != policy.TargetKindUUID {
		t.Fatalf("expected uuid requested subject, got %#v", binding.RequestedSubject)
	}
	if binding.EffectiveSubject.Kind != policy.TargetKindConnection {
		t.Fatalf("expected bridged connection subject, got %#v", binding.EffectiveSubject)
	}
	if binding.Identity == nil || binding.Identity.Kind != IdentityKindSession || binding.Identity.Value != session.ID {
		t.Fatalf("expected session identity, got %#v", binding.Identity)
	}
	if binding.Readiness != BindingReadinessPartial {
		t.Fatalf("expected partial bridge readiness, got %q", binding.Readiness)
	}
}

func TestBindUUIDSessionBridgeRejectsInsufficientEvidence(t *testing.T) {
	session := bindingTestSession()
	requested, err := limiter.SubjectFromSession(policy.TargetKindUUID, session)
	if err != nil {
		t.Fatalf("expected uuid subject construction to succeed, got %v", err)
	}

	session.Policy.UUID = "other-user"
	if _, err := BindUUIDSessionBridge(requested, session); err == nil {
		t.Fatal("expected mismatched uuid bridge to fail")
	}
}
