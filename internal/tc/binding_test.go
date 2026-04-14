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
