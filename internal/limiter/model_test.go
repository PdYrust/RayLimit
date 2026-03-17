package limiter

import (
	"testing"

	"github.com/PdYrust/RayLimit/internal/discovery"
	"github.com/PdYrust/RayLimit/internal/policy"
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

func testDesiredState(t *testing.T, kind policy.TargetKind) DesiredState {
	t.Helper()

	session := testSession()
	target := policy.Target{Kind: kind}
	switch kind {
	case policy.TargetKindConnection:
		target.Connection = &policy.ConnectionRef{
			SessionID: session.ID,
			Runtime: &discovery.SessionRuntime{
				Source:  discovery.DiscoverySourceHostProcess,
				HostPID: 4242,
			},
		}
	case policy.TargetKindUUID:
		target.Value = session.Policy.UUID
	case policy.TargetKindIP:
		target.Value = session.Client.IP
	case policy.TargetKindInbound:
		target.Value = session.Route.InboundTag
	case policy.TargetKindOutbound:
		target.Value = session.Route.OutboundTag
	default:
		t.Fatalf("unsupported target kind %q", kind)
	}

	evaluation, err := (policy.Evaluator{}).Evaluate([]policy.Policy{
		{
			Name:   string(kind) + "-limit",
			Target: target,
			Limits: policy.LimitPolicy{
				Upload:   &policy.RateLimit{BytesPerSecond: 2048},
				Download: &policy.RateLimit{BytesPerSecond: 4096},
			},
		},
	}, session)
	if err != nil {
		t.Fatalf("expected policy evaluation to succeed, got %v", err)
	}

	desired, err := DesiredStateFromEvaluation(session, evaluation)
	if err != nil {
		t.Fatalf("expected desired state construction to succeed, got %v", err)
	}

	return desired
}

func TestDesiredStateFromEvaluationConnectionTarget(t *testing.T) {
	desired := testDesiredState(t, policy.TargetKindConnection)

	if desired.Subject.Kind != policy.TargetKindConnection {
		t.Fatalf("expected connection subject, got %q", desired.Subject.Kind)
	}
	if desired.Subject.Binding.SessionID != "conn-1" {
		t.Fatalf("expected connection binding to keep session id, got %#v", desired.Subject.Binding)
	}
	if desired.Limits.Upload == nil || desired.Limits.Upload.BytesPerSecond != 2048 {
		t.Fatalf("unexpected desired limits: %#v", desired.Limits)
	}
}

func TestSubjectFromSessionBroaderTargetKinds(t *testing.T) {
	cases := []struct {
		name  string
		kind  policy.TargetKind
		value string
	}{
		{name: "uuid", kind: policy.TargetKindUUID, value: "f47ac10b-58cc-4372-a567-0e02b2c3d479"},
		{name: "ip", kind: policy.TargetKindIP, value: "203.0.113.10"},
		{name: "inbound", kind: policy.TargetKindInbound, value: "api-in"},
		{name: "outbound", kind: policy.TargetKindOutbound, value: "direct"},
	}

	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			subject, err := SubjectFromSession(tt.kind, testSession())
			if err != nil {
				t.Fatalf("expected subject derivation to succeed, got %v", err)
			}

			if subject.Kind != tt.kind {
				t.Fatalf("expected subject kind %q, got %q", tt.kind, subject.Kind)
			}
			if subject.Value != tt.value {
				t.Fatalf("expected subject value %q, got %q", tt.value, subject.Value)
			}
			if subject.Binding.SessionID != "" {
				t.Fatalf("expected broader subject to avoid session binding, got %#v", subject.Binding)
			}
		})
	}
}

func TestSubjectFromSessionCanonicalizesIPTargets(t *testing.T) {
	session := testSession()
	session.Client.IP = "::ffff:203.0.113.10"

	subject, err := SubjectFromSession(policy.TargetKindIP, session)
	if err != nil {
		t.Fatalf("expected ip subject derivation to succeed, got %v", err)
	}

	if subject.Value != "203.0.113.10" {
		t.Fatalf("expected mapped ipv4 evidence to normalize, got %#v", subject)
	}
}

func TestIPSubjectsCompareByCanonicalAddressIdentity(t *testing.T) {
	left := Subject{
		Kind:  policy.TargetKindIP,
		Value: "::ffff:203.0.113.10",
		Binding: RuntimeBinding{
			Runtime: testSession().Runtime,
		},
	}
	right := Subject{
		Kind:  policy.TargetKindIP,
		Value: "203.0.113.10",
		Binding: RuntimeBinding{
			Runtime: testSession().Runtime,
		},
	}

	if !left.Equal(right) {
		t.Fatalf("expected canonical ip subject equality, got %#v and %#v", left, right)
	}
}

func TestAppliedStateValidateRejectsIncompleteState(t *testing.T) {
	applied := AppliedState{
		Subject: Subject{
			Kind:  policy.TargetKindIP,
			Value: "203.0.113.10",
			Binding: RuntimeBinding{
				Runtime: discovery.SessionRuntime{
					Source:  discovery.DiscoverySourceHostProcess,
					HostPID: 4242,
				},
			},
		},
		Limits: policy.LimitPolicy{
			Download: &policy.RateLimit{BytesPerSecond: 1024},
		},
	}

	if err := applied.Validate(); err == nil {
		t.Fatal("expected applied state without driver to fail validation")
	}
}

func TestActionValidateIntents(t *testing.T) {
	desired := testDesiredState(t, policy.TargetKindUUID)
	applied := AppliedState{
		Subject: desired.Subject,
		Limits:  desired.Limits,
		Driver:  "tc",
	}

	cases := []struct {
		name   string
		action Action
	}{
		{
			name: "apply",
			action: Action{
				Kind:    ActionApply,
				Subject: desired.Subject,
				Desired: &desired,
			},
		},
		{
			name: "remove",
			action: Action{
				Kind:    ActionRemove,
				Subject: desired.Subject,
			},
		},
		{
			name: "reconcile",
			action: Action{
				Kind:    ActionReconcile,
				Subject: desired.Subject,
				Desired: &desired,
				Applied: []AppliedState{applied},
			},
		},
		{
			name: "inspect",
			action: Action{
				Kind:    ActionInspect,
				Subject: desired.Subject,
			},
		},
	}

	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			if err := tt.action.Validate(); err != nil {
				t.Fatalf("expected %s action to validate, got %v", tt.name, err)
			}
		})
	}
}

func TestActionValidateRejectsMismatchedState(t *testing.T) {
	desired := testDesiredState(t, policy.TargetKindConnection)
	mismatchedSubject := Subject{
		Kind:  policy.TargetKindIP,
		Value: "203.0.113.10",
		Binding: RuntimeBinding{
			Runtime: discovery.SessionRuntime{
				Source:  discovery.DiscoverySourceHostProcess,
				HostPID: 4242,
			},
		},
	}

	action := Action{
		Kind:    ActionApply,
		Subject: mismatchedSubject,
		Desired: &desired,
	}

	if err := action.Validate(); err == nil {
		t.Fatal("expected mismatched action subject to fail validation")
	}
}

func TestAppliedStateMatchesDesired(t *testing.T) {
	desired := testDesiredState(t, policy.TargetKindOutbound)
	applied := AppliedState{
		Subject: desired.Subject,
		Limits:  desired.Limits,
		Driver:  "tc",
	}

	if !applied.MatchesDesired(desired) {
		t.Fatalf("expected applied state to match desired state, got %#v and %#v", applied, desired)
	}
}
