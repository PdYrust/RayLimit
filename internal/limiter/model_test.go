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

func TestDesiredStateFromEvaluationIPTarget(t *testing.T) {
	desired := testDesiredState(t, policy.TargetKindIP)

	if desired.Mode != DesiredModeLimit {
		t.Fatalf("expected limit desired mode, got %#v", desired)
	}
	if desired.Subject.Kind != policy.TargetKindIP || desired.Subject.Value != "203.0.113.10" {
		t.Fatalf("unexpected ip subject, got %#v", desired.Subject)
	}
	if desired.Subject.IPAggregation != "" {
		t.Fatalf("expected specific ip subject to keep aggregation empty, got %#v", desired.Subject)
	}
	if desired.Limits.Upload == nil || desired.Limits.Upload.BytesPerSecond != 2048 {
		t.Fatalf("unexpected desired limits: %#v", desired.Limits)
	}
}

func TestDesiredStateFromEvaluationIPAllBaseline(t *testing.T) {
	session := testSession()
	evaluation, err := (policy.Evaluator{}).Evaluate([]policy.Policy{
		{
			Name: "ip-all-limit",
			Target: policy.Target{
				Kind: policy.TargetKindIP,
				All:  true,
			},
			Limits: policy.LimitPolicy{
				Upload: &policy.RateLimit{BytesPerSecond: 2048},
			},
		},
	}, session)
	if err != nil {
		t.Fatalf("expected policy evaluation to succeed, got %v", err)
	}

	desired, err := DesiredStateFromEvaluation(session, evaluation)
	if err != nil {
		t.Fatalf("expected baseline desired state construction to succeed, got %v", err)
	}

	if desired.Mode != DesiredModeLimit {
		t.Fatalf("expected limit desired mode, got %#v", desired)
	}
	if !desired.Subject.All || desired.Subject.Value != "" {
		t.Fatalf("expected baseline ip subject, got %#v", desired.Subject)
	}
	if desired.Subject.NormalizedIPAggregation() != policy.IPAggregationModeShared {
		t.Fatalf("expected baseline ip subject to default to shared aggregation, got %#v", desired.Subject)
	}
	if evaluation.Selection.Target.NormalizedIPAggregation() != policy.IPAggregationModeShared {
		t.Fatalf("expected baseline evaluation target to default to shared aggregation, got %#v", evaluation.Selection.Target)
	}
	if desired.Limits.Upload == nil || desired.Limits.Upload.BytesPerSecond != 2048 {
		t.Fatalf("unexpected baseline desired limits: %#v", desired.Limits)
	}
}

func TestSubjectFromSessionSupportedTargetKinds(t *testing.T) {
	cases := []struct {
		name  string
		kind  policy.TargetKind
		value string
	}{
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

			if subject.Kind != tt.kind || subject.Value != tt.value {
				t.Fatalf("unexpected subject: %#v", subject)
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

func TestIPSubjectsRemainDistinctAcrossRuntimes(t *testing.T) {
	left := Subject{
		Kind:  policy.TargetKindIP,
		Value: "203.0.113.10",
		Binding: RuntimeBinding{
			Runtime: testSession().Runtime,
		},
	}
	right := Subject{
		Kind:  policy.TargetKindIP,
		Value: "203.0.113.10",
		Binding: RuntimeBinding{
			Runtime: discovery.SessionRuntime{
				Source:  discovery.DiscoverySourceHostProcess,
				HostPID: 4343,
				Name:    "edge-b",
			},
		},
	}

	if left.Equal(right) {
		t.Fatalf("expected identical ips on different runtimes to remain distinct subjects, got %#v and %#v", left, right)
	}
}

func TestActionValidateIntents(t *testing.T) {
	desired := testDesiredState(t, policy.TargetKindIP)
	applied := AppliedState{
		Mode:    DesiredModeLimit,
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
	}

	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			if err := tt.action.Validate(); err != nil {
				t.Fatalf("expected %s action to validate, got %v", tt.name, err)
			}
		})
	}
}

func TestAppliedStateMatchesDesired(t *testing.T) {
	desired := testDesiredState(t, policy.TargetKindOutbound)
	applied := AppliedState{
		Mode:    DesiredModeLimit,
		Subject: desired.Subject,
		Limits:  desired.Limits,
		Driver:  "tc",
	}

	if !applied.MatchesDesired(desired) {
		t.Fatalf("expected applied state to match desired state, got %#v and %#v", applied, desired)
	}
}

func TestSubjectFromTargetBuildsIPBaselineSubject(t *testing.T) {
	subject, err := SubjectFromTarget(policy.Target{
		Kind: policy.TargetKindIP,
		All:  true,
	}, testSession())
	if err != nil {
		t.Fatalf("expected ip baseline subject derivation to succeed, got %v", err)
	}

	if !subject.All || subject.Value != "" {
		t.Fatalf("expected baseline ip subject, got %#v", subject)
	}
	if subject.NormalizedIPAggregation() != policy.IPAggregationModeShared {
		t.Fatalf("expected baseline ip subject to normalize to shared aggregation, got %#v", subject)
	}
}

func TestSubjectFromTargetPreservesExplicitPerIPAggregation(t *testing.T) {
	subject, err := SubjectFromTarget(policy.Target{
		Kind:          policy.TargetKindIP,
		All:           true,
		IPAggregation: policy.IPAggregationModePerIP,
	}, testSession())
	if err != nil {
		t.Fatalf("expected per-ip subject derivation to succeed, got %v", err)
	}

	if !subject.All || subject.Value != "" {
		t.Fatalf("expected all-ip subject, got %#v", subject)
	}
	if subject.IPAggregation != policy.IPAggregationModePerIP {
		t.Fatalf("expected per-ip aggregation to be preserved, got %#v", subject)
	}
}

func TestAllIPSubjectsRemainDistinctAcrossAggregationModes(t *testing.T) {
	shared := Subject{
		Kind:          policy.TargetKindIP,
		All:           true,
		IPAggregation: policy.IPAggregationModeShared,
		Binding: RuntimeBinding{
			Runtime: testSession().Runtime,
		},
	}
	perIP := Subject{
		Kind:          policy.TargetKindIP,
		All:           true,
		IPAggregation: policy.IPAggregationModePerIP,
		Binding: RuntimeBinding{
			Runtime: testSession().Runtime,
		},
	}

	if shared.Equal(perIP) {
		t.Fatalf("expected all-ip subjects with different aggregation modes to remain distinct, got %#v and %#v", shared, perIP)
	}
}

func TestSubjectValidateRejectsAggregationForSpecificIP(t *testing.T) {
	subject := Subject{
		Kind:          policy.TargetKindIP,
		Value:         "203.0.113.10",
		IPAggregation: policy.IPAggregationModeShared,
		Binding: RuntimeBinding{
			Runtime: testSession().Runtime,
		},
	}

	if err := subject.Validate(); err == nil {
		t.Fatalf("expected specific ip subject with aggregation to fail validation: %#v", subject)
	}
}

func TestDesiredStateFromEvaluationIPUnlimited(t *testing.T) {
	session := testSession()
	evaluation, err := (policy.Evaluator{}).Evaluate([]policy.Policy{
		{
			Name:   "ip-unlimited",
			Effect: policy.EffectExclude,
			Target: policy.Target{
				Kind:  policy.TargetKindIP,
				Value: session.Client.IP,
			},
		},
	}, session)
	if err != nil {
		t.Fatalf("expected policy evaluation to succeed, got %v", err)
	}

	desired, err := DesiredStateFromEvaluation(session, evaluation)
	if err != nil {
		t.Fatalf("expected unlimited desired state construction to succeed, got %v", err)
	}

	if desired.Mode != DesiredModeUnlimited {
		t.Fatalf("expected unlimited desired mode, got %#v", desired)
	}
	if desired.Subject.All || desired.Subject.Value != "203.0.113.10" {
		t.Fatalf("expected specific ip unlimited subject, got %#v", desired.Subject)
	}
	if desired.Limits.HasAny() {
		t.Fatalf("expected unlimited desired state to keep empty limits, got %#v", desired)
	}
}

func TestAppliedUnlimitedStateMatchesUnlimitedDesiredState(t *testing.T) {
	session := testSession()
	evaluation, err := (policy.Evaluator{}).Evaluate([]policy.Policy{
		{
			Name:   "ip-unlimited",
			Effect: policy.EffectExclude,
			Target: policy.Target{
				Kind:  policy.TargetKindIP,
				Value: session.Client.IP,
			},
		},
	}, session)
	if err != nil {
		t.Fatalf("expected policy evaluation to succeed, got %v", err)
	}
	desired, err := DesiredStateFromEvaluation(session, evaluation)
	if err != nil {
		t.Fatalf("expected unlimited desired state construction to succeed, got %v", err)
	}

	applied := AppliedState{
		Mode:    DesiredModeUnlimited,
		Subject: desired.Subject,
		Driver:  "tc",
	}
	if err := applied.Validate(); err != nil {
		t.Fatalf("expected unlimited applied state to validate, got %v", err)
	}
	if !applied.MatchesDesired(desired) {
		t.Fatalf("expected unlimited applied state to match desired state, got %#v and %#v", applied, desired)
	}
}
