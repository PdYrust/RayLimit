package cli

import (
	"strings"
	"testing"

	"github.com/PdYrust/RayLimit/internal/discovery"
	"github.com/PdYrust/RayLimit/internal/limiter"
	"github.com/PdYrust/RayLimit/internal/policy"
	"github.com/PdYrust/RayLimit/internal/tc"
)

func testLimitSession() discovery.Session {
	return discovery.Session{
		Runtime: discovery.SessionRuntime{
			Source:  discovery.DiscoverySourceHostProcess,
			HostPID: 4242,
			Name:    "edge-a",
		},
		Client: discovery.SessionClient{
			IP: "203.0.113.10",
		},
	}
}

func testLimitDesiredState(t *testing.T, session discovery.Session, rule policy.Policy) limiter.DesiredState {
	t.Helper()

	evaluation, err := (policy.Evaluator{}).Evaluate([]policy.Policy{rule}, session)
	if err != nil {
		t.Fatalf("expected policy evaluation to succeed, got %v", err)
	}

	desired, err := limiter.DesiredStateFromEvaluation(session, evaluation)
	if err != nil {
		t.Fatalf("expected desired state construction to succeed, got %v", err)
	}

	return desired
}

func TestLimitDecisionReappliesIPAllBaselineWhenAttachmentIsMissing(t *testing.T) {
	desired := testLimitDesiredState(t, testLimitSession(), policy.Policy{
		Name: "ip-all-limit",
		Target: policy.Target{
			Kind: policy.TargetKindIP,
			All:  true,
		},
		Limits: policy.LimitPolicy{
			Upload: &policy.RateLimit{BytesPerSecond: 2048},
		},
	})
	applied := limiter.AppliedState{
		Mode:    limiter.DesiredModeLimit,
		Subject: desired.Subject,
		Limits:  desired.Limits,
		Driver:  "tc",
	}

	decision, err := (App{}).limitDecision(limitOperationApply, desired.Subject, &desired, limitObservationReport{
		Available:         true,
		Reconcilable:      true,
		Matched:           true,
		AttachmentMatched: boolPtr(false),
	}, []limiter.AppliedState{applied})
	if err != nil {
		t.Fatalf("expected limit decision to succeed, got %v", err)
	}

	if decision.Kind != limiter.DecisionApply {
		t.Fatalf("expected attachment-missing baseline to trigger reapply, got %#v", decision)
	}
	if decision.Reason != attachmentReapplyDecisionReason(desired.Subject) {
		t.Fatalf("expected attachment reapply reason, got %#v", decision)
	}
}

func TestObservedRemoveDirectAttachmentMatchFindsSpecificIPLimitAndUnlimitedRules(t *testing.T) {
	subject := limiter.Subject{
		Kind:  policy.TargetKindIP,
		Value: "203.0.113.10",
		Binding: limiter.RuntimeBinding{
			Runtime: testLimitSession().Runtime,
		},
	}
	binding, err := tc.BindSubject(subject)
	if err != nil {
		t.Fatalf("expected ip binding to succeed, got %v", err)
	}

	scope := tc.Scope{
		Device:    "eth0",
		Direction: tc.DirectionUpload,
	}
	limitExecution, err := tc.BuildDirectAttachmentExecution(binding, scope, limiter.DesiredModeLimit, "1:2a")
	if err != nil {
		t.Fatalf("expected limit direct attachment execution to succeed, got %v", err)
	}
	unlimitedExecution, err := tc.BuildDirectAttachmentExecution(binding, scope, limiter.DesiredModeUnlimited, "")
	if err != nil {
		t.Fatalf("expected unlimited direct attachment execution to succeed, got %v", err)
	}

	tests := []struct {
		name    string
		filters []tc.FilterState
		matched bool
	}{
		{
			name: "limit-filter-only",
			filters: []tc.FilterState{{
				Kind:       "u32",
				Parent:     "1:",
				Protocol:   "ip",
				Preference: limitExecution.Rules[0].Preference,
				FlowID:     "1:2a",
			}},
			matched: true,
		},
		{
			name: "unlimited-filter-only",
			filters: []tc.FilterState{{
				Kind:       "u32",
				Parent:     "1:",
				Protocol:   "ip",
				Preference: unlimitedExecution.Rules[0].Preference,
			}},
			matched: true,
		},
		{
			name: "no-matching-filter",
			filters: []tc.FilterState{{
				Kind:       "u32",
				Parent:     "1:",
				Protocol:   "ip",
				Preference: 999,
				FlowID:     "1:2a",
			}},
			matched: false,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			comparable, matched, err := observedRemoveDirectAttachmentMatch(subject, binding, scope, "1:", "1:2a", tc.Snapshot{
				Device:  "eth0",
				Filters: test.filters,
			})
			if err != nil {
				t.Fatalf("expected remove direct attachment match observation to succeed, got %v", err)
			}
			if !comparable {
				t.Fatalf("expected remove direct attachment observation to be comparable")
			}
			if matched != test.matched {
				t.Fatalf("expected matched=%t, got %#v", test.matched, matched)
			}
		})
	}
}

func TestShouldShowPlanClassIDHidesUnlimitedApplyPlans(t *testing.T) {
	desired := testLimitDesiredState(t, testLimitSession(), policy.Policy{
		Name:   "ip-unlimited",
		Effect: policy.EffectExclude,
		Target: policy.Target{
			Kind:  policy.TargetKindIP,
			Value: "203.0.113.10",
		},
	})
	plan, err := (tc.Planner{}).Plan(limiter.Action{
		Kind:    limiter.ActionApply,
		Subject: desired.Subject,
		Desired: &desired,
	}, tc.Scope{
		Device:    "eth0",
		Direction: tc.DirectionUpload,
	})
	if err != nil {
		t.Fatalf("expected unlimited plan to succeed, got %v", err)
	}

	if shouldShowPlanClassID(plan) {
		t.Fatalf("expected unlimited apply plan to hide class id output, got %#v", plan)
	}
}

func TestWriteRequestedLimitTextUsesRuleSetLanguageForRemove(t *testing.T) {
	var output strings.Builder

	writeRequestedLimitText(&output, limitOperationRemove, tc.Scope{
		Device:    "eth0",
		Direction: tc.DirectionUpload,
	}, 0, false)

	if got := output.String(); !strings.Contains(got, "Requested removal: explicit upload rule set on eth0") {
		t.Fatalf("expected rule-set removal wording, got %q", got)
	}
}
