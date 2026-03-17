package limiter

import (
	"strings"
	"testing"

	"github.com/PdYrust/RayLimit/internal/policy"
)

func testAppliedState(t *testing.T, desired DesiredState, upload int64, download int64, reference string) AppliedState {
	t.Helper()

	limits := policy.LimitPolicy{}
	if upload > 0 {
		limits.Upload = &policy.RateLimit{BytesPerSecond: upload}
	}
	if download > 0 {
		limits.Download = &policy.RateLimit{BytesPerSecond: download}
	}

	applied := AppliedState{
		Subject:   desired.Subject,
		Limits:    limits,
		Driver:    "tc",
		Reference: reference,
	}
	if err := applied.Validate(); err != nil {
		t.Fatalf("expected applied state to validate, got %v", err)
	}

	return applied
}

func TestReconcilerDecideApplyWithNoAppliedState(t *testing.T) {
	desired := testDesiredState(t, policy.TargetKindConnection)

	decision, err := (Reconciler{}).Decide(&desired, nil)
	if err != nil {
		t.Fatalf("expected apply decision, got %v", err)
	}

	if decision.Kind != DecisionApply {
		t.Fatalf("expected apply decision, got %#v", decision)
	}
	if decision.Subject == nil || !decision.Subject.Equal(desired.Subject) {
		t.Fatalf("expected decision subject to match desired state, got %#v", decision.Subject)
	}
	if !strings.Contains(decision.Reason, "no applied state") {
		t.Fatalf("expected explicit apply reason, got %q", decision.Reason)
	}

	action, err := decision.Action()
	if err != nil {
		t.Fatalf("expected action conversion to succeed, got %v", err)
	}
	if action == nil || action.Kind != ActionApply {
		t.Fatalf("expected apply action, got %#v", action)
	}
}

func TestReconcilerDecideNoOpForMatchingAppliedState(t *testing.T) {
	desired := testDesiredState(t, policy.TargetKindUUID)
	applied := testAppliedState(t, desired, 2048, 4096, "1:2a")

	decision, err := (Reconciler{}).Decide(&desired, []AppliedState{applied})
	if err != nil {
		t.Fatalf("expected no-op decision, got %v", err)
	}

	if decision.Kind != DecisionNoOp {
		t.Fatalf("expected no-op decision, got %#v", decision)
	}
	if !strings.Contains(decision.Reason, "already matches") {
		t.Fatalf("expected matching reason, got %q", decision.Reason)
	}

	action, err := decision.Action()
	if err != nil {
		t.Fatalf("expected no-op action conversion to succeed, got %v", err)
	}
	if action != nil {
		t.Fatalf("expected no action for no-op decision, got %#v", action)
	}
}

func TestReconcilerDecideReplaceForDifferingAppliedState(t *testing.T) {
	desired := testDesiredState(t, policy.TargetKindIP)
	applied := testAppliedState(t, desired, 1024, 4096, "1:2a")

	decision, err := (Reconciler{}).Decide(&desired, []AppliedState{applied})
	if err != nil {
		t.Fatalf("expected replace decision, got %v", err)
	}

	if decision.Kind != DecisionReplace {
		t.Fatalf("expected replace decision, got %#v", decision)
	}
	if !strings.Contains(decision.Reason, "differs from the desired state") {
		t.Fatalf("expected replace reason, got %q", decision.Reason)
	}

	action, err := decision.Action()
	if err != nil {
		t.Fatalf("expected replace action conversion to succeed, got %v", err)
	}
	if action == nil || action.Kind != ActionReconcile {
		t.Fatalf("expected reconcile action, got %#v", action)
	}
	if len(action.Applied) != 1 || action.Applied[0].Reference != "1:2a" {
		t.Fatalf("expected reconcile action to preserve applied state, got %#v", action)
	}
}

func TestReconcilerDecideRemoveWhenAppliedStateExistsWithoutDesiredState(t *testing.T) {
	desired := testDesiredState(t, policy.TargetKindOutbound)
	applied := testAppliedState(t, desired, 2048, 4096, "1:2a")

	decision, err := (Reconciler{}).Decide(nil, []AppliedState{applied})
	if err != nil {
		t.Fatalf("expected remove decision, got %v", err)
	}

	if decision.Kind != DecisionRemove {
		t.Fatalf("expected remove decision, got %#v", decision)
	}
	if !strings.Contains(decision.Reason, "without a desired state") {
		t.Fatalf("expected remove reason, got %q", decision.Reason)
	}

	action, err := decision.Action()
	if err != nil {
		t.Fatalf("expected remove action conversion to succeed, got %v", err)
	}
	if action == nil || action.Kind != ActionRemove {
		t.Fatalf("expected remove action, got %#v", action)
	}
}

func TestReconcilerDecideReplaceForMultipleAppliedStates(t *testing.T) {
	desired := testDesiredState(t, policy.TargetKindConnection)
	applied := []AppliedState{
		testAppliedState(t, desired, 2048, 4096, "1:2a"),
		testAppliedState(t, desired, 2048, 4096, "1:2b"),
	}

	decision, err := (Reconciler{}).Decide(&desired, applied)
	if err != nil {
		t.Fatalf("expected replace decision, got %v", err)
	}

	if decision.Kind != DecisionReplace {
		t.Fatalf("expected replace decision for multiple applied states, got %#v", decision)
	}
	if !strings.Contains(decision.Reason, "multiple applied states") {
		t.Fatalf("expected duplicate-state reason, got %q", decision.Reason)
	}
}

func TestReconcilerDecideRejectsMismatchedAppliedState(t *testing.T) {
	desired := testDesiredState(t, policy.TargetKindConnection)
	mismatched := testDesiredState(t, policy.TargetKindIP)
	applied := testAppliedState(t, mismatched, 2048, 4096, "1:2a")

	_, err := (Reconciler{}).Decide(&desired, []AppliedState{applied})
	if err == nil {
		t.Fatal("expected mismatched applied state to fail reconciliation")
	}
}

func TestDecisionValidateAllowsSubjectOnlyRemoveDecision(t *testing.T) {
	desired := testDesiredState(t, policy.TargetKindUUID)

	err := (Decision{
		Kind:    DecisionRemove,
		Subject: &desired.Subject,
		Reason:  "remove stale state",
	}).Validate()
	if err != nil {
		t.Fatalf("expected subject-only remove decision to validate, got %v", err)
	}
}
