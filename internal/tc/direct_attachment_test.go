package tc

import (
	"strings"
	"testing"

	"github.com/PdYrust/RayLimit/internal/limiter"
	"github.com/PdYrust/RayLimit/internal/policy"
)

func TestBuildDirectAttachmentExecutionForIP(t *testing.T) {
	subject := bindingTestSubject(t, policy.TargetKindIP)
	binding, err := BindSubject(subject)
	if err != nil {
		t.Fatalf("expected ip binding to succeed, got %v", err)
	}

	execution, err := BuildDirectAttachmentExecution(binding, Scope{
		Device:    "eth0",
		Direction: DirectionUpload,
	}, limiter.DesiredModeLimit, "1:2a")
	if err != nil {
		t.Fatalf("expected direct attachment execution construction to succeed, got %v", err)
	}

	if execution.Readiness != BindingReadinessReady {
		t.Fatalf("expected ready direct attachment execution, got %#v", execution)
	}
	if len(execution.Rules) != 1 {
		t.Fatalf("expected one direct attachment rule, got %#v", execution)
	}
	if execution.Rules[0].Identity.Value != "203.0.113.10" {
		t.Fatalf("expected canonical ipv4 client identity, got %#v", execution.Rules[0])
	}
	if execution.Rules[0].MatchField != AttachmentMatchSource {
		t.Fatalf("expected upload matching to use source ip, got %#v", execution.Rules[0])
	}
}

func TestBuildDirectAttachmentExecutionSupportsIPv6IP(t *testing.T) {
	subject := limiter.Subject{
		Kind:  policy.TargetKindIP,
		Value: "2001:db8::10",
		Binding: limiter.RuntimeBinding{
			Runtime: bindingTestSession().Runtime,
		},
	}
	binding, err := BindSubject(subject)
	if err != nil {
		t.Fatalf("expected ipv6 ip binding to succeed, got %v", err)
	}

	execution, err := BuildDirectAttachmentExecution(binding, Scope{
		Device:    "eth0",
		Direction: DirectionUpload,
	}, limiter.DesiredModeLimit, "1:2a")
	if err != nil {
		t.Fatalf("expected ipv6 direct attachment execution construction to succeed, got %v", err)
	}

	if execution.Readiness != BindingReadinessReady {
		t.Fatalf("expected ready ipv6 direct attachment execution, got %#v", execution)
	}
	if len(execution.Rules) != 1 {
		t.Fatalf("expected one direct attachment rule for ipv6, got %#v", execution)
	}
	if execution.Rules[0].Identity.Value != "2001:db8::10" {
		t.Fatalf("expected canonical ipv6 client identity, got %#v", execution.Rules[0])
	}
	if execution.Rules[0].Confidence != BindingConfidenceMedium {
		t.Fatalf("expected conservative ipv6 confidence, got %#v", execution.Rules[0])
	}
}

func TestBuildDirectAttachmentExecutionAcceptsIPv4MappedIPv6(t *testing.T) {
	subject := limiter.Subject{
		Kind:  policy.TargetKindIP,
		Value: "::ffff:203.0.113.10",
		Binding: limiter.RuntimeBinding{
			Runtime: bindingTestSession().Runtime,
		},
	}
	binding, err := BindSubject(subject)
	if err != nil {
		t.Fatalf("expected mapped ip binding to succeed, got %v", err)
	}

	execution, err := BuildDirectAttachmentExecution(binding, Scope{
		Device:    "eth0",
		Direction: DirectionUpload,
	}, limiter.DesiredModeLimit, "1:2a")
	if err != nil {
		t.Fatalf("expected mapped ip direct attachment execution construction to succeed, got %v", err)
	}

	if execution.Readiness != BindingReadinessReady {
		t.Fatalf("expected ready mapped ip direct attachment execution, got %#v", execution)
	}
	if len(execution.Rules) != 1 || execution.Rules[0].Identity.Value != "203.0.113.10" {
		t.Fatalf("expected mapped ipv6 client ip to normalize to ipv4, got %#v", execution)
	}
}

func TestBuildDirectAttachmentExecutionCanonicalizesEquivalentIPv6ForDeterministicRule(t *testing.T) {
	values := []string{"2001:db8::10", "2001:0db8::0010"}
	executions := make([]DirectAttachmentExecution, 0, len(values))

	for _, value := range values {
		binding, err := BindSubject(limiter.Subject{
			Kind:  policy.TargetKindIP,
			Value: value,
			Binding: limiter.RuntimeBinding{
				Runtime: bindingTestSession().Runtime,
			},
		})
		if err != nil {
			t.Fatalf("expected ipv6 binding for %q to succeed, got %v", value, err)
		}

		execution, err := BuildDirectAttachmentExecution(binding, Scope{
			Device:    "eth0",
			Direction: DirectionUpload,
		}, limiter.DesiredModeLimit, "1:2a")
		if err != nil {
			t.Fatalf("expected ipv6 direct attachment execution construction for %q to succeed, got %v", value, err)
		}
		executions = append(executions, execution)
	}

	if len(executions) != 2 {
		t.Fatalf("expected two comparable executions, got %#v", executions)
	}
	if executions[0].Rules[0].Identity.Value != "2001:db8::10" || executions[1].Rules[0].Identity.Value != "2001:db8::10" {
		t.Fatalf("expected equivalent ipv6 forms to normalize to one rule identity, got %#v", executions)
	}
	if executions[0].Rules[0].Preference != executions[1].Rules[0].Preference {
		t.Fatalf("expected equivalent ipv6 forms to derive one rule preference, got %#v", executions)
	}
}

func TestBuildDirectAttachmentExecutionCanonicalizesMappedIPv4ForDeterministicRule(t *testing.T) {
	values := []string{"203.0.113.10", "::ffff:203.0.113.10"}
	executions := make([]DirectAttachmentExecution, 0, len(values))

	for _, value := range values {
		binding, err := BindSubject(limiter.Subject{
			Kind:  policy.TargetKindIP,
			Value: value,
			Binding: limiter.RuntimeBinding{
				Runtime: bindingTestSession().Runtime,
			},
		})
		if err != nil {
			t.Fatalf("expected ip binding for %q to succeed, got %v", value, err)
		}

		execution, err := BuildDirectAttachmentExecution(binding, Scope{
			Device:    "eth0",
			Direction: DirectionUpload,
		}, limiter.DesiredModeLimit, "1:2a")
		if err != nil {
			t.Fatalf("expected direct attachment execution construction for %q to succeed, got %v", value, err)
		}
		executions = append(executions, execution)
	}

	if len(executions) != 2 {
		t.Fatalf("expected two comparable executions, got %#v", executions)
	}
	if executions[0].Rules[0].Identity.Value != "203.0.113.10" || executions[1].Rules[0].Identity.Value != "203.0.113.10" {
		t.Fatalf("expected equivalent ipv4 forms to normalize to one rule identity, got %#v", executions)
	}
	if executions[0].Rules[0].Preference != executions[1].Rules[0].Preference {
		t.Fatalf("expected equivalent ipv4 forms to derive one rule preference, got %#v", executions)
	}
}

func TestBuildDirectAttachmentExecutionForIPUnlimited(t *testing.T) {
	subject := bindingTestSubject(t, policy.TargetKindIP)
	binding, err := BindSubject(subject)
	if err != nil {
		t.Fatalf("expected ip binding to succeed, got %v", err)
	}

	execution, err := BuildDirectAttachmentExecution(binding, Scope{
		Device:    "eth0",
		Direction: DirectionUpload,
	}, limiter.DesiredModeUnlimited, "")
	if err != nil {
		t.Fatalf("expected unlimited direct attachment execution construction to succeed, got %v", err)
	}

	if execution.Readiness != BindingReadinessReady || len(execution.Rules) != 1 {
		t.Fatalf("expected ready unlimited direct attachment execution, got %#v", execution)
	}
	if execution.Rules[0].Disposition != DirectAttachmentDispositionPass || execution.Rules[0].ClassID != "" {
		t.Fatalf("expected pass-through unlimited rule, got %#v", execution.Rules[0])
	}
}

func TestBuildDirectAttachmentExecutionForIPBaselineAll(t *testing.T) {
	subject := limiter.Subject{
		Kind: policy.TargetKindIP,
		All:  true,
		Binding: limiter.RuntimeBinding{
			Runtime: bindingTestSession().Runtime,
		},
	}
	binding, err := BindSubject(subject)
	if err != nil {
		t.Fatalf("expected ip baseline binding to succeed, got %v", err)
	}

	execution, err := BuildDirectAttachmentExecution(binding, Scope{
		Device:    "eth0",
		Direction: DirectionUpload,
	}, limiter.DesiredModeLimit, "1:2a")
	if err != nil {
		t.Fatalf("expected baseline direct attachment execution construction to succeed, got %v", err)
	}

	if execution.Readiness != BindingReadinessReady || len(execution.Rules) != 1 {
		t.Fatalf("expected ready baseline direct attachment execution, got %#v", execution)
	}
	if execution.Rules[0].Classifier != DirectAttachmentClassifierMatchAll || execution.Rules[0].Identity.Kind != IdentityKindAllClientIP {
		t.Fatalf("expected matchall baseline rule, got %#v", execution.Rules[0])
	}
}

func TestBuildDirectAttachmentExecutionReportsUnavailableForNonIPKinds(t *testing.T) {
	tests := []policy.TargetKind{
		policy.TargetKindInbound,
		policy.TargetKindOutbound,
	}

	for _, kind := range tests {
		t.Run(string(kind), func(t *testing.T) {
			subject := bindingTestSubject(t, kind)
			binding, err := BindSubject(subject)
			if err != nil {
				t.Fatalf("expected %s binding to succeed, got %v", kind, err)
			}

			execution, err := BuildDirectAttachmentExecution(binding, Scope{
				Device:    "eth0",
				Direction: DirectionUpload,
			}, limiter.DesiredModeLimit, "1:2a")
			if err != nil {
				t.Fatalf("expected %s direct attachment execution construction to succeed, got %v", kind, err)
			}

			if execution.Readiness != BindingReadinessUnavailable {
				t.Fatalf("expected unavailable direct attachment execution, got %#v", execution)
			}
			if len(execution.Rules) != 0 {
				t.Fatalf("expected no direct attachment rules, got %#v", execution)
			}
			switch kind {
			case policy.TargetKindInbound:
				if !strings.Contains(execution.Reason, "mark-backed") {
					t.Fatalf("expected inbound execution reason, got %#v", execution)
				}
			case policy.TargetKindOutbound:
				if !strings.Contains(execution.Reason, "socket mark") || !strings.Contains(execution.Reason, "mark-backed") {
					t.Fatalf("expected outbound execution reason, got %#v", execution)
				}
			}
		})
	}
}

func TestObserveDirectAttachmentMatchesExpectedFilter(t *testing.T) {
	desired := testDesiredState(t, policy.TargetKindIP, 2048, 0)
	plan, err := (Planner{}).Plan(limiter.Action{
		Kind:    limiter.ActionInspect,
		Subject: desired.Subject,
	}, Scope{
		Device:    "eth0",
		Direction: DirectionUpload,
	})
	if err != nil {
		t.Fatalf("expected inspect plan to succeed, got %v", err)
	}

	snapshot := Snapshot{
		Device: "eth0",
		Filters: []FilterState{
			{
				Kind:       "u32",
				Parent:     plan.Handles.RootHandle,
				Protocol:   "ip",
				Preference: plan.AttachmentExecution.Rules[0].Preference,
				FlowID:     plan.Handles.ClassID,
			},
		},
	}

	observation, err := ObserveDirectAttachment(snapshot, plan)
	if err != nil {
		t.Fatalf("expected direct attachment observation to succeed, got %v", err)
	}
	if !observation.Comparable || !observation.Matched {
		t.Fatalf("expected direct attachment observation to report a match, got %#v", observation)
	}
}

func TestObserveDirectAttachmentMatchesExpectedIPv6Filter(t *testing.T) {
	subject := limiter.Subject{
		Kind:  policy.TargetKindIP,
		Value: "2001:db8::10",
		Binding: limiter.RuntimeBinding{
			Runtime: bindingTestSession().Runtime,
		},
	}
	plan, err := (Planner{}).Plan(limiter.Action{
		Kind:    limiter.ActionInspect,
		Subject: subject,
	}, Scope{
		Device:    "eth0",
		Direction: DirectionUpload,
	})
	if err != nil {
		t.Fatalf("expected ipv6 inspect plan to succeed, got %v", err)
	}

	snapshot := Snapshot{
		Device: "eth0",
		Filters: []FilterState{
			{
				Kind:       "u32",
				Parent:     plan.Handles.RootHandle,
				Protocol:   "ipv6",
				Preference: plan.AttachmentExecution.Rules[0].Preference,
				FlowID:     plan.Handles.ClassID,
			},
		},
	}

	observation, err := ObserveDirectAttachment(snapshot, plan)
	if err != nil {
		t.Fatalf("expected ipv6 direct attachment observation to succeed, got %v", err)
	}
	if !observation.Comparable || !observation.Matched {
		t.Fatalf("expected ipv6 direct attachment observation to report a match, got %#v", observation)
	}
}

func TestAppendObservedDirectAttachmentCleanupDropsClassDeleteWhenClassIsAlreadyGone(t *testing.T) {
	desired := testDesiredState(t, policy.TargetKindIP, 2048, 0)
	plan, err := (Planner{}).Plan(limiter.Action{
		Kind:    limiter.ActionRemove,
		Subject: desired.Subject,
		Applied: []limiter.AppliedState{{
			Mode:      limiter.DesiredModeLimit,
			Subject:   desired.Subject,
			Limits:    desired.Limits,
			Driver:    "tc",
			Reference: "1:2a",
		}},
	}, Scope{
		Device:    "eth0",
		Direction: DirectionUpload,
	})
	if err != nil {
		t.Fatalf("expected remove plan to succeed, got %v", err)
	}

	snapshot := Snapshot{
		Device: "eth0",
		QDiscs: []QDiscState{{Kind: "htb", Handle: plan.Handles.RootHandle, Parent: "root"}},
		Filters: []FilterState{{
			Kind:       "u32",
			Parent:     plan.Handles.RootHandle,
			Protocol:   "ip",
			Preference: plan.AttachmentExecution.Rules[0].Preference,
			FlowID:     plan.Handles.ClassID,
		}},
	}

	updated, err := AppendObservedDirectAttachmentCleanup(plan, snapshot)
	if err != nil {
		t.Fatalf("expected observed direct attachment cleanup to succeed, got %v", err)
	}

	if len(updated.Steps) != 2 {
		t.Fatalf("expected attachment-only cleanup steps when the class is already gone, got %#v", updated.Steps)
	}
	if updated.Steps[0].Name != "delete-direct-attachment-1" || updated.Steps[1].Name != "delete-direct-attachment-2" {
		t.Fatalf("expected direct attachment cleanup steps only, got %#v", updated.Steps)
	}
}

func TestSnapshotEligibleForRootQDiscCleanupAfterDirectAttachmentRemoval(t *testing.T) {
	desired := testDesiredState(t, policy.TargetKindIP, 2048, 0)
	plan, err := (Planner{}).Plan(limiter.Action{
		Kind:    limiter.ActionInspect,
		Subject: desired.Subject,
	}, Scope{
		Device:    "eth0",
		Direction: DirectionUpload,
	})
	if err != nil {
		t.Fatalf("expected inspect plan to succeed, got %v", err)
	}

	snapshot := Snapshot{
		Device: "eth0",
		QDiscs: []QDiscState{{Kind: "htb", Handle: plan.Handles.RootHandle, Parent: "root"}},
		Classes: []ClassState{{
			Kind:    "htb",
			ClassID: plan.Handles.ClassID,
			Parent:  plan.Handles.RootHandle,
		}},
		Filters: []FilterState{{
			Kind:       "u32",
			Parent:     plan.Handles.RootHandle,
			Protocol:   "ip",
			Preference: plan.AttachmentExecution.Rules[0].Preference,
			FlowID:     plan.Handles.ClassID,
		}},
	}

	if !snapshot.EligibleForRootQDiscCleanupAfterDirectAttachmentRemoval(plan.Handles.RootHandle, plan.Handles.ClassID, plan.AttachmentExecution) {
		t.Fatalf("expected snapshot to be eligible for root qdisc cleanup after direct attachment removal, got %#v", snapshot)
	}
}

func TestSnapshotEligibleForRootQDiscCleanupAfterDirectAttachmentRemovalWithoutClass(t *testing.T) {
	desired := testDesiredState(t, policy.TargetKindIP, 2048, 0)
	plan, err := (Planner{}).Plan(limiter.Action{
		Kind:    limiter.ActionInspect,
		Subject: desired.Subject,
	}, Scope{
		Device:    "eth0",
		Direction: DirectionUpload,
	})
	if err != nil {
		t.Fatalf("expected inspect plan to succeed, got %v", err)
	}

	snapshot := Snapshot{
		Device: "eth0",
		QDiscs: []QDiscState{{Kind: "htb", Handle: plan.Handles.RootHandle, Parent: "root"}},
		Filters: []FilterState{{
			Kind:       "u32",
			Parent:     plan.Handles.RootHandle,
			Protocol:   "ip",
			Preference: plan.AttachmentExecution.Rules[0].Preference,
			FlowID:     plan.Handles.ClassID,
		}},
	}

	if !snapshot.EligibleForRootQDiscCleanupAfterDirectAttachmentRemoval(plan.Handles.RootHandle, plan.Handles.ClassID, plan.AttachmentExecution) {
		t.Fatalf("expected attachment-only snapshot to be eligible for root qdisc cleanup after direct attachment removal, got %#v", snapshot)
	}
}
