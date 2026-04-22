package tc

import (
	"fmt"
	"strings"
	"testing"

	"github.com/PdYrust/RayLimit/internal/discovery"
	"github.com/PdYrust/RayLimit/internal/limiter"
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

func testDesiredState(t *testing.T, kind policy.TargetKind, upload int64, download int64) limiter.DesiredState {
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

	limits := policy.LimitPolicy{}
	if upload > 0 {
		limits.Upload = &policy.RateLimit{BytesPerSecond: upload}
	}
	if download > 0 {
		limits.Download = &policy.RateLimit{BytesPerSecond: download}
	}

	evaluation, err := (policy.Evaluator{}).Evaluate([]policy.Policy{
		{
			Name:   string(kind) + "-limit",
			Target: target,
			Limits: limits,
		},
	}, session)
	if err != nil {
		t.Fatalf("expected policy evaluation to succeed, got %v", err)
	}

	desired, err := limiter.DesiredStateFromEvaluation(session, evaluation)
	if err != nil {
		t.Fatalf("expected desired state construction to succeed, got %v", err)
	}

	return desired
}

func testDesiredStateForPolicy(t *testing.T, policyDef policy.Policy) limiter.DesiredState {
	t.Helper()

	evaluation, err := (policy.Evaluator{}).Evaluate([]policy.Policy{policyDef}, testSession())
	if err != nil {
		t.Fatalf("expected policy evaluation to succeed, got %v", err)
	}

	desired, err := limiter.DesiredStateFromEvaluation(testSession(), evaluation)
	if err != nil {
		t.Fatalf("expected desired state construction to succeed, got %v", err)
	}

	return desired
}

func TestPlannerPlanApplyBuildsDeterministicCommands(t *testing.T) {
	desired := testDesiredState(t, policy.TargetKindOutbound, 2048, 0)
	action := limiter.Action{
		Kind:    limiter.ActionApply,
		Subject: desired.Subject,
		Desired: &desired,
	}
	scope := Scope{
		Device:    "eth0",
		Direction: DirectionUpload,
	}

	planner := Planner{}
	first, err := planner.Plan(action, scope)
	if err != nil {
		t.Fatalf("expected apply plan to succeed, got %v", err)
	}
	second, err := planner.Plan(action, scope)
	if err != nil {
		t.Fatalf("expected repeat apply plan to succeed, got %v", err)
	}

	if len(first.Steps) != 2 {
		t.Fatalf("expected two apply steps, got %#v", first.Steps)
	}
	if !first.Binding.EffectiveSubject.Equal(action.Subject) {
		t.Fatalf("expected plan binding to track the effective action subject, got %#v", first.Binding)
	}
	if first.Binding.Identity == nil || first.Binding.Identity.Kind != IdentityKindOutbound {
		t.Fatalf("expected outbound plan binding to include an outbound identity, got %#v", first.Binding)
	}
	if first.Handles.ClassID != second.Handles.ClassID {
		t.Fatalf("expected deterministic class ids, got %q and %q", first.Handles.ClassID, second.Handles.ClassID)
	}
	if first.Steps[0].Command.Args[0] != "qdisc" || first.Steps[1].Command.Args[0] != "class" {
		t.Fatalf("unexpected apply commands: %#v", first.Steps)
	}
	if got := first.Steps[1].Command.Args[len(first.Steps[1].Command.Args)-1]; got != "2048bps" {
		t.Fatalf("expected class rate to be rendered in bps, got %q", got)
	}
}

func TestPlannerPlanApplyBuildsDirectIPAttachmentCommands(t *testing.T) {
	desired := testDesiredState(t, policy.TargetKindIP, 2048, 0)
	action := limiter.Action{
		Kind:    limiter.ActionApply,
		Subject: desired.Subject,
		Desired: &desired,
	}

	plan, err := (Planner{}).Plan(action, Scope{
		Device:    "eth0",
		Direction: DirectionUpload,
	})
	if err != nil {
		t.Fatalf("expected ip apply plan to succeed, got %v", err)
	}

	if plan.AttachmentExecution.Readiness != BindingReadinessReady {
		t.Fatalf("expected ready direct attachment execution, got %#v", plan.AttachmentExecution)
	}
	if len(plan.Steps) != 3 {
		t.Fatalf("expected qdisc, class, and filter steps, got %#v", plan.Steps)
	}
	if plan.Steps[2].Name != "upsert-direct-attachment-1" {
		t.Fatalf("expected direct attachment step, got %#v", plan.Steps[2])
	}
	if got := plan.Steps[2].Command.Args[len(plan.Steps[2].Command.Args)-1]; got != plan.Handles.ClassID {
		t.Fatalf("expected direct attachment flowid to target the class id, got %#v", plan.Steps[2].Command.Args)
	}
}

func TestPlannerPlanApplyBuildsIPBaselineAllMatchAllCommands(t *testing.T) {
	desired := testDesiredStateForPolicy(t, policy.Policy{
		Name: "ip-all-limit",
		Target: policy.Target{
			Kind: policy.TargetKindIP,
			All:  true,
		},
		Limits: policy.LimitPolicy{
			Upload: &policy.RateLimit{BytesPerSecond: 2048},
		},
	})
	action := limiter.Action{
		Kind:    limiter.ActionApply,
		Subject: desired.Subject,
		Desired: &desired,
	}

	plan, err := (Planner{}).Plan(action, Scope{
		Device:    "eth0",
		Direction: DirectionUpload,
	})
	if err != nil {
		t.Fatalf("expected ip baseline apply plan to succeed, got %v", err)
	}

	if !plan.Action.Subject.All {
		t.Fatalf("expected baseline subject to remain explicit in the plan, got %#v", plan.Action.Subject)
	}
	if plan.Binding.Identity == nil || plan.Binding.Identity.NormalizedIPAggregation() != policy.IPAggregationModeShared {
		t.Fatalf("expected shared all-ip plan binding identity, got %#v", plan.Binding)
	}
	if plan.AttachmentExecution.Readiness != BindingReadinessReady || len(plan.AttachmentExecution.Rules) != 1 {
		t.Fatalf("expected one ready baseline attachment rule, got %#v", plan.AttachmentExecution)
	}
	if plan.AttachmentExecution.Rules[0].Classifier != DirectAttachmentClassifierMatchAll {
		t.Fatalf("expected matchall baseline rule, got %#v", plan.AttachmentExecution.Rules[0])
	}
	if len(plan.Steps) != 3 {
		t.Fatalf("expected qdisc, class, and baseline filter steps, got %#v", plan.Steps)
	}
	if got := strings.Join(plan.Steps[2].Command.Args, " "); !strings.Contains(got, "matchall") || !strings.Contains(got, "classid "+plan.Handles.ClassID) {
		t.Fatalf("expected baseline matchall classify command, got %q", got)
	}
}

func TestPlannerPlanApplyKeepsIPAllPerIPDistinctAndNonExecuting(t *testing.T) {
	sharedDesired := testDesiredStateForPolicy(t, policy.Policy{
		Name: "ip-all-shared-limit",
		Target: policy.Target{
			Kind: policy.TargetKindIP,
			All:  true,
		},
		Limits: policy.LimitPolicy{
			Upload: &policy.RateLimit{BytesPerSecond: 2048},
		},
	})
	perIPDesired := testDesiredStateForPolicy(t, policy.Policy{
		Name: "ip-all-per-ip-limit",
		Target: policy.Target{
			Kind:          policy.TargetKindIP,
			All:           true,
			IPAggregation: policy.IPAggregationModePerIP,
		},
		Limits: policy.LimitPolicy{
			Upload: &policy.RateLimit{BytesPerSecond: 2048},
		},
	})

	scope := Scope{
		Device:    "eth0",
		Direction: DirectionUpload,
	}
	sharedPlan, err := (Planner{}).Plan(limiter.Action{
		Kind:    limiter.ActionApply,
		Subject: sharedDesired.Subject,
		Desired: &sharedDesired,
	}, scope)
	if err != nil {
		t.Fatalf("expected shared all-ip apply plan to succeed, got %v", err)
	}
	perIPPlan, err := (Planner{}).Plan(limiter.Action{
		Kind:    limiter.ActionApply,
		Subject: perIPDesired.Subject,
		Desired: &perIPDesired,
	}, scope)
	if err != nil {
		t.Fatalf("expected per_ip all-ip apply plan to succeed, got %v", err)
	}

	if sharedPlan.Handles.ClassID == perIPPlan.Handles.ClassID {
		t.Fatalf("expected shared and per_ip all-ip plans to keep distinct class identities, got %q", sharedPlan.Handles.ClassID)
	}
	if perIPPlan.Binding.Readiness != BindingReadinessPartial {
		t.Fatalf("expected per_ip all-ip binding readiness to stay partial, got %#v", perIPPlan.Binding)
	}
	if perIPPlan.Binding.Identity == nil || perIPPlan.Binding.Identity.NormalizedIPAggregation() != policy.IPAggregationModePerIP {
		t.Fatalf("expected per_ip all-ip plan binding identity to preserve aggregation, got %#v", perIPPlan.Binding)
	}
	if perIPPlan.AttachmentExecution.Readiness != BindingReadinessUnavailable || len(perIPPlan.AttachmentExecution.Rules) != 0 {
		t.Fatalf("expected per_ip all-ip plan to avoid direct attachment execution, got %#v", perIPPlan.AttachmentExecution)
	}
	if len(perIPPlan.Steps) != 0 {
		t.Fatalf("expected per_ip all-ip plan to defer concrete tc steps, got %#v", perIPPlan.Steps)
	}
}

func TestPlannerPlanApplyBuildsIPUnlimitedPassCommands(t *testing.T) {
	desired := testDesiredStateForPolicy(t, policy.Policy{
		Name:   "ip-unlimited",
		Effect: policy.EffectExclude,
		Target: policy.Target{
			Kind:  policy.TargetKindIP,
			Value: "203.0.113.10",
		},
	})
	action := limiter.Action{
		Kind:    limiter.ActionApply,
		Subject: desired.Subject,
		Desired: &desired,
	}

	plan, err := (Planner{}).Plan(action, Scope{
		Device:    "eth0",
		Direction: DirectionUpload,
	})
	if err != nil {
		t.Fatalf("expected ip unlimited apply plan to succeed, got %v", err)
	}

	if plan.AttachmentExecution.Readiness != BindingReadinessReady || len(plan.AttachmentExecution.Rules) != 1 {
		t.Fatalf("expected one ready unlimited attachment rule, got %#v", plan.AttachmentExecution)
	}
	if plan.AttachmentExecution.Rules[0].Disposition != DirectAttachmentDispositionPass {
		t.Fatalf("expected pass-through unlimited rule, got %#v", plan.AttachmentExecution.Rules[0])
	}
	if len(plan.Steps) != 2 {
		t.Fatalf("expected qdisc and pass-rule steps only, got %#v", plan.Steps)
	}
	if got := strings.Join(plan.Steps[1].Command.Args, " "); !strings.Contains(got, " action pass") || strings.Contains(got, "flowid") {
		t.Fatalf("expected direct pass command without class flowid, got %q", got)
	}
}

func TestPlannerPlanApplyBuildsDirectIPv6AttachmentCommands(t *testing.T) {
	subject := limiter.Subject{
		Kind:  policy.TargetKindIP,
		Value: "2001:db8::10",
		Binding: limiter.RuntimeBinding{
			Runtime: testSession().Runtime,
		},
	}
	desired := limiter.DesiredState{
		Mode:    limiter.DesiredModeLimit,
		Subject: subject,
		Limits: policy.LimitPolicy{
			Upload: &policy.RateLimit{BytesPerSecond: 2048},
		},
		PolicyEvaluation: policy.Evaluation{
			Matches: []policy.Match{{Policy: policy.Policy{Name: "ipv6-limit", Target: policy.Target{Kind: policy.TargetKindIP, Value: "2001:db8::10"}, Limits: policy.LimitPolicy{Upload: &policy.RateLimit{BytesPerSecond: 2048}}}}},
			Selection: policy.Selection{
				Kind:       policy.TargetKindIP,
				Precedence: policy.TargetKindIP.Precedence(),
				Target:     policy.Target{Kind: policy.TargetKindIP, Value: "2001:db8::10"},
				Limits: []policy.Policy{{
					Name:   "ipv6-limit",
					Target: policy.Target{Kind: policy.TargetKindIP, Value: "2001:db8::10"},
					Limits: policy.LimitPolicy{Upload: &policy.RateLimit{BytesPerSecond: 2048}},
				}},
			},
			EffectiveLimits: policy.LimitPolicy{Upload: &policy.RateLimit{BytesPerSecond: 2048}},
			EffectiveReason: "test ipv6 limit",
		},
	}
	action := limiter.Action{
		Kind:    limiter.ActionApply,
		Subject: desired.Subject,
		Desired: &desired,
	}

	plan, err := (Planner{}).Plan(action, Scope{
		Device:    "eth0",
		Direction: DirectionUpload,
	})
	if err != nil {
		t.Fatalf("expected ipv6 apply plan to succeed, got %v", err)
	}

	if plan.AttachmentExecution.Readiness != BindingReadinessReady {
		t.Fatalf("expected ready ipv6 direct attachment execution, got %#v", plan.AttachmentExecution)
	}
	if plan.AttachmentExecution.Confidence != BindingConfidenceMedium {
		t.Fatalf("expected conservative ipv6 execution confidence, got %#v", plan.AttachmentExecution)
	}
	if len(plan.Steps) != 3 {
		t.Fatalf("expected qdisc, class, and ipv6 filter steps, got %#v", plan.Steps)
	}
	if got := strings.Join(plan.Steps[2].Command.Args, " "); !strings.Contains(got, "protocol ipv6") || !strings.Contains(got, "match ip6 src 2001:db8::10/128") {
		t.Fatalf("expected ipv6 direct attachment command, got %q", got)
	}
}

func TestPlannerPlanIPCanonicalizesMappedIPv4ForDeterministicClassID(t *testing.T) {
	runtime := testSession().Runtime
	cases := []struct {
		name  string
		value string
	}{
		{name: "canonical-ipv4", value: "203.0.113.10"},
		{name: "mapped-ipv4", value: "::ffff:203.0.113.10"},
	}

	plans := make([]Plan, 0, len(cases))
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			plan, err := (Planner{}).Plan(limiter.Action{
				Kind: limiter.ActionInspect,
				Subject: limiter.Subject{
					Kind:  policy.TargetKindIP,
					Value: tc.value,
					Binding: limiter.RuntimeBinding{
						Runtime: runtime,
					},
				},
			}, Scope{
				Device:    "eth0",
				Direction: DirectionUpload,
			})
			if err != nil {
				t.Fatalf("expected inspect plan to succeed, got %v", err)
			}
			plans = append(plans, plan)
		})
	}

	if len(plans) != 2 {
		t.Fatalf("expected two comparable plans, got %#v", plans)
	}
	if plans[0].Handles.ClassID != plans[1].Handles.ClassID {
		t.Fatalf("expected canonical-equivalent IP subjects to share one class id, got %q and %q", plans[0].Handles.ClassID, plans[1].Handles.ClassID)
	}
	if len(plans[1].AttachmentExecution.Rules) != 1 || plans[1].AttachmentExecution.Rules[0].Identity.Value != "203.0.113.10" {
		t.Fatalf("expected mapped ipv4 direct attachment identity to normalize, got %#v", plans[1].AttachmentExecution)
	}
}

func TestPlannerPlanIPCanonicalizesEquivalentIPv6ForDeterministicClassID(t *testing.T) {
	runtime := testSession().Runtime
	cases := []struct {
		name  string
		value string
	}{
		{name: "canonical-ipv6", value: "2001:db8::10"},
		{name: "expanded-ipv6", value: "2001:0db8::0010"},
	}

	plans := make([]Plan, 0, len(cases))
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			plan, err := (Planner{}).Plan(limiter.Action{
				Kind: limiter.ActionInspect,
				Subject: limiter.Subject{
					Kind:  policy.TargetKindIP,
					Value: tc.value,
					Binding: limiter.RuntimeBinding{
						Runtime: runtime,
					},
				},
			}, Scope{
				Device:    "eth0",
				Direction: DirectionUpload,
			})
			if err != nil {
				t.Fatalf("expected inspect plan to succeed, got %v", err)
			}
			plans = append(plans, plan)
		})
	}

	if len(plans) != 2 {
		t.Fatalf("expected two comparable plans, got %#v", plans)
	}
	if plans[0].Handles.ClassID != plans[1].Handles.ClassID {
		t.Fatalf("expected canonical-equivalent ipv6 subjects to share one class id, got %q and %q", plans[0].Handles.ClassID, plans[1].Handles.ClassID)
	}
	if len(plans[1].AttachmentExecution.Rules) != 1 || plans[1].AttachmentExecution.Rules[0].Identity.Value != "2001:db8::10" {
		t.Fatalf("expected expanded ipv6 direct attachment identity to normalize, got %#v", plans[1].AttachmentExecution)
	}
}

func TestPlannerPlanIPScopesClassIDByRuntime(t *testing.T) {
	baseRuntime := testSession().Runtime
	otherRuntime := discovery.SessionRuntime{
		Source:  discovery.DiscoverySourceHostProcess,
		HostPID: 4343,
		Name:    "edge-b",
	}

	planForRuntime := func(t *testing.T, runtime discovery.SessionRuntime) Plan {
		t.Helper()

		plan, err := (Planner{}).Plan(limiter.Action{
			Kind: limiter.ActionInspect,
			Subject: limiter.Subject{
				Kind:  policy.TargetKindIP,
				Value: "203.0.113.10",
				Binding: limiter.RuntimeBinding{
					Runtime: runtime,
				},
			},
		}, Scope{
			Device:    "eth0",
			Direction: DirectionUpload,
		})
		if err != nil {
			t.Fatalf("expected inspect plan to succeed, got %v", err)
		}

		return plan
	}

	left := planForRuntime(t, baseRuntime)
	right := planForRuntime(t, otherRuntime)

	if left.Handles.ClassID == right.Handles.ClassID {
		t.Fatalf("expected identical ips on different runtimes to derive different class ids, got %q and %q", left.Handles.ClassID, right.Handles.ClassID)
	}
}

func TestPlannerPlanRemoveUsesAppliedReference(t *testing.T) {
	desired := testDesiredState(t, policy.TargetKindOutbound, 4096, 0)
	action := limiter.Action{
		Kind:    limiter.ActionRemove,
		Subject: desired.Subject,
		Applied: []limiter.AppliedState{
			{
				Mode:      limiter.DesiredModeLimit,
				Subject:   desired.Subject,
				Limits:    desired.Limits,
				Driver:    "tc",
				Reference: "1:2a",
			},
		},
	}

	plan, err := (Planner{}).Plan(action, Scope{
		Device:    "eth0",
		Direction: DirectionUpload,
	})
	if err != nil {
		t.Fatalf("expected remove plan to succeed, got %v", err)
	}

	if len(plan.Steps) != 1 {
		t.Fatalf("expected one remove step, got %#v", plan.Steps)
	}
	if got := plan.Steps[0].Command.Args[len(plan.Steps[0].Command.Args)-1]; got != "1:2a" {
		t.Fatalf("expected remove plan to use applied class reference, got %q", got)
	}
}

func TestPlannerPlanRemoveDeletesDirectIPAttachmentBeforeClass(t *testing.T) {
	desired := testDesiredState(t, policy.TargetKindIP, 4096, 0)
	action := limiter.Action{
		Kind:    limiter.ActionRemove,
		Subject: desired.Subject,
		Applied: []limiter.AppliedState{
			{
				Mode:      limiter.DesiredModeLimit,
				Subject:   desired.Subject,
				Limits:    desired.Limits,
				Driver:    "tc",
				Reference: "1:2a",
			},
		},
	}

	plan, err := (Planner{}).Plan(action, Scope{
		Device:    "eth0",
		Direction: DirectionUpload,
	})
	if err != nil {
		t.Fatalf("expected ip remove plan to succeed, got %v", err)
	}

	if len(plan.Steps) != 3 {
		t.Fatalf("expected explicit rule cleanup plus class delete, got %#v", plan.Steps)
	}
	if plan.Steps[0].Name != "delete-direct-attachment-1" ||
		plan.Steps[1].Name != "delete-direct-attachment-2" ||
		plan.Steps[2].Name != "delete-class" {
		t.Fatalf("expected explicit rule cleanup before class delete, got %#v", plan.Steps)
	}
}

func TestPlannerPlanRemoveWithoutObservedSpecificIPStateRemovesUnlimitedAndLimitRules(t *testing.T) {
	subject := testDesiredState(t, policy.TargetKindIP, 4096, 0).Subject
	action := limiter.Action{
		Kind:    limiter.ActionRemove,
		Subject: subject,
	}
	scope := Scope{
		Device:    "eth0",
		Direction: DirectionUpload,
	}

	plan, err := (Planner{}).Plan(action, scope)
	if err != nil {
		t.Fatalf("expected ip remove plan without observed state to succeed, got %v", err)
	}

	binding, err := BindSubject(subject)
	if err != nil {
		t.Fatalf("expected ip binding to succeed, got %v", err)
	}
	unlimitedExecution, err := BuildDirectAttachmentExecution(binding, scope, limiter.DesiredModeUnlimited, "")
	if err != nil {
		t.Fatalf("expected unlimited direct attachment execution to build, got %v", err)
	}
	limitExecution, err := BuildDirectAttachmentExecution(binding, scope, limiter.DesiredModeLimit, plan.Handles.ClassID)
	if err != nil {
		t.Fatalf("expected limit direct attachment execution to build, got %v", err)
	}

	if len(plan.Steps) != 3 {
		t.Fatalf("expected unlimited cleanup, limit cleanup, and class delete steps, got %#v", plan.Steps)
	}
	if got := strings.Join(plan.Steps[0].Command.Args, " "); !strings.Contains(got, fmt.Sprintf("pref %d", unlimitedExecution.Rules[0].Preference)) {
		t.Fatalf("expected first cleanup step to target the unlimited pass rule, got %q", got)
	}
	if got := strings.Join(plan.Steps[1].Command.Args, " "); !strings.Contains(got, fmt.Sprintf("pref %d", limitExecution.Rules[0].Preference)) {
		t.Fatalf("expected second cleanup step to target the explicit limit rule, got %q", got)
	}
	if plan.Steps[2].Name != "delete-class" {
		t.Fatalf("expected class delete after explicit rule cleanup, got %#v", plan.Steps)
	}
}

func TestPlannerPlanRemoveObservedSpecificIPUnlimitedDeletesBothExplicitRulesWithoutClass(t *testing.T) {
	desired := testDesiredStateForPolicy(t, policy.Policy{
		Name:   "ip-unlimited",
		Effect: policy.EffectExclude,
		Target: policy.Target{
			Kind:  policy.TargetKindIP,
			Value: "203.0.113.10",
		},
	})
	action := limiter.Action{
		Kind:    limiter.ActionRemove,
		Subject: desired.Subject,
		Applied: []limiter.AppliedState{
			{
				Mode:    limiter.DesiredModeUnlimited,
				Subject: desired.Subject,
				Driver:  "tc",
			},
		},
	}
	scope := Scope{
		Device:    "eth0",
		Direction: DirectionUpload,
	}

	plan, err := (Planner{}).Plan(action, scope)
	if err != nil {
		t.Fatalf("expected specific ip unlimited remove plan to succeed, got %v", err)
	}

	binding, err := BindSubject(desired.Subject)
	if err != nil {
		t.Fatalf("expected ip binding to succeed, got %v", err)
	}
	unlimitedExecution, err := BuildDirectAttachmentExecution(binding, scope, limiter.DesiredModeUnlimited, "")
	if err != nil {
		t.Fatalf("expected unlimited direct attachment execution to build, got %v", err)
	}
	limitExecution, err := BuildDirectAttachmentExecution(binding, scope, limiter.DesiredModeLimit, plan.Handles.ClassID)
	if err != nil {
		t.Fatalf("expected limit direct attachment execution to build, got %v", err)
	}

	if len(plan.Steps) != 2 {
		t.Fatalf("expected explicit unlimited and limit cleanup steps only, got %#v", plan.Steps)
	}
	if got := strings.Join(plan.Steps[0].Command.Args, " "); !strings.Contains(got, fmt.Sprintf("pref %d", unlimitedExecution.Rules[0].Preference)) {
		t.Fatalf("expected first cleanup step to target the unlimited pass rule, got %q", got)
	}
	if got := strings.Join(plan.Steps[1].Command.Args, " "); !strings.Contains(got, fmt.Sprintf("pref %d", limitExecution.Rules[0].Preference)) {
		t.Fatalf("expected second cleanup step to target the explicit limit rule, got %q", got)
	}
	for _, step := range plan.Steps {
		if step.Name == "delete-class" {
			t.Fatalf("expected unlimited-only remove plan to avoid class deletion, got %#v", plan.Steps)
		}
	}
}

func TestPlannerPlanRemoveDeletesDirectIPv6AttachmentBeforeClass(t *testing.T) {
	subject := limiter.Subject{
		Kind:  policy.TargetKindIP,
		Value: "2001:db8::10",
		Binding: limiter.RuntimeBinding{
			Runtime: testSession().Runtime,
		},
	}
	action := limiter.Action{
		Kind:    limiter.ActionRemove,
		Subject: subject,
		Applied: []limiter.AppliedState{
			{
				Mode:    limiter.DesiredModeLimit,
				Subject: subject,
				Limits: policy.LimitPolicy{
					Upload: &policy.RateLimit{BytesPerSecond: 4096},
				},
				Driver:    "tc",
				Reference: "1:2a",
			},
		},
	}

	plan, err := (Planner{}).Plan(action, Scope{
		Device:    "eth0",
		Direction: DirectionUpload,
	})
	if err != nil {
		t.Fatalf("expected ipv6 remove plan to succeed, got %v", err)
	}

	if len(plan.Steps) != 3 {
		t.Fatalf("expected ipv6 explicit rule cleanup plus class delete, got %#v", plan.Steps)
	}
	if got := strings.Join(plan.Steps[0].Command.Args, " "); !strings.Contains(got, "protocol ipv6") {
		t.Fatalf("expected ipv6 unlimited cleanup command, got %q", got)
	}
	if got := strings.Join(plan.Steps[1].Command.Args, " "); !strings.Contains(got, "protocol ipv6") {
		t.Fatalf("expected ipv6 direct attachment cleanup command, got %q", got)
	}
}

func TestAppendRootQDiscCleanupAppendsDeleteRootStep(t *testing.T) {
	desired := testDesiredState(t, policy.TargetKindOutbound, 2048, 0)
	action := limiter.Action{
		Kind:    limiter.ActionRemove,
		Subject: desired.Subject,
		Applied: []limiter.AppliedState{
			{
				Mode:      limiter.DesiredModeLimit,
				Subject:   desired.Subject,
				Limits:    desired.Limits,
				Driver:    "tc",
				Reference: "1:2a",
			},
		},
	}

	plan, err := (Planner{}).Plan(action, Scope{
		Device:    "eth0",
		Direction: DirectionUpload,
	})
	if err != nil {
		t.Fatalf("expected remove plan to succeed, got %v", err)
	}

	plan, err = AppendRootQDiscCleanup(plan)
	if err != nil {
		t.Fatalf("expected root qdisc cleanup append to succeed, got %v", err)
	}

	if len(plan.Steps) != 2 {
		t.Fatalf("expected class delete plus qdisc delete, got %#v", plan.Steps)
	}
	if plan.Steps[1].Name != "delete-root-qdisc" {
		t.Fatalf("unexpected cleanup step: %#v", plan.Steps[1])
	}
	expectedArgs := []string{"qdisc", "del", "dev", "eth0", "root"}
	for index, arg := range expectedArgs {
		if plan.Steps[1].Command.Args[index] != arg {
			t.Fatalf("unexpected root cleanup command: %#v", plan.Steps[1].Command)
		}
	}
}

func TestPlannerPlanInspectBuildsShowCommands(t *testing.T) {
	desired := testDesiredState(t, policy.TargetKindOutbound, 4096, 0)
	action := limiter.Action{
		Kind:    limiter.ActionInspect,
		Subject: desired.Subject,
	}

	plan, err := (Planner{}).Plan(action, Scope{
		Device:    "eth1",
		Direction: DirectionUpload,
	})
	if err != nil {
		t.Fatalf("expected inspect plan to succeed, got %v", err)
	}

	if len(plan.Steps) != 3 {
		t.Fatalf("expected three inspect steps, got %#v", plan.Steps)
	}
	if plan.Steps[0].Command.Args[0] != "-j" || plan.Steps[2].Command.Args[1] != "filter" {
		t.Fatalf("unexpected inspect commands: %#v", plan.Steps)
	}
}

func TestPlannerPlanApplyKeepsInboundAndOutboundClassOriented(t *testing.T) {
	tests := []policy.TargetKind{
		policy.TargetKindInbound,
		policy.TargetKindOutbound,
	}

	for _, kind := range tests {
		t.Run(string(kind), func(t *testing.T) {
			desired := testDesiredState(t, kind, 2048, 0)
			action := limiter.Action{
				Kind:    limiter.ActionApply,
				Subject: desired.Subject,
				Desired: &desired,
			}

			plan, err := (Planner{}).Plan(action, Scope{
				Device:    "eth0",
				Direction: DirectionUpload,
			})
			if err != nil {
				t.Fatalf("expected %s apply plan to succeed, got %v", kind, err)
			}

			if plan.AttachmentExecution.Readiness != BindingReadinessUnavailable {
				t.Fatalf("expected unavailable direct attachment execution, got %#v", plan.AttachmentExecution)
			}
			if len(plan.AttachmentExecution.Rules) != 0 {
				t.Fatalf("expected no direct attachment rules, got %#v", plan.AttachmentExecution)
			}
			if len(plan.Steps) != 2 {
				t.Fatalf("expected class-oriented qdisc/class steps only, got %#v", plan.Steps)
			}
		})
	}
}

func TestPlannerPlanRejectsMissingDirectionalLimit(t *testing.T) {
	desired := testDesiredState(t, policy.TargetKindIP, 1024, 0)
	action := limiter.Action{
		Kind:    limiter.ActionApply,
		Subject: desired.Subject,
		Desired: &desired,
	}

	_, err := (Planner{}).Plan(action, Scope{
		Device:    "eth0",
		Direction: DirectionDownload,
	})
	if err == nil {
		t.Fatal("expected missing download limit to fail planning")
	}
}

func TestPlannerPlanReconcileReturnsNoOpForMatchingState(t *testing.T) {
	desired := testDesiredState(t, policy.TargetKindOutbound, 2048, 0)
	action := limiter.Action{
		Kind:    limiter.ActionReconcile,
		Subject: desired.Subject,
		Desired: &desired,
		Applied: []limiter.AppliedState{
			{
				Mode:    limiter.DesiredModeLimit,
				Subject: desired.Subject,
				Limits:  desired.Limits,
				Driver:  "tc",
			},
		},
	}

	plan, err := (Planner{}).Plan(action, Scope{
		Device:    "eth0",
		Direction: DirectionUpload,
	})
	if err != nil {
		t.Fatalf("expected reconcile plan to succeed, got %v", err)
	}

	if !plan.NoOp {
		t.Fatalf("expected reconcile plan to be a no-op, got %#v", plan)
	}
	if len(plan.Steps) != 0 {
		t.Fatalf("expected no-op reconcile plan to avoid commands, got %#v", plan.Steps)
	}
}

func TestPlannerPlanReconcileReturnsNoOpForMatchingUnlimitedState(t *testing.T) {
	desired := testDesiredStateForPolicy(t, policy.Policy{
		Name:   "ip-unlimited",
		Effect: policy.EffectExclude,
		Target: policy.Target{
			Kind:  policy.TargetKindIP,
			Value: "203.0.113.10",
		},
	})
	action := limiter.Action{
		Kind:    limiter.ActionReconcile,
		Subject: desired.Subject,
		Desired: &desired,
		Applied: []limiter.AppliedState{
			{
				Mode:    limiter.DesiredModeUnlimited,
				Subject: desired.Subject,
				Driver:  "tc",
			},
		},
	}

	plan, err := (Planner{}).Plan(action, Scope{
		Device:    "eth0",
		Direction: DirectionUpload,
	})
	if err != nil {
		t.Fatalf("expected unlimited reconcile plan to succeed, got %v", err)
	}

	if !plan.NoOp || len(plan.Steps) != 0 {
		t.Fatalf("expected matching unlimited state to reconcile as a no-op, got %#v", plan)
	}
}
