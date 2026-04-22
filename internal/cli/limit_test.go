package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/PdYrust/RayLimit/internal/discovery"
	"github.com/PdYrust/RayLimit/internal/limiter"
	"github.com/PdYrust/RayLimit/internal/policy"
	"github.com/PdYrust/RayLimit/internal/privilege"
	"github.com/PdYrust/RayLimit/internal/tc"
)

type stubTCStateInspector struct {
	snapshot tc.Snapshot
	results  []tc.Result
	err      error
	calls    int
}

func (s *stubTCStateInspector) Inspect(_ context.Context, req tc.InspectRequest) (tc.Snapshot, []tc.Result, error) {
	s.calls++

	snapshot := s.snapshot
	if snapshot.Device == "" {
		snapshot.Device = req.Device
	}

	return snapshot, append([]tc.Result(nil), s.results...), s.err
}

type stubSessionEvidenceProvider struct {
	result discovery.SessionEvidenceResult
	err    error
	calls  int
}

func (s *stubSessionEvidenceProvider) ObserveSessions(_ context.Context, runtime discovery.SessionRuntime) (discovery.SessionEvidenceResult, error) {
	s.calls++

	result := s.result
	if strings.TrimSpace(result.Provider) == "" {
		result.Provider = "xray_api"
	}
	if !result.Runtime.Source.Valid() {
		result.Runtime = runtime
	}

	return result, s.err
}

type stubTCRunner struct {
	commands  []tc.Command
	results   []tc.Result
	err       error
	failOnRun int
	calls     int
}

func (s *stubTCRunner) Run(_ context.Context, command tc.Command) (tc.Result, error) {
	s.calls++
	s.commands = append(s.commands, command)
	if s.err != nil && (s.failOnRun == 0 || s.calls == s.failOnRun) {
		result := tc.Result{
			Command: command,
			Error:   s.err.Error(),
		}
		s.results = append(s.results, result)
		return result, s.err
	}

	result := tc.Result{Command: command}
	s.results = append(s.results, result)
	return result, nil
}

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

func testSessionEvidence(runtime discovery.SessionRuntime, clientIPs ...string) discovery.SessionEvidenceResult {
	evidence := make([]discovery.SessionEvidence, 0, len(clientIPs))
	for index, clientIP := range clientIPs {
		evidence = append(evidence, discovery.SessionEvidence{
			Runtime: runtime,
			Session: discovery.Session{
				ID:      "session-" + strings.TrimSpace(clientIP) + "-" + strings.TrimSpace(string(rune('a'+index))),
				Runtime: runtime,
				Client: discovery.SessionClient{
					IP: clientIP,
				},
			},
			Confidence: discovery.SessionEvidenceConfidenceHigh,
			Note:       "observed via test evidence",
		})
	}

	return discovery.SessionEvidenceResult{
		Provider: "xray_api",
		Runtime:  runtime,
		Evidence: evidence,
	}
}

func testLimitRuntimeTarget() discovery.RuntimeTarget {
	return discovery.RuntimeTarget{
		Source: discovery.DiscoverySourceHostProcess,
		Identity: discovery.RuntimeIdentity{
			Name: "edge-a",
		},
		HostProcess: &discovery.HostProcessCandidate{PID: 4242},
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

func testSpecificIPPlan(t *testing.T, clientIP string, direction tc.Direction, rate int64) tc.Plan {
	t.Helper()

	desired := testLimitDesiredState(t, discovery.Session{
		Runtime: testLimitSession().Runtime,
		Client: discovery.SessionClient{
			IP: clientIP,
		},
	}, policy.Policy{
		Name: "specific-ip-limit",
		Target: policy.Target{
			Kind:  policy.TargetKindIP,
			Value: clientIP,
		},
		Limits: limitPolicyForDirection(direction, rate),
	})

	plan, err := (tc.Planner{}).Plan(limiter.Action{
		Kind:    limiter.ActionApply,
		Subject: desired.Subject,
		Desired: &desired,
	}, tc.Scope{
		Device:    "eth0",
		Direction: direction,
	})
	if err != nil {
		t.Fatalf("expected specific ip plan to succeed, got %v", err)
	}

	return plan
}

func testSpecificIPPlansSnapshot(device string, rate int64, plans ...tc.Plan) tc.Snapshot {
	snapshot := tc.Snapshot{
		Device: device,
	}
	if len(plans) == 0 {
		return snapshot
	}

	snapshot.QDiscs = []tc.QDiscState{{
		Kind:   "htb",
		Handle: plans[0].Handles.RootHandle,
		Parent: "root",
	}}
	for _, plan := range plans {
		protocol, _ := describeClientIPIdentity(plan.AttachmentExecution.Rules[0].Identity.Value)
		snapshot.Classes = append(snapshot.Classes, tc.ClassState{
			Kind:               "htb",
			ClassID:            plan.Handles.ClassID,
			Parent:             plan.Handles.RootHandle,
			RateBytesPerSecond: rate,
		})
		snapshot.Filters = append(snapshot.Filters, tc.FilterState{
			Kind:       "u32",
			Parent:     plan.Handles.RootHandle,
			Protocol:   protocol,
			Preference: plan.AttachmentExecution.Rules[0].Preference,
			FlowID:     plan.Handles.ClassID,
		})
	}

	return snapshot
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

func TestLimitTargetReportFromSelectionUsesSharedAggregationForIPAll(t *testing.T) {
	report := limitTargetReportFromSelection(limitTargetSelection{IP: "all"})

	if report.Kind != policy.TargetKindIP {
		t.Fatalf("expected ip target kind, got %#v", report)
	}
	if report.Value != "all" {
		t.Fatalf("expected ip all target value, got %#v", report)
	}
	if report.IPAggregation != policy.IPAggregationModeShared {
		t.Fatalf("expected shared ip aggregation for ip all, got %#v", report)
	}
}

func TestLimitTargetReportFromSelectionLeavesAggregationUnsetForSpecificIP(t *testing.T) {
	report := limitTargetReportFromSelection(limitTargetSelection{IP: "203.0.113.10"})

	if report.Kind != policy.TargetKindIP {
		t.Fatalf("expected ip target kind, got %#v", report)
	}
	if report.Value != "203.0.113.10" {
		t.Fatalf("expected specific ip target value, got %#v", report)
	}
	if report.IPAggregation != "" {
		t.Fatalf("expected specific ip target to leave aggregation unset, got %#v", report)
	}
}

func TestWriteLimitReportJSONUsesStructuredTargetContract(t *testing.T) {
	tests := []struct {
		name            string
		target          limitTargetReport
		wantKind        policy.TargetKind
		wantValue       string
		wantAggregation policy.IPAggregationMode
	}{
		{
			name:            "shared-ip-all",
			target:          limitTargetReportFromSelection(limitTargetSelection{IP: "all"}),
			wantKind:        policy.TargetKindIP,
			wantValue:       "all",
			wantAggregation: policy.IPAggregationModeShared,
		},
		{
			name: "future-per-ip",
			target: limitTargetReport{
				Kind:          policy.TargetKindIP,
				Value:         "all",
				IPAggregation: policy.IPAggregationModePerIP,
			},
			wantKind:        policy.TargetKindIP,
			wantValue:       "all",
			wantAggregation: policy.IPAggregationModePerIP,
		},
		{
			name:            "specific-ip",
			target:          limitTargetReportFromSelection(limitTargetSelection{IP: "203.0.113.10"}),
			wantKind:        policy.TargetKindIP,
			wantValue:       "203.0.113.10",
			wantAggregation: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			report := limitReport{
				Mode:      "dry-run",
				Operation: limitOperationApply,
				Target:    tt.target,
				Decision: &limitDecisionReport{
					Kind:   limiter.DecisionNoOp,
					Reason: "already matches",
				},
			}

			var output bytes.Buffer
			if err := writeLimitReport(&output, discovery.OutputFormatJSON, report); err != nil {
				t.Fatalf("expected json report write to succeed, got %v", err)
			}

			var decoded map[string]any
			if err := json.Unmarshal(output.Bytes(), &decoded); err != nil {
				t.Fatalf("expected json report to decode, got %v", err)
			}

			if _, exists := decoded["target_kind"]; exists {
				t.Fatalf("expected flat target_kind field to be removed, got %v", decoded["target_kind"])
			}
			if _, exists := decoded["target_value"]; exists {
				t.Fatalf("expected flat target_value field to be removed, got %v", decoded["target_value"])
			}

			target, ok := decoded["target"].(map[string]any)
			if !ok {
				t.Fatalf("expected structured target object, got %#v", decoded["target"])
			}
			if kind, ok := target["kind"].(string); !ok || kind != string(tt.wantKind) {
				t.Fatalf("expected target kind %q, got %#v", tt.wantKind, target["kind"])
			}
			if value, ok := target["value"].(string); !ok || value != tt.wantValue {
				t.Fatalf("expected target value %q, got %#v", tt.wantValue, target["value"])
			}

			aggregation, exists := target["ip_aggregation"]
			if tt.wantAggregation == "" {
				if exists {
					t.Fatalf("expected ip aggregation to be omitted, got %#v", aggregation)
				}
				return
			}
			if !exists {
				t.Fatalf("expected ip aggregation %q to be present", tt.wantAggregation)
			}
			if got, ok := aggregation.(string); !ok || got != string(tt.wantAggregation) {
				t.Fatalf("expected ip aggregation %q, got %#v", tt.wantAggregation, aggregation)
			}
		})
	}
}

func TestWriteLimitTextUsesStructuredTargetContract(t *testing.T) {
	report := limitReport{
		Mode:      "dry-run",
		Operation: limitOperationApply,
		Target: limitTargetReport{
			Kind:          policy.TargetKindIP,
			Value:         "all",
			IPAggregation: policy.IPAggregationModeShared,
		},
		Decision: &limitDecisionReport{
			Kind:   limiter.DecisionNoOp,
			Reason: "already matches",
		},
	}

	var output strings.Builder
	writeLimitText(&output, report)

	got := output.String()
	if !strings.Contains(got, "Target: ip all\n") {
		t.Fatalf("expected structured target report to render as ip all, got %q", got)
	}
	if !strings.Contains(got, "IP aggregation: shared\n") {
		t.Fatalf("expected shared ip aggregation text output, got %q", got)
	}
}

func TestWriteLimitTextOmitsIPAggregationForSpecificIP(t *testing.T) {
	report := limitReport{
		Mode:      "dry-run",
		Operation: limitOperationApply,
		Target: limitTargetReport{
			Kind:  policy.TargetKindIP,
			Value: "203.0.113.10",
		},
		Decision: &limitDecisionReport{
			Kind:   limiter.DecisionNoOp,
			Reason: "already matches",
		},
	}

	var output strings.Builder
	writeLimitText(&output, report)

	if strings.Contains(output.String(), "IP aggregation:") {
		t.Fatalf("expected specific ip text output to omit aggregation details, got %q", output.String())
	}
}

func TestWriteLimitTextUsesReplacePlanLabelForReconcilePlans(t *testing.T) {
	desired := testLimitDesiredState(t, testLimitSession(), policy.Policy{
		Name: "specific-ip-limit",
		Target: policy.Target{
			Kind:  policy.TargetKindIP,
			Value: "203.0.113.10",
		},
		Limits: policy.LimitPolicy{
			Upload: &policy.RateLimit{BytesPerSecond: 2048},
		},
	})
	applied := limiter.AppliedState{
		Mode:    limiter.DesiredModeLimit,
		Subject: desired.Subject,
		Limits: policy.LimitPolicy{
			Upload: &policy.RateLimit{BytesPerSecond: 1024},
		},
		Driver: "tc",
	}
	plan, err := (tc.Planner{}).Plan(limiter.Action{
		Kind:    limiter.ActionReconcile,
		Subject: desired.Subject,
		Desired: &desired,
		Applied: []limiter.AppliedState{applied},
	}, tc.Scope{
		Device:    "eth0",
		Direction: tc.DirectionUpload,
	})
	if err != nil {
		t.Fatalf("expected reconcile plan to succeed, got %v", err)
	}

	report := limitReport{
		Mode:      "dry-run",
		Operation: limitOperationApply,
		Target: limitTargetReport{
			Kind:  policy.TargetKindIP,
			Value: "203.0.113.10",
		},
		Decision: &limitDecisionReport{
			Kind:   limiter.DecisionReplace,
			Reason: "observed applied state differs from the desired state",
		},
		Plan: &plan,
	}

	var output strings.Builder
	writeLimitText(&output, report)

	rendered := output.String()
	if !strings.Contains(rendered, "Planned action: replace\n") {
		t.Fatalf("expected reconcile plans to render as replace in text output, got %q", rendered)
	}
	if strings.Contains(rendered, "Planned action: reconcile\n") {
		t.Fatalf("expected raw reconcile action label to stay hidden in text output, got %q", rendered)
	}
}

func TestLimitReportLogFieldsUseStructuredTargetContract(t *testing.T) {
	report := limitReport{
		Mode:      "execute",
		Operation: limitOperationApply,
		Target: limitTargetReport{
			Kind:          policy.TargetKindIP,
			Value:         "all",
			IPAggregation: policy.IPAggregationModeShared,
		},
	}

	rendered := renderLogFields(report.logFields())
	if !strings.Contains(rendered, `mode=execute`) {
		t.Fatalf("expected report log fields to include mode, got %q", rendered)
	}
	if !strings.Contains(rendered, `operation=limit`) {
		t.Fatalf("expected report log fields to include operation, got %q", rendered)
	}
	if !strings.Contains(rendered, `target="ip all"`) {
		t.Fatalf("expected report log fields to include structured target, got %q", rendered)
	}
	if !strings.Contains(rendered, `ip_aggregation=shared`) {
		t.Fatalf("expected report log fields to include shared aggregation, got %q", rendered)
	}
}

func TestLimitReportLogFieldsKeepZeroPerIPDecisionCounts(t *testing.T) {
	report := limitReport{
		Mode:      "execute",
		Operation: limitOperationApply,
		Target: limitTargetReport{
			Kind:          policy.TargetKindIP,
			Value:         "all",
			IPAggregation: policy.IPAggregationModePerIP,
		},
		PerIPExpansion: &limitPerIPExpansionReport{
			State:          discovery.SessionEvidenceStateAvailable,
			ReconcileState: limitPerIPReconcileStateObservedManagedState,
			DecisionSummary: &limitPerIPDecisionSummary{
				NoOp:    0,
				Apply:   2,
				Replace: 0,
				Remove:  0,
			},
		},
	}

	rendered := renderLogFields(report.logFields())
	for _, fragment := range []string{
		`per_ip_no_op_count=0`,
		`per_ip_apply_count=2`,
		`per_ip_replace_count=0`,
		`per_ip_remove_count=0`,
	} {
		if !strings.Contains(rendered, fragment) {
			t.Fatalf("expected report log fields to include %q, got %q", fragment, rendered)
		}
	}
}

func TestRunLimitTextOutputUsesSharedAggregationContract(t *testing.T) {
	service := &stubDiscoveryService{
		result: discovery.Result{
			Targets: []discovery.RuntimeTarget{testLimitRuntimeTarget()},
		},
	}
	inspector := &stubTCStateInspector{
		err: errors.New("tc unavailable"),
	}
	sessionEvidence := &stubSessionEvidenceProvider{}
	app := NewApp(service)
	app.tcInspector = inspector
	app.sessionEvidence = sessionEvidence

	var stdout bytes.Buffer
	var stderr bytes.Buffer

	exitCode := app.Run([]string{"limit", "--pid", "4242", "--ip", "all", "--device", "eth0", "--direction", "upload", "--rate", "2048"}, &stdout, &stderr)

	if exitCode != 0 {
		t.Fatalf("expected exit code 0, got %d with stderr %q", exitCode, stderr.String())
	}
	if !strings.Contains(stdout.String(), "Target: ip all\n") {
		t.Fatalf("expected structured target text output, got %q", stdout.String())
	}
	if !strings.Contains(stdout.String(), "IP aggregation: shared\n") {
		t.Fatalf("expected shared aggregation text output, got %q", stdout.String())
	}
	if stderr.Len() != 0 {
		t.Fatalf("expected no diagnostics for dry-run output, got %q", stderr.String())
	}
	if inspector.calls != 1 {
		t.Fatalf("expected tc inspection to be called once, got %d", inspector.calls)
	}
	if sessionEvidence.calls != 0 {
		t.Fatalf("expected shared path to avoid live per_ip evidence lookup, got %d calls", sessionEvidence.calls)
	}
}

func TestRunLimitJSONOutputUsesSharedAggregationContract(t *testing.T) {
	service := &stubDiscoveryService{
		result: discovery.Result{
			Targets: []discovery.RuntimeTarget{testLimitRuntimeTarget()},
		},
	}
	inspector := &stubTCStateInspector{
		err: errors.New("tc unavailable"),
	}
	app := NewApp(service)
	app.tcInspector = inspector

	var stdout bytes.Buffer
	var stderr bytes.Buffer

	exitCode := app.Run([]string{"limit", "--pid", "4242", "--ip", "all", "--device", "eth0", "--direction", "upload", "--rate", "2048", "--format", "json"}, &stdout, &stderr)

	if exitCode != 0 {
		t.Fatalf("expected exit code 0, got %d with stderr %q", exitCode, stderr.String())
	}
	if stderr.Len() != 0 {
		t.Fatalf("expected no diagnostics for dry-run json output, got %q", stderr.String())
	}

	var payload map[string]any
	if err := json.Unmarshal(stdout.Bytes(), &payload); err != nil {
		t.Fatalf("expected json output to decode, got %v", err)
	}

	if _, exists := payload["target_kind"]; exists {
		t.Fatalf("expected flat target_kind field to be absent, got %v", payload["target_kind"])
	}
	if _, exists := payload["target_value"]; exists {
		t.Fatalf("expected flat target_value field to be absent, got %v", payload["target_value"])
	}

	target, ok := payload["target"].(map[string]any)
	if !ok {
		t.Fatalf("expected structured target object, got %#v", payload["target"])
	}
	if kind, ok := target["kind"].(string); !ok || kind != string(policy.TargetKindIP) {
		t.Fatalf("expected target kind ip, got %#v", target["kind"])
	}
	if value, ok := target["value"].(string); !ok || value != "all" {
		t.Fatalf("expected target value all, got %#v", target["value"])
	}
	if aggregation, ok := target["ip_aggregation"].(string); !ok || aggregation != string(policy.IPAggregationModeShared) {
		t.Fatalf("expected shared ip aggregation, got %#v", target["ip_aggregation"])
	}
}

func TestLimitDirectAttachmentReportFromPlanUsesBindingReadinessForIPAllPerIP(t *testing.T) {
	desired := testLimitDesiredState(t, testLimitSession(), policy.Policy{
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
	plan, err := (tc.Planner{}).Plan(limiter.Action{
		Kind:    limiter.ActionApply,
		Subject: desired.Subject,
		Desired: &desired,
	}, tc.Scope{
		Device:    "eth0",
		Direction: tc.DirectionUpload,
	})
	if err != nil {
		t.Fatalf("expected per_ip plan to succeed, got %v", err)
	}

	report := limitDirectAttachmentReportFromPlan(plan)

	if report.ShapingReadiness != tc.BindingReadinessPartial {
		t.Fatalf("expected per_ip shaping readiness to follow binding readiness, got %#v", report)
	}
	if report.AttachmentReadiness != tc.BindingReadinessPartial {
		t.Fatalf("expected per_ip attachment readiness to remain partial, got %#v", report)
	}
	if report.AttachmentExecutionReadiness != tc.BindingReadinessUnavailable {
		t.Fatalf("expected per_ip attachment execution to remain unavailable, got %#v", report)
	}
	if !strings.Contains(report.Note, "per-client class fanout") {
		t.Fatalf("expected per_ip direct attachment note to explain the planning gap, got %#v", report)
	}
}

func TestLimitPerIPClientIPsNormalizesDeduplicatesAndSortsDeterministically(t *testing.T) {
	result := testSessionEvidence(
		testLimitSession().Runtime,
		"203.0.113.10",
		"2001:0db8::10",
		"::ffff:203.0.113.10",
		"192.0.2.15",
		"2001:db8::10",
	)

	clientIPs := limitPerIPClientIPs(result)

	expected := []string{"192.0.2.15", "2001:db8::10", "203.0.113.10"}
	if len(clientIPs) != len(expected) {
		t.Fatalf("expected %d concrete client IPs, got %#v", len(expected), clientIPs)
	}
	for index, want := range expected {
		if clientIPs[index] != want {
			t.Fatalf("expected client ip %q at index %d, got %#v", want, index, clientIPs)
		}
	}
}

func TestRunLimitPerIPDryRunShowsConcreteExpansion(t *testing.T) {
	service := &stubDiscoveryService{
		result: discovery.Result{
			Targets: []discovery.RuntimeTarget{testLimitRuntimeTarget()},
		},
	}
	sessionEvidence := &stubSessionEvidenceProvider{
		result: testSessionEvidence(
			testLimitSession().Runtime,
			"203.0.113.10",
			"2001:0db8::10",
			"::ffff:203.0.113.10",
			"192.0.2.15",
		),
	}
	app := NewApp(service)
	app.tcInspector = &stubTCStateInspector{
		snapshot: tc.Snapshot{Device: "eth0"},
	}
	app.sessionEvidence = sessionEvidence

	var stdout bytes.Buffer
	var stderr bytes.Buffer

	exitCode := app.Run(
		[]string{"limit", "--pid", "4242", "--ip", "all", "--ip-aggregation", "per_ip", "--device", "eth0", "--direction", "upload", "--rate", "2048"},
		&stdout,
		&stderr,
	)

	if exitCode != 0 {
		t.Fatalf("expected exit code 0, got %d with stderr %q", exitCode, stderr.String())
	}
	rendered := stdout.String()
	for _, fragment := range []string{
		"Target: ip all\n",
		"IP aggregation: per_ip\n",
		"Per-IP evidence provider: xray_api\n",
		"Per-IP evidence state: available\n",
		"Per-IP reconcile state: no_observed_managed_state\n",
		"Visible client IPs: 3\n",
		"  1. 192.0.2.15\n",
		"  2. 2001:db8::10\n",
		"  3. 203.0.113.10\n",
		"Expanded targets:\n",
		"  1. ip 192.0.2.15\n",
		"  2. ip 2001:db8::10\n",
		"  3. ip 203.0.113.10\n",
		"Observed applied states: 0\n",
		"Desired managed objects: 3\n",
		"Observed managed objects: 0\n",
		"Outcome: plan ready\n",
		"Work summary: Planned 3 command(s).\n",
		"match ip src 192.0.2.15/32",
		"match ip6 src 2001:db8::10/128",
		"match ip src 203.0.113.10/32",
	} {
		if !strings.Contains(rendered, fragment) {
			t.Fatalf("expected dry-run per_ip output to contain %q, got %q", fragment, rendered)
		}
	}
	if stderr.Len() != 0 {
		t.Fatalf("expected no diagnostic output for dry-run per_ip expansion, got %q", stderr.String())
	}
	if sessionEvidence.calls != 1 {
		t.Fatalf("expected one live evidence lookup, got %d", sessionEvidence.calls)
	}
}

func TestRunLimitPerIPJSONOutputUsesExpandedSpecificIPPlans(t *testing.T) {
	service := &stubDiscoveryService{
		result: discovery.Result{
			Targets: []discovery.RuntimeTarget{testLimitRuntimeTarget()},
		},
	}
	app := NewApp(service)
	app.tcInspector = &stubTCStateInspector{
		snapshot: tc.Snapshot{Device: "eth0"},
	}
	app.sessionEvidence = &stubSessionEvidenceProvider{
		result: testSessionEvidence(
			testLimitSession().Runtime,
			"203.0.113.10",
			"192.0.2.15",
		),
	}

	var stdout bytes.Buffer
	var stderr bytes.Buffer

	exitCode := app.Run(
		[]string{"limit", "--pid", "4242", "--ip", "all", "--ip-aggregation", "per_ip", "--device", "eth0", "--direction", "upload", "--rate", "2048", "--format", "json"},
		&stdout,
		&stderr,
	)

	if exitCode != 0 {
		t.Fatalf("expected exit code 0, got %d with stderr %q", exitCode, stderr.String())
	}
	if stderr.Len() != 0 {
		t.Fatalf("expected no diagnostics for dry-run json per_ip output, got %q", stderr.String())
	}

	var payload map[string]any
	if err := json.Unmarshal(stdout.Bytes(), &payload); err != nil {
		t.Fatalf("expected per_ip json output to decode, got %v", err)
	}

	target := payload["target"].(map[string]any)
	if aggregation, ok := target["ip_aggregation"].(string); !ok || aggregation != string(policy.IPAggregationModePerIP) {
		t.Fatalf("expected per_ip top-level target aggregation, got %#v", target["ip_aggregation"])
	}
	expansion, ok := payload["per_ip_expansion"].(map[string]any)
	if !ok {
		t.Fatalf("expected per_ip expansion payload, got %#v", payload["per_ip_expansion"])
	}
	if state, ok := expansion["state"].(string); !ok || state != string(discovery.SessionEvidenceStateAvailable) {
		t.Fatalf("expected available per_ip expansion state, got %#v", expansion["state"])
	}
	if reconcileState, ok := expansion["reconcile_state"].(string); !ok || reconcileState != string(limitPerIPReconcileStateNoObservedManaged) {
		t.Fatalf("expected no_observed_managed_state reconcile state, got %#v", expansion["reconcile_state"])
	}
	decisionSummary, ok := expansion["decision_summary"].(map[string]any)
	if !ok {
		t.Fatalf("expected grouped per_ip decision summary, got %#v", expansion["decision_summary"])
	}
	if noOpCount, ok := decisionSummary["no_op"].(float64); !ok || int(noOpCount) != 0 {
		t.Fatalf("expected no_op decision count of 0, got %#v", decisionSummary["no_op"])
	}
	if applyCount, ok := decisionSummary["apply"].(float64); !ok || int(applyCount) != 2 {
		t.Fatalf("expected apply decision count of 2, got %#v", decisionSummary["apply"])
	}
	if replaceCount, ok := decisionSummary["replace"].(float64); !ok || int(replaceCount) != 0 {
		t.Fatalf("expected replace decision count of 0, got %#v", decisionSummary["replace"])
	}
	if removeCount, ok := decisionSummary["remove"].(float64); !ok || int(removeCount) != 0 {
		t.Fatalf("expected remove decision count of 0, got %#v", decisionSummary["remove"])
	}
	if _, exists := payload["observation"]; exists {
		t.Fatalf("expected top-level observation to be omitted for per_ip expansion output, got %#v", payload["observation"])
	}
	if _, exists := payload["decision"]; exists {
		t.Fatalf("expected top-level decision to be omitted for per_ip expansion output, got %#v", payload["decision"])
	}
	clientIPs, ok := expansion["client_ips"].([]any)
	if !ok || len(clientIPs) != 2 {
		t.Fatalf("expected two concrete client IPs, got %#v", expansion["client_ips"])
	}
	if clientIPs[0] != "192.0.2.15" || clientIPs[1] != "203.0.113.10" {
		t.Fatalf("expected deterministic concrete client IP ordering, got %#v", clientIPs)
	}
	entries, ok := expansion["entries"].([]any)
	if !ok || len(entries) != 2 {
		t.Fatalf("expected two per_ip entries, got %#v", expansion["entries"])
	}
	firstTarget := entries[0].(map[string]any)["target"].(map[string]any)
	if value, ok := firstTarget["value"].(string); !ok || value != "192.0.2.15" {
		t.Fatalf("expected first expanded target to reuse specific ip planning, got %#v", firstTarget)
	}
	firstEntry := entries[0].(map[string]any)
	if _, ok := firstEntry["observation"].(map[string]any); !ok {
		t.Fatalf("expected concrete per_ip entry observation payload, got %#v", firstEntry["observation"])
	}
	if _, ok := firstEntry["decision"].(map[string]any); !ok {
		t.Fatalf("expected concrete per_ip entry decision payload, got %#v", firstEntry["decision"])
	}
	if applied, exists := firstEntry["applied"]; exists {
		t.Fatalf("expected first dry-run entry to omit empty applied state, got %#v", applied)
	}
	reconcileInput, ok := firstEntry["reconcile_input"].(map[string]any)
	if !ok {
		t.Fatalf("expected grouped reconcile input payload, got %#v", firstEntry["reconcile_input"])
	}
	desiredManaged := reconcileInput["desired"].(map[string]any)
	observedManaged := reconcileInput["observed"].(map[string]any)
	if desiredObjects, ok := desiredManaged["objects"].([]any); !ok || len(desiredObjects) != 3 {
		t.Fatalf("expected three desired managed objects for the first entry, got %#v", desiredManaged["objects"])
	}
	if observedObjects, exists := observedManaged["objects"]; exists {
		t.Fatalf("expected zero observed managed objects for the first entry, got %#v", observedObjects)
	}
	firstResults, ok := firstEntry["results"].([]any)
	if !ok || len(firstResults) != 3 {
		t.Fatalf("expected grouped dry-run results for first concrete entry, got %#v", firstEntry["results"])
	}
	results, ok := payload["results"].([]any)
	if !ok || len(results) != 6 {
		t.Fatalf("expected aggregated dry-run results across all concrete entries, got %#v", payload["results"])
	}
}

func TestRunLimitPerIPJSONOutputReportsPartialObservedStateDeterministically(t *testing.T) {
	service := &stubDiscoveryService{
		result: discovery.Result{
			Targets: []discovery.RuntimeTarget{testLimitRuntimeTarget()},
		},
	}
	firstPlan := testSpecificIPPlan(t, "192.0.2.15", tc.DirectionUpload, 2048)
	app := NewApp(service)
	app.tcInspector = &stubTCStateInspector{
		snapshot: tc.Snapshot{
			Device: "eth0",
			QDiscs: []tc.QDiscState{{
				Kind:   "htb",
				Handle: firstPlan.Handles.RootHandle,
				Parent: "root",
			}},
			Classes: []tc.ClassState{{
				Kind:               "htb",
				ClassID:            firstPlan.Handles.ClassID,
				Parent:             firstPlan.Handles.RootHandle,
				RateBytesPerSecond: 2048,
			}},
			Filters: []tc.FilterState{{
				Kind:       "u32",
				Parent:     firstPlan.Handles.RootHandle,
				Protocol:   "ip",
				Preference: firstPlan.AttachmentExecution.Rules[0].Preference,
				FlowID:     firstPlan.Handles.ClassID,
			}},
		},
	}
	app.sessionEvidence = &stubSessionEvidenceProvider{
		result: testSessionEvidence(
			testLimitSession().Runtime,
			"203.0.113.10",
			"192.0.2.15",
		),
	}

	var stdout bytes.Buffer
	var stderr bytes.Buffer

	exitCode := app.Run(
		[]string{"limit", "--pid", "4242", "--ip", "all", "--ip-aggregation", "per_ip", "--device", "eth0", "--direction", "upload", "--rate", "2048", "--format", "json"},
		&stdout,
		&stderr,
	)

	if exitCode != 0 {
		t.Fatalf("expected exit code 0, got %d with stderr %q", exitCode, stderr.String())
	}
	if stderr.Len() != 0 {
		t.Fatalf("expected no diagnostics for partial observed-state preview, got %q", stderr.String())
	}

	var payload map[string]any
	if err := json.Unmarshal(stdout.Bytes(), &payload); err != nil {
		t.Fatalf("expected partial observed-state json output to decode, got %v", err)
	}

	expansion := payload["per_ip_expansion"].(map[string]any)
	if reconcileState, ok := expansion["reconcile_state"].(string); !ok || reconcileState != string(limitPerIPReconcileStatePartialObservedState) {
		t.Fatalf("expected partial_observed_state reconcile state, got %#v", expansion["reconcile_state"])
	}
	entries := expansion["entries"].([]any)
	firstEntry := entries[0].(map[string]any)
	secondEntry := entries[1].(map[string]any)
	firstApplied, ok := firstEntry["applied"].([]any)
	if !ok || len(firstApplied) != 1 {
		t.Fatalf("expected first concrete entry to recover one applied state, got %#v", firstEntry["applied"])
	}
	if secondApplied, exists := secondEntry["applied"]; exists {
		t.Fatalf("expected second concrete entry to omit empty applied state, got %#v", secondApplied)
	}
	firstReconcile := firstEntry["reconcile_input"].(map[string]any)
	if observed := firstReconcile["observed"].(map[string]any)["objects"].([]any); len(observed) != 3 {
		t.Fatalf("expected first entry to recover three observed managed objects, got %#v", firstReconcile["observed"])
	}
	secondReconcile := secondEntry["reconcile_input"].(map[string]any)
	if observed := secondReconcile["observed"].(map[string]any)["objects"].([]any); len(observed) != 1 {
		t.Fatalf("expected second entry to keep only the shared root qdisc object, got %#v", secondReconcile["observed"])
	}
}

func TestRunLimitPerIPDryRunShowsAllNoOpReconcileSummary(t *testing.T) {
	service := &stubDiscoveryService{
		result: discovery.Result{
			Targets: []discovery.RuntimeTarget{testLimitRuntimeTarget()},
		},
	}
	firstPlan := testSpecificIPPlan(t, "192.0.2.15", tc.DirectionUpload, 2048)
	secondPlan := testSpecificIPPlan(t, "203.0.113.10", tc.DirectionUpload, 2048)
	app := NewApp(service)
	app.tcInspector = &stubTCStateInspector{
		snapshot: testSpecificIPPlansSnapshot("eth0", 2048, firstPlan, secondPlan),
	}
	app.sessionEvidence = &stubSessionEvidenceProvider{
		result: testSessionEvidence(
			testLimitSession().Runtime,
			"203.0.113.10",
			"192.0.2.15",
		),
	}

	var stdout bytes.Buffer
	var stderr bytes.Buffer

	exitCode := app.Run(
		[]string{"limit", "--pid", "4242", "--ip", "all", "--ip-aggregation", "per_ip", "--device", "eth0", "--direction", "upload", "--rate", "2048"},
		&stdout,
		&stderr,
	)

	if exitCode != 0 {
		t.Fatalf("expected exit code 0, got %d with stderr %q", exitCode, stderr.String())
	}
	rendered := stdout.String()
	for _, fragment := range []string{
		"Per-IP reconcile state: observed_managed_state\n",
		"Decision summary: 2 no-op, 0 apply, 0 replace, 0 remove\n",
		"Outcome: no changes\n",
	} {
		if !strings.Contains(rendered, fragment) {
			t.Fatalf("expected all-no-op per_ip output to contain %q, got %q", fragment, rendered)
		}
	}
	if strings.Count(rendered, "Reconcile decision: no_op\n") != 2 {
		t.Fatalf("expected two no_op decisions, got %q", rendered)
	}
	if strings.Contains(rendered, "Planned action:") {
		t.Fatalf("expected all-no-op per_ip output to avoid planned actions, got %q", rendered)
	}
}

func TestRunLimitPerIPDryRunShowsMixedReconcileDecisionsDeterministically(t *testing.T) {
	service := &stubDiscoveryService{
		result: discovery.Result{
			Targets: []discovery.RuntimeTarget{testLimitRuntimeTarget()},
		},
	}
	firstPlan := testSpecificIPPlan(t, "192.0.2.15", tc.DirectionUpload, 2048)
	secondPlan := testSpecificIPPlan(t, "203.0.113.10", tc.DirectionUpload, 2048)
	app := NewApp(service)
	app.tcInspector = &stubTCStateInspector{
		snapshot: tc.Snapshot{
			Device: "eth0",
			QDiscs: []tc.QDiscState{{
				Kind:   "htb",
				Handle: firstPlan.Handles.RootHandle,
				Parent: "root",
			}},
			Classes: []tc.ClassState{
				{
					Kind:               "htb",
					ClassID:            firstPlan.Handles.ClassID,
					Parent:             firstPlan.Handles.RootHandle,
					RateBytesPerSecond: 2048,
				},
				{
					Kind:               "htb",
					ClassID:            secondPlan.Handles.ClassID,
					Parent:             secondPlan.Handles.RootHandle,
					RateBytesPerSecond: 1024,
				},
			},
			Filters: []tc.FilterState{
				{
					Kind:       "u32",
					Parent:     firstPlan.Handles.RootHandle,
					Protocol:   "ip",
					Preference: firstPlan.AttachmentExecution.Rules[0].Preference,
					FlowID:     firstPlan.Handles.ClassID,
				},
				{
					Kind:       "u32",
					Parent:     secondPlan.Handles.RootHandle,
					Protocol:   "ip",
					Preference: secondPlan.AttachmentExecution.Rules[0].Preference,
					FlowID:     secondPlan.Handles.ClassID,
				},
			},
		},
	}
	app.sessionEvidence = &stubSessionEvidenceProvider{
		result: testSessionEvidence(
			testLimitSession().Runtime,
			"203.0.113.11",
			"192.0.2.15",
			"203.0.113.10",
		),
	}

	var stdout bytes.Buffer
	var stderr bytes.Buffer

	exitCode := app.Run(
		[]string{"limit", "--pid", "4242", "--ip", "all", "--ip-aggregation", "per_ip", "--device", "eth0", "--direction", "upload", "--rate", "2048"},
		&stdout,
		&stderr,
	)

	if exitCode != 0 {
		t.Fatalf("expected exit code 0, got %d with stderr %q", exitCode, stderr.String())
	}
	rendered := stdout.String()
	for _, fragment := range []string{
		"Decision summary: 1 no-op, 1 apply, 1 replace, 0 remove\n",
		"Planned action: replace\n",
		"Planned action: apply\n",
	} {
		if !strings.Contains(rendered, fragment) {
			t.Fatalf("expected mixed per_ip reconcile output to contain %q, got %q", fragment, rendered)
		}
	}
	firstIndex := strings.Index(rendered, "  1. ip 192.0.2.15\n")
	secondIndex := strings.Index(rendered, "  2. ip 203.0.113.10\n")
	thirdIndex := strings.Index(rendered, "  3. ip 203.0.113.11\n")
	if !(firstIndex >= 0 && secondIndex > firstIndex && thirdIndex > secondIndex) {
		t.Fatalf("expected deterministic expanded IP ordering, got %q", rendered)
	}
	if !strings.Contains(rendered[firstIndex:secondIndex], "Reconcile decision: no_op\n") {
		t.Fatalf("expected first expanded entry to remain no_op, got %q", rendered)
	}
	if !strings.Contains(rendered[secondIndex:thirdIndex], "Reconcile decision: replace\n") {
		t.Fatalf("expected second expanded entry to require replace, got %q", rendered)
	}
	if !strings.Contains(rendered[thirdIndex:], "Reconcile decision: apply\n") {
		t.Fatalf("expected third expanded entry to require apply, got %q", rendered)
	}
}

func TestRunLimitPerIPDryRunShowsReapplyPlannedActionWhenAttachmentIsMissing(t *testing.T) {
	service := &stubDiscoveryService{
		result: discovery.Result{
			Targets: []discovery.RuntimeTarget{testLimitRuntimeTarget()},
		},
	}
	plan := testSpecificIPPlan(t, "203.0.113.10", tc.DirectionUpload, 2048)
	app := NewApp(service)
	app.tcInspector = &stubTCStateInspector{
		snapshot: tc.Snapshot{
			Device: "eth0",
			QDiscs: []tc.QDiscState{{
				Kind:   "htb",
				Handle: plan.Handles.RootHandle,
				Parent: "root",
			}},
			Classes: []tc.ClassState{{
				Kind:               "htb",
				ClassID:            plan.Handles.ClassID,
				Parent:             plan.Handles.RootHandle,
				RateBytesPerSecond: 2048,
			}},
		},
	}
	app.sessionEvidence = &stubSessionEvidenceProvider{
		result: testSessionEvidence(
			testLimitSession().Runtime,
			"203.0.113.10",
		),
	}

	var stdout bytes.Buffer
	var stderr bytes.Buffer

	exitCode := app.Run(
		[]string{"limit", "--pid", "4242", "--ip", "all", "--ip-aggregation", "per_ip", "--device", "eth0", "--direction", "upload", "--rate", "2048"},
		&stdout,
		&stderr,
	)

	if exitCode != 0 {
		t.Fatalf("expected exit code 0, got %d with stderr %q", exitCode, stderr.String())
	}
	rendered := stdout.String()
	for _, fragment := range []string{
		"Reconcile decision: apply\n",
		"Decision reason: matching direct class already satisfies the requested rate, but the expected direct attachment rules were not observed; reapply the class and concrete attachment rules\n",
		"Planned action: apply (reapply)\n",
	} {
		if !strings.Contains(rendered, fragment) {
			t.Fatalf("expected reapply per_ip output to contain %q, got %q", fragment, rendered)
		}
	}
}

func TestRunLimitPerIPExecuteRunsConcreteSpecificIPPlans(t *testing.T) {
	service := &stubDiscoveryService{
		result: discovery.Result{
			Targets: []discovery.RuntimeTarget{testLimitRuntimeTarget()},
		},
	}
	runner := &stubTCRunner{}
	app := NewApp(service)
	app.tcInspector = &stubTCStateInspector{
		snapshot: tc.Snapshot{Device: "eth0"},
	}
	app.sessionEvidence = &stubSessionEvidenceProvider{
		result: testSessionEvidence(
			testLimitSession().Runtime,
			"203.0.113.10",
			"192.0.2.15",
		),
	}
	app.tcRunner = runner
	app.privilegeStatus = func() privilege.Status {
		return privilege.Status{EUID: 0, IsRoot: true}
	}

	var stdout bytes.Buffer
	var stderr bytes.Buffer

	exitCode := app.Run(
		[]string{"limit", "--pid", "4242", "--ip", "all", "--ip-aggregation", "per_ip", "--device", "eth0", "--direction", "upload", "--rate", "2048", "--execute", "--format", "json"},
		&stdout,
		&stderr,
	)

	if exitCode != 0 {
		t.Fatalf("expected exit code 0, got %d with stderr %q", exitCode, stderr.String())
	}
	if stderr.Len() != 0 {
		t.Fatalf("expected no diagnostics for concrete per_ip execute path, got %q", stderr.String())
	}
	if len(runner.commands) != 6 {
		t.Fatalf("expected two concrete specific-ip plans with three commands each, got %#v", runner.commands)
	}

	filterCommands := make([]string, 0, 2)
	for _, command := range runner.commands {
		if len(command.Args) == 0 || command.Args[0] != "filter" {
			continue
		}
		filterCommands = append(filterCommands, strings.Join(command.Args, " "))
	}
	if len(filterCommands) != 2 {
		t.Fatalf("expected two concrete direct attachment filter commands, got %#v", runner.commands)
	}
	if !strings.Contains(filterCommands[0], "match ip src 192.0.2.15/32") {
		t.Fatalf("expected first concrete filter to target the first deterministic client ip, got %#v", filterCommands)
	}
	if !strings.Contains(filterCommands[1], "match ip src 203.0.113.10/32") {
		t.Fatalf("expected second concrete filter to target the second deterministic client ip, got %#v", filterCommands)
	}

	var payload map[string]any
	if err := json.Unmarshal(stdout.Bytes(), &payload); err != nil {
		t.Fatalf("expected execute json output to decode, got %v", err)
	}
	results, ok := payload["results"].([]any)
	if !ok || len(results) != 6 {
		t.Fatalf("expected aggregated execute results for every concrete command, got %#v", payload["results"])
	}
	expansion := payload["per_ip_expansion"].(map[string]any)
	entries := expansion["entries"].([]any)
	if len(entries) != 2 {
		t.Fatalf("expected grouped execute entries, got %#v", expansion["entries"])
	}
	for index, rawEntry := range entries {
		entry := rawEntry.(map[string]any)
		entryResults, ok := entry["results"].([]any)
		if !ok || len(entryResults) != 3 {
			t.Fatalf("expected three grouped execute results for entry %d, got %#v", index, entry["results"])
		}
	}
}

func TestRunLimitPerIPRemoveDryRunShowsConcreteCleanup(t *testing.T) {
	service := &stubDiscoveryService{
		result: discovery.Result{
			Targets: []discovery.RuntimeTarget{testLimitRuntimeTarget()},
		},
	}
	firstPlan := testSpecificIPPlan(t, "192.0.2.15", tc.DirectionUpload, 2048)
	secondPlan := testSpecificIPPlan(t, "203.0.113.10", tc.DirectionUpload, 2048)
	app := NewApp(service)
	app.tcInspector = &stubTCStateInspector{
		snapshot: testSpecificIPPlansSnapshot("eth0", 2048, firstPlan, secondPlan),
	}
	app.sessionEvidence = &stubSessionEvidenceProvider{
		result: testSessionEvidence(
			testLimitSession().Runtime,
			"203.0.113.10",
			"192.0.2.15",
		),
	}

	var stdout bytes.Buffer
	var stderr bytes.Buffer

	exitCode := app.Run(
		[]string{"limit", "--pid", "4242", "--ip", "all", "--ip-aggregation", "per_ip", "--device", "eth0", "--direction", "upload", "--remove"},
		&stdout,
		&stderr,
	)

	if exitCode != 0 {
		t.Fatalf("expected exit code 0, got %d with stderr %q", exitCode, stderr.String())
	}
	rendered := stdout.String()
	for _, fragment := range []string{
		"Requested removal: explicit upload rule set on eth0\n",
		"Per-IP evidence state: available\n",
		"Per-IP reconcile state: observed_managed_state\n",
		"Per-IP expansion note: expanded the requested per_ip remove into 2 concrete client IP target(s) using current live Xray session evidence; concrete work and cleanup stay limited to the client IPs currently proven by that evidence\n",
		"qdisc del dev eth0 root",
		"Outcome: plan ready\n",
	} {
		if !strings.Contains(rendered, fragment) {
			t.Fatalf("expected per_ip remove dry-run output to contain %q, got %q", fragment, rendered)
		}
	}
	if strings.Count(rendered, "Reconcile decision: remove\n") != 2 {
		t.Fatalf("expected two concrete remove decisions, got %q", rendered)
	}
	if strings.Count(rendered, "qdisc del dev eth0 root") != 1 {
		t.Fatalf("expected one shared root cleanup command, got %q", rendered)
	}
	if stderr.Len() != 0 {
		t.Fatalf("expected no diagnostics for per_ip remove dry-run, got %q", stderr.String())
	}
}

func TestRunLimitPerIPRemoveDryRunShowsMixedRemoveAndNoOpSummary(t *testing.T) {
	service := &stubDiscoveryService{
		result: discovery.Result{
			Targets: []discovery.RuntimeTarget{testLimitRuntimeTarget()},
		},
	}
	plan := testSpecificIPPlan(t, "192.0.2.15", tc.DirectionUpload, 2048)
	app := NewApp(service)
	app.tcInspector = &stubTCStateInspector{
		snapshot: tc.Snapshot{
			Device: "eth0",
			QDiscs: []tc.QDiscState{{
				Kind:   "htb",
				Handle: plan.Handles.RootHandle,
				Parent: "root",
			}},
			Classes: []tc.ClassState{{
				Kind:               "htb",
				ClassID:            plan.Handles.ClassID,
				Parent:             plan.Handles.RootHandle,
				RateBytesPerSecond: 2048,
			}},
			Filters: []tc.FilterState{{
				Kind:       "u32",
				Parent:     plan.Handles.RootHandle,
				Protocol:   "ip",
				Preference: plan.AttachmentExecution.Rules[0].Preference,
				FlowID:     plan.Handles.ClassID,
			}},
		},
	}
	app.sessionEvidence = &stubSessionEvidenceProvider{
		result: testSessionEvidence(
			testLimitSession().Runtime,
			"203.0.113.10",
			"192.0.2.15",
		),
	}

	var stdout bytes.Buffer
	var stderr bytes.Buffer

	exitCode := app.Run(
		[]string{"limit", "--pid", "4242", "--ip", "all", "--ip-aggregation", "per_ip", "--device", "eth0", "--direction", "upload", "--remove"},
		&stdout,
		&stderr,
	)

	if exitCode != 0 {
		t.Fatalf("expected exit code 0, got %d with stderr %q", exitCode, stderr.String())
	}
	rendered := stdout.String()
	for _, fragment := range []string{
		"Decision summary: 1 no-op, 0 apply, 0 replace, 1 remove\n",
		"Planned action: remove\n",
		"Cleanup scope: class plus root qdisc\n",
	} {
		if !strings.Contains(rendered, fragment) {
			t.Fatalf("expected mixed per_ip remove output to contain %q, got %q", fragment, rendered)
		}
	}
	if strings.Count(rendered, "Reconcile decision: remove\n") != 1 {
		t.Fatalf("expected one remove decision, got %q", rendered)
	}
	if strings.Count(rendered, "Reconcile decision: no_op\n") != 1 {
		t.Fatalf("expected one no_op decision, got %q", rendered)
	}
}

func TestRunLimitPerIPRemoveExecuteRunsConcreteCleanupWithOneSharedRootDelete(t *testing.T) {
	service := &stubDiscoveryService{
		result: discovery.Result{
			Targets: []discovery.RuntimeTarget{testLimitRuntimeTarget()},
		},
	}
	firstPlan := testSpecificIPPlan(t, "192.0.2.15", tc.DirectionUpload, 2048)
	secondPlan := testSpecificIPPlan(t, "203.0.113.10", tc.DirectionUpload, 2048)
	runner := &stubTCRunner{}
	app := NewApp(service)
	app.tcInspector = &stubTCStateInspector{
		snapshot: testSpecificIPPlansSnapshot("eth0", 2048, firstPlan, secondPlan),
	}
	app.sessionEvidence = &stubSessionEvidenceProvider{
		result: testSessionEvidence(
			testLimitSession().Runtime,
			"203.0.113.10",
			"192.0.2.15",
		),
	}
	app.tcRunner = runner
	app.privilegeStatus = func() privilege.Status {
		return privilege.Status{EUID: 0, IsRoot: true}
	}

	var stdout bytes.Buffer
	var stderr bytes.Buffer

	exitCode := app.Run(
		[]string{"limit", "--pid", "4242", "--ip", "all", "--ip-aggregation", "per_ip", "--device", "eth0", "--direction", "upload", "--remove", "--execute", "--format", "json"},
		&stdout,
		&stderr,
	)

	if exitCode != 0 {
		t.Fatalf("expected exit code 0, got %d with stderr %q", exitCode, stderr.String())
	}
	if stderr.Len() != 0 {
		t.Fatalf("expected no diagnostics for per_ip remove execute path, got %q", stderr.String())
	}
	if len(runner.commands) != 7 {
		t.Fatalf("expected two concrete remove plans plus one shared root cleanup, got %#v", runner.commands)
	}
	if got := strings.Join(runner.commands[len(runner.commands)-1].Args, " "); got != "qdisc del dev eth0 root" {
		t.Fatalf("expected final command to delete the shared root qdisc, got %#v", runner.commands)
	}
	rootDeletes := 0
	for _, command := range runner.commands {
		if len(command.Args) != 5 {
			continue
		}
		if strings.Join(command.Args, " ") == "qdisc del dev eth0 root" {
			rootDeletes++
		}
	}
	if rootDeletes != 1 {
		t.Fatalf("expected one shared root delete command, got %#v", runner.commands)
	}

	var payload map[string]any
	if err := json.Unmarshal(stdout.Bytes(), &payload); err != nil {
		t.Fatalf("expected per_ip remove execute json output to decode, got %v", err)
	}
	if results, ok := payload["results"].([]any); !ok || len(results) != 7 {
		t.Fatalf("expected aggregated remove execute results, got %#v", payload["results"])
	}
	expansion := payload["per_ip_expansion"].(map[string]any)
	if reconcileState, ok := expansion["reconcile_state"].(string); !ok || reconcileState != string(limitPerIPReconcileStateObservedManagedState) {
		t.Fatalf("expected observed_managed_state reconcile state, got %#v", expansion["reconcile_state"])
	}
	entries := expansion["entries"].([]any)
	if len(entries) != 2 {
		t.Fatalf("expected two grouped remove entries, got %#v", expansion["entries"])
	}
	firstResults, ok := entries[0].(map[string]any)["results"].([]any)
	if !ok || len(firstResults) != 3 {
		t.Fatalf("expected first remove entry to execute three commands, got %#v", entries[0])
	}
	secondResults, ok := entries[1].(map[string]any)["results"].([]any)
	if !ok || len(secondResults) != 4 {
		t.Fatalf("expected second remove entry to execute four commands including shared root cleanup, got %#v", entries[1])
	}
}

func TestRunLimitPerIPDryRunBlocksWhenLiveEvidenceIsInsufficient(t *testing.T) {
	service := &stubDiscoveryService{
		result: discovery.Result{
			Targets: []discovery.RuntimeTarget{testLimitRuntimeTarget()},
		},
	}
	app := NewApp(service)
	app.sessionEvidence = &stubSessionEvidenceProvider{
		result: discovery.SessionEvidenceResult{
			Provider: "xray_api",
			Runtime:  testLimitSession().Runtime,
			Issues: []discovery.SessionEvidenceIssue{
				{
					Code:    discovery.SessionEvidenceIssueInsufficient,
					Message: "Xray API capability was inferred, but no concrete API endpoint hint is available for live session evidence",
				},
			},
		},
	}

	var stdout bytes.Buffer
	var stderr bytes.Buffer

	exitCode := app.Run(
		[]string{"limit", "--pid", "4242", "--ip", "all", "--ip-aggregation", "per_ip", "--device", "eth0", "--direction", "upload", "--rate", "2048"},
		&stdout,
		&stderr,
	)

	if exitCode != exitCodeSuccess {
		t.Fatalf("expected exit code %d, got %d with stderr %q", exitCodeSuccess, exitCode, stderr.String())
	}
	rendered := stdout.String()
	for _, fragment := range []string{
		"Per-IP evidence state: insufficient\n",
		"Per-IP reconcile state: insufficient_evidence\n",
		"Execution status: blocked\n",
		"Outcome: blocked\n",
		"per_ip apply planning requires live client IP evidence for the selected runtime",
	} {
		if !strings.Contains(rendered, fragment) {
			t.Fatalf("expected blocked dry-run per_ip output to contain %q, got %q", fragment, rendered)
		}
	}
	if stderr.Len() != 0 {
		t.Fatalf("expected blocked dry-run preview to avoid diagnostic stderr output, got %q", stderr.String())
	}
}

func TestRunLimitPerIPDryRunReportsNoSessionsAsEmptyReconcileInput(t *testing.T) {
	service := &stubDiscoveryService{
		result: discovery.Result{
			Targets: []discovery.RuntimeTarget{testLimitRuntimeTarget()},
		},
	}
	app := NewApp(service)
	app.sessionEvidence = &stubSessionEvidenceProvider{
		result: discovery.SessionEvidenceResult{
			Provider: "xray_api",
			Runtime:  testLimitSession().Runtime,
		},
	}

	var stdout bytes.Buffer
	var stderr bytes.Buffer

	exitCode := app.Run(
		[]string{"limit", "--pid", "4242", "--ip", "all", "--ip-aggregation", "per_ip", "--device", "eth0", "--direction", "upload", "--rate", "2048"},
		&stdout,
		&stderr,
	)

	if exitCode != exitCodeSuccess {
		t.Fatalf("expected exit code %d, got %d with stderr %q", exitCodeSuccess, exitCode, stderr.String())
	}
	rendered := stdout.String()
	for _, fragment := range []string{
		"Per-IP evidence state: no_sessions\n",
		"Per-IP reconcile state: no_sessions\n",
		"Visible client IPs: none\n",
		"Outcome: no changes\n",
	} {
		if !strings.Contains(rendered, fragment) {
			t.Fatalf("expected no-sessions per_ip output to contain %q, got %q", fragment, rendered)
		}
	}
	if stderr.Len() != 0 {
		t.Fatalf("expected no diagnostics for no-sessions preview, got %q", stderr.String())
	}
}

func TestRunLimitPerIPExecuteBlocksWhenLiveEvidenceIsInsufficient(t *testing.T) {
	service := &stubDiscoveryService{
		result: discovery.Result{
			Targets: []discovery.RuntimeTarget{testLimitRuntimeTarget()},
		},
	}
	app := NewApp(service)
	app.sessionEvidence = &stubSessionEvidenceProvider{
		result: discovery.SessionEvidenceResult{
			Provider: "xray_api",
			Runtime:  testLimitSession().Runtime,
			Issues: []discovery.SessionEvidenceIssue{
				{
					Code:    discovery.SessionEvidenceIssueInsufficient,
					Message: "Xray API capability was inferred, but no concrete API endpoint hint is available for live session evidence",
				},
			},
		},
	}

	var stdout bytes.Buffer
	var stderr bytes.Buffer

	exitCode := app.Run(
		[]string{"limit", "--pid", "4242", "--ip", "all", "--ip-aggregation", "per_ip", "--device", "eth0", "--direction", "upload", "--rate", "2048", "--execute"},
		&stdout,
		&stderr,
	)

	if exitCode != exitCodeFailure {
		t.Fatalf("expected exit code %d, got %d", exitCodeFailure, exitCode)
	}
	if !strings.Contains(stdout.String(), "IP aggregation: per_ip\n") {
		t.Fatalf("expected per_ip target output, got %q", stdout.String())
	}
	if !strings.Contains(stdout.String(), "Per-IP evidence state: insufficient\n") {
		t.Fatalf("expected insufficient per_ip evidence state, got %q", stdout.String())
	}
	if !strings.Contains(stdout.String(), "Per-IP reconcile state: insufficient_evidence\n") {
		t.Fatalf("expected insufficient_evidence reconcile state, got %q", stdout.String())
	}
	if !strings.Contains(stdout.String(), "Execution status: blocked\n") {
		t.Fatalf("expected blocked per_ip execute status, got %q", stdout.String())
	}
	if !strings.Contains(stderr.String(), `ip_aggregation=per_ip`) {
		t.Fatalf("expected per_ip diagnostic logging fields, got %q", stderr.String())
	}
	if !strings.Contains(stderr.String(), `per_ip_evidence_state=insufficient`) {
		t.Fatalf("expected per_ip evidence-state logging field, got %q", stderr.String())
	}
	if !strings.Contains(stderr.String(), `per_ip_reconcile_state=insufficient_evidence`) {
		t.Fatalf("expected per_ip reconcile-state logging field, got %q", stderr.String())
	}
	if !strings.Contains(stderr.String(), "real per_ip apply execution requires live client IP evidence for the selected runtime") {
		t.Fatalf("expected per_ip execute block note, got %q", stderr.String())
	}
}

func TestRunLimitPerIPExecuteAggregatesBlockedExpandedTargetsDuringPreflight(t *testing.T) {
	service := &stubDiscoveryService{
		result: discovery.Result{
			Targets: []discovery.RuntimeTarget{testLimitRuntimeTarget()},
		},
	}
	app := NewApp(service)
	app.tcInspector = &stubTCStateInspector{
		err: errors.New("tc unavailable"),
	}
	app.sessionEvidence = &stubSessionEvidenceProvider{
		result: testSessionEvidence(
			testLimitSession().Runtime,
			"203.0.113.10",
			"192.0.2.15",
		),
	}

	var stdout bytes.Buffer
	var stderr bytes.Buffer

	exitCode := app.Run(
		[]string{"limit", "--pid", "4242", "--ip", "all", "--ip-aggregation", "per_ip", "--device", "eth0", "--direction", "upload", "--rate", "2048", "--execute"},
		&stdout,
		&stderr,
	)

	if exitCode != exitCodeFailure {
		t.Fatalf("expected exit code %d, got %d", exitCodeFailure, exitCode)
	}
	rendered := stdout.String()
	for _, fragment := range []string{
		"Decision summary: 0 no-op, 2 apply, 0 replace, 0 remove\n",
		"  1. ip 192.0.2.15\n",
		"  2. ip 203.0.113.10\n",
		"Execution status: blocked\n",
		"Execution note: real per_ip apply execution was blocked for 2 expanded target(s):",
	} {
		if !strings.Contains(rendered, fragment) {
			t.Fatalf("expected aggregated blocked preflight output to contain %q, got %q", fragment, rendered)
		}
	}
	if !strings.Contains(stderr.String(), `error="real per_ip apply execution was blocked for 2 expanded target(s):`) {
		t.Fatalf("expected aggregated blocked execution diagnostic, got %q", stderr.String())
	}
	if !strings.Contains(stderr.String(), `per_ip_apply_count=2`) {
		t.Fatalf("expected grouped per_ip decision-count diagnostics, got %q", stderr.String())
	}
}

func TestRunLimitPerIPExecuteReportsGroupedFailureAndPartialExecution(t *testing.T) {
	service := &stubDiscoveryService{
		result: discovery.Result{
			Targets: []discovery.RuntimeTarget{testLimitRuntimeTarget()},
		},
	}
	runner := &stubTCRunner{
		err:       errors.New("tc command failed"),
		failOnRun: 4,
	}
	app := NewApp(service)
	app.tcInspector = &stubTCStateInspector{
		snapshot: tc.Snapshot{Device: "eth0"},
	}
	app.sessionEvidence = &stubSessionEvidenceProvider{
		result: testSessionEvidence(
			testLimitSession().Runtime,
			"203.0.113.10",
			"192.0.2.15",
		),
	}
	app.tcRunner = runner
	app.privilegeStatus = func() privilege.Status {
		return privilege.Status{EUID: 0, IsRoot: true}
	}

	var stdout bytes.Buffer
	var stderr bytes.Buffer

	exitCode := app.Run(
		[]string{"limit", "--pid", "4242", "--ip", "all", "--ip-aggregation", "per_ip", "--device", "eth0", "--direction", "upload", "--rate", "2048", "--execute"},
		&stdout,
		&stderr,
	)

	if exitCode != exitCodeFailure {
		t.Fatalf("expected exit code %d, got %d", exitCodeFailure, exitCode)
	}
	rendered := stdout.String()
	for _, fragment := range []string{
		"Execution status: failed\n",
		"Outcome: failed\n",
		"Execution stopped after 4 command(s).\n",
		"Outcome: executed\n",
		"Outcome: failed\n",
		"Execution stopped after 1 command(s).\n",
		"Status note: tc command failed\n",
	} {
		if !strings.Contains(rendered, fragment) {
			t.Fatalf("expected per_ip partial failure output to contain %q, got %q", fragment, rendered)
		}
	}
	if !strings.Contains(stderr.String(), `per_ip_evidence_state=available`) {
		t.Fatalf("expected per_ip available evidence logging field, got %q", stderr.String())
	}
	if !strings.Contains(stderr.String(), `per_ip_reconcile_state=no_observed_managed_state`) {
		t.Fatalf("expected no_observed_managed_state logging field, got %q", stderr.String())
	}
	if !strings.Contains(stderr.String(), `expanded_client_ip_count=2`) {
		t.Fatalf("expected expanded client count logging field, got %q", stderr.String())
	}
	if !strings.Contains(stderr.String(), `error="limit execution failed: tc command failed"`) {
		t.Fatalf("expected execute failure diagnostic detail, got %q", stderr.String())
	}
}

func TestRunLimitBlockedExecutionDiagnosticUsesStructuredTargetFields(t *testing.T) {
	service := &stubDiscoveryService{
		result: discovery.Result{
			Targets: []discovery.RuntimeTarget{testLimitRuntimeTarget()},
		},
	}
	app := NewApp(service)
	app.tcInspector = &stubTCStateInspector{
		err: errors.New("tc unavailable"),
	}

	var stdout bytes.Buffer
	var stderr bytes.Buffer

	exitCode := app.Run([]string{"limit", "--pid", "4242", "--ip", "all", "--device", "eth0", "--direction", "upload", "--rate", "2048", "--execute"}, &stdout, &stderr)

	if exitCode != exitCodeFailure {
		t.Fatalf("expected exit code %d, got %d", exitCodeFailure, exitCode)
	}
	if !strings.Contains(stdout.String(), "IP aggregation: shared\n") {
		t.Fatalf("expected shared aggregation in text output, got %q", stdout.String())
	}
	expected := "error execution: limit execution blocked | mode=execute operation=limit target=\"ip all\" ip_aggregation=shared error=\"real execution requires observed tc state; tc state inspection failed: tc unavailable; rerun with --allow-missing-tc-state to execute without observation\"\n"
	if got := stderr.String(); got != expected {
		t.Fatalf("unexpected execution diagnostic output: %q", got)
	}
}
