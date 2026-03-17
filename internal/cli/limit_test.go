package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/PdYrust/RayLimit/internal/correlation"
	"github.com/PdYrust/RayLimit/internal/discovery"
	"github.com/PdYrust/RayLimit/internal/limiter"
	"github.com/PdYrust/RayLimit/internal/policy"
	"github.com/PdYrust/RayLimit/internal/privilege"
	"github.com/PdYrust/RayLimit/internal/tc"
)

type stubTCRunner struct {
	commands []tc.Command
	result   tc.Result
	err      error
}

func (r *stubTCRunner) Run(_ context.Context, command tc.Command) (tc.Result, error) {
	r.commands = append(r.commands, command)

	result := r.result
	result.Command = command

	return result, r.err
}

type stubTCInspector struct {
	requests []tc.InspectRequest
	snapshot tc.Snapshot
	results  []tc.Result
	err      error
}

func (s *stubTCInspector) Inspect(_ context.Context, req tc.InspectRequest) (tc.Snapshot, []tc.Result, error) {
	s.requests = append(s.requests, req)
	return s.snapshot, s.results, s.err
}

type stubNftInspector struct {
	requests int
	snapshot tc.NftablesSnapshot
	results  []tc.Result
	err      error
}

func (s *stubNftInspector) Inspect(_ context.Context) (tc.NftablesSnapshot, []tc.Result, error) {
	s.requests++
	return s.snapshot, s.results, s.err
}

type stubInboundSelectorDeriver struct {
	requests []struct {
		target discovery.RuntimeTarget
		tag    string
	}
	result discovery.InboundMarkSelectorResult
	err    error
}

func (s *stubInboundSelectorDeriver) Derive(_ context.Context, target discovery.RuntimeTarget, inboundTag string) (discovery.InboundMarkSelectorResult, error) {
	s.requests = append(s.requests, struct {
		target discovery.RuntimeTarget
		tag    string
	}{target: target, tag: inboundTag})
	return s.result, s.err
}

type stubOutboundSelectorDeriver struct {
	requests []struct {
		target discovery.RuntimeTarget
		tag    string
	}
	result discovery.OutboundMarkSelectorResult
	err    error
}

func (s *stubOutboundSelectorDeriver) Derive(_ context.Context, target discovery.RuntimeTarget, outboundTag string) (discovery.OutboundMarkSelectorResult, error) {
	s.requests = append(s.requests, struct {
		target discovery.RuntimeTarget
		tag    string
	}{target: target, tag: outboundTag})
	return s.result, s.err
}

type stubUUIDCorrelator struct {
	requests []correlation.UUIDRequest
	result   correlation.UUIDResult
	err      error
}

func (s *stubUUIDCorrelator) Correlate(_ context.Context, req correlation.UUIDRequest) (correlation.UUIDResult, error) {
	s.requests = append(s.requests, req)
	return s.result, s.err
}

type stubUUIDNonIPBackendCandidateDeriver struct {
	requests []struct {
		target discovery.RuntimeTarget
		uuid   string
	}
	result discovery.UUIDNonIPBackendCandidate
	err    error
}

func (s *stubUUIDNonIPBackendCandidateDeriver) Derive(_ context.Context, target discovery.RuntimeTarget, uuid string) (discovery.UUIDNonIPBackendCandidate, error) {
	s.requests = append(s.requests, struct {
		target discovery.RuntimeTarget
		uuid   string
	}{target: target, uuid: uuid})
	return s.result, s.err
}

type stubUUIDRoutingEvidenceProvider struct {
	requests []struct {
		runtime discovery.SessionRuntime
		uuid    string
	}
	result discovery.UUIDRoutingEvidenceResult
	err    error
}

func (s *stubUUIDRoutingEvidenceProvider) ObserveUUIDRoutingEvidence(_ context.Context, runtime discovery.SessionRuntime, uuid string) (discovery.UUIDRoutingEvidenceResult, error) {
	s.requests = append(s.requests, struct {
		runtime discovery.SessionRuntime
		uuid    string
	}{runtime: runtime, uuid: uuid})
	return s.result, s.err
}

func testLimitTarget() discovery.RuntimeTarget {
	return discovery.RuntimeTarget{
		Source: discovery.DiscoverySourceHostProcess,
		Identity: discovery.RuntimeIdentity{
			Name:   "edge-a",
			Binary: "xray",
		},
		HostProcess: &discovery.HostProcessCandidate{
			PID:            1001,
			ExecutablePath: "/usr/local/bin/xray",
			CommandLine:    []string{"/usr/local/bin/xray", "run"},
		},
	}
}

func testLimitRuntime(t *testing.T, target discovery.RuntimeTarget) discovery.SessionRuntime {
	t.Helper()

	runtime, err := discovery.SessionRuntimeFromTarget(target)
	if err != nil {
		t.Fatalf("expected runtime binding to succeed, got %v", err)
	}

	return runtime
}

func testUUIDCorrelationResult(t *testing.T, target discovery.RuntimeTarget, status correlation.UUIDStatus, sessions ...discovery.Session) correlation.UUIDResult {
	t.Helper()

	return correlation.UUIDResult{
		Request: correlation.UUIDRequest{
			UUID:    "user-a",
			Runtime: testLimitRuntime(t, target),
		},
		Provider: "xray_api",
		Scope:    correlation.UUIDScopeRuntime,
		Status:   status,
		Sessions: sessions,
		EvidenceState: func() discovery.SessionEvidenceState {
			if status == correlation.UUIDStatusZeroSessions {
				return discovery.SessionEvidenceStateNoSessions
			}
			return discovery.SessionEvidenceStateAvailable
		}(),
		Confidence: func() discovery.SessionEvidenceConfidence {
			if status == correlation.UUIDStatusSingleSession || status == correlation.UUIDStatusMultipleSessions {
				return discovery.SessionEvidenceConfidenceHigh
			}
			return ""
		}(),
	}
}

func testUUIDSession(t *testing.T, target discovery.RuntimeTarget, id string) discovery.Session {
	t.Helper()

	ip := "203.0.113.10"
	switch id {
	case "conn-1":
		ip = "203.0.113.11"
	case "conn-2":
		ip = "203.0.113.12"
	case "conn-3":
		ip = "203.0.113.13"
	}

	return discovery.Session{
		ID:      id,
		Runtime: testLimitRuntime(t, target),
		Policy: discovery.SessionPolicyIdentity{
			UUID: "user-a",
		},
		Client: discovery.SessionClient{
			IP: ip,
		},
	}
}

func testUUIDAggregatePlan(
	t *testing.T,
	target discovery.RuntimeTarget,
	operation tc.UUIDAggregateOperation,
	device string,
	direction tc.Direction,
	rateBytes int64,
	cleanupRootQDisc bool,
	sessions ...discovery.Session,
) tc.UUIDAggregatePlan {
	t.Helper()

	membership, err := correlation.NewUUIDAggregateMembership(
		correlation.UUIDAggregateSubject{
			UUID:    "user-a",
			Runtime: testLimitRuntime(t, target),
		},
		sessions,
	)
	if err != nil {
		t.Fatalf("expected aggregate membership construction to succeed, got %v", err)
	}

	input := tc.UUIDAggregatePlanInput{
		Operation:        operation,
		Membership:       membership,
		Scope:            tc.Scope{Device: device, Direction: direction},
		CleanupRootQDisc: cleanupRootQDisc,
	}
	if operation == tc.UUIDAggregateOperationApply {
		input.Limits = limitPolicyForDirection(direction, rateBytes)
	}

	plan, err := (tc.Planner{}).PlanUUIDAggregate(input)
	if err != nil {
		t.Fatalf("expected aggregate plan construction to succeed, got %v", err)
	}

	return plan
}

func testUUIDRoutingEvidenceResult(
	t *testing.T,
	target discovery.RuntimeTarget,
	uuid string,
	contexts ...discovery.UUIDRoutingContext,
) discovery.UUIDRoutingEvidenceResult {
	t.Helper()

	result := discovery.UUIDRoutingEvidenceResult{
		Provider: "xray_routing_api",
		Runtime:  testLimitRuntime(t, target),
		UUID:     uuid,
		Candidate: &discovery.UUIDNonIPBackendCandidate{
			Status: discovery.UUIDNonIPBackendStatusCandidate,
			Kind:   discovery.UUIDNonIPBackendKindRoutingStatsPortClassifier,
			Reason: `readable Xray config enables RoutingService and exact user routing for UUID "user-a"; live routing contexts can already drive the concrete local-socket and client-socket UUID backends, and the next broader exact-user-safe step is a remote-socket classifier that combines local and target tuple evidence without falling back to shared client IP`,
		},
		Contexts: append([]discovery.UUIDRoutingContext(nil), contexts...),
	}
	if err := result.Validate(); err != nil {
		t.Fatalf("expected uuid routing evidence result validation to succeed, got %v", err)
	}

	return result
}

func testUUIDRoutingContext(
	t *testing.T,
	target discovery.RuntimeTarget,
	uuid string,
	network string,
	localIP string,
	localPort int,
) discovery.UUIDRoutingContext {
	t.Helper()

	context := discovery.UUIDRoutingContext{
		Runtime:    testLimitRuntime(t, target),
		UUID:       uuid,
		Network:    network,
		LocalIPs:   []string{localIP},
		LocalPort:  localPort,
		Confidence: discovery.SessionEvidenceConfidenceHigh,
		Note:       "fresh exact-user RoutingService local socket tuple",
	}
	if err := context.Validate(); err != nil {
		t.Fatalf("expected uuid routing context validation to succeed, got %v", err)
	}

	return context
}

func testUUIDClientRoutingContext(
	t *testing.T,
	target discovery.RuntimeTarget,
	uuid string,
	network string,
	clientIP string,
	clientPort int,
) discovery.UUIDRoutingContext {
	t.Helper()

	context := discovery.UUIDRoutingContext{
		Runtime:    testLimitRuntime(t, target),
		UUID:       uuid,
		Network:    network,
		SourceIPs:  []string{clientIP},
		SourcePort: clientPort,
		Confidence: discovery.SessionEvidenceConfidenceHigh,
		Note:       "fresh exact-user RoutingService client socket tuple",
	}
	if err := context.Validate(); err != nil {
		t.Fatalf("expected uuid client routing context validation to succeed, got %v", err)
	}

	return context
}

func testUUIDTargetRoutingContext(
	t *testing.T,
	target discovery.RuntimeTarget,
	uuid string,
	network string,
	targetIP string,
	targetPort int,
) discovery.UUIDRoutingContext {
	t.Helper()

	context := discovery.UUIDRoutingContext{
		Runtime:    testLimitRuntime(t, target),
		UUID:       uuid,
		Network:    network,
		TargetIPs:  []string{targetIP},
		TargetPort: targetPort,
		Confidence: discovery.SessionEvidenceConfidenceHigh,
		Note:       "fresh exact-user RoutingService remote target tuple",
	}
	if err := context.Validate(); err != nil {
		t.Fatalf("expected uuid target routing context validation to succeed, got %v", err)
	}

	return context
}

func testObservedUUIDAggregateRoutingMarkState(
	t *testing.T,
	target discovery.RuntimeTarget,
	device string,
	direction tc.Direction,
	desiredRate int64,
	localIP string,
	localPort int,
) (tc.UUIDAggregatePlan, tc.Snapshot, tc.NftablesSnapshot) {
	t.Helper()

	session := testUUIDSession(t, target, "conn-1")
	session.Client.IP = ""

	membership, err := correlation.NewUUIDAggregateMembership(
		correlation.UUIDAggregateSubject{
			UUID:    "user-a",
			Runtime: testLimitRuntime(t, target),
		},
		[]discovery.Session{session},
	)
	if err != nil {
		t.Fatalf("expected routing-backed aggregate membership construction to succeed, got %v", err)
	}

	evidence := testUUIDRoutingEvidenceResult(
		t,
		target,
		"user-a",
		testUUIDRoutingContext(t, target, "user-a", "tcp", localIP, localPort),
	)
	assessment, err := discovery.AssessUUIDRoutingEvidence(
		discovery.UUIDRoutingEvidenceSnapshot{
			Result:     evidence,
			ObservedAt: time.Now(),
		},
		discovery.RuntimeEvidencePolicy{FreshTTL: 30 * time.Second},
		time.Now(),
	)
	if err != nil {
		t.Fatalf("expected routing-backed aggregate evidence assessment to succeed, got %v", err)
	}

	plan, err := (tc.Planner{}).PlanUUIDAggregate(tc.UUIDAggregatePlanInput{
		Operation:  tc.UUIDAggregateOperationApply,
		Membership: membership,
		Scope: tc.Scope{
			Device:    device,
			Direction: direction,
		},
		Limits:                    limitPolicyForDirection(direction, desiredRate),
		RoutingEvidence:           &evidence,
		RoutingEvidenceAssessment: &assessment,
	})
	if err != nil {
		t.Fatalf("expected routing-backed aggregate apply plan to succeed, got %v", err)
	}
	if len(plan.AttachmentExecution.MarkAttachments) == 0 {
		t.Fatalf("expected routing-backed aggregate plan to expose mark attachments, got %#v", plan.AttachmentExecution)
	}

	snapshot := tc.Snapshot{
		Device: device,
		QDiscs: []tc.QDiscState{{
			Kind:   "htb",
			Handle: plan.Handles.RootHandle,
			Parent: "root",
		}},
		Classes: []tc.ClassState{{
			Kind:               "htb",
			ClassID:            plan.Handles.ClassID,
			Parent:             plan.Handles.RootHandle,
			RateBytesPerSecond: desiredRate,
		}},
	}
	nftSnapshot := tc.NftablesSnapshot{}

	shared := plan.AttachmentExecution.MarkAttachments[0]
	nftSnapshot.Tables = append(nftSnapshot.Tables, tc.NftablesTableState{
		Family: shared.Table.Family,
		Name:   shared.Table.Name,
	})
	nftSnapshot.Chains = append(nftSnapshot.Chains, tc.NftablesChainState{
		Family:   shared.Chain.Family,
		Table:    shared.Chain.Table,
		Name:     shared.Chain.Name,
		Type:     shared.Chain.Type,
		Hook:     shared.Chain.Hook,
		Priority: shared.Chain.Priority,
	})
	for index, attachment := range plan.AttachmentExecution.MarkAttachments {
		snapshot.Filters = append(snapshot.Filters, tc.FilterState{
			Kind:       "fw",
			Parent:     plan.Handles.RootHandle,
			Protocol:   attachment.Filter.Protocol,
			Preference: attachment.Filter.Preference,
			Handle: "0x" + strings.TrimPrefix(strings.ToLower(fmt.Sprintf("%x", attachment.Filter.Mark)), "0x") +
				"/0x" + strings.TrimPrefix(strings.ToLower(fmt.Sprintf("%x", attachment.Filter.Mask)), "0x"),
			FlowID: attachment.Filter.ClassID,
		})
		nftSnapshot.Rules = append(nftSnapshot.Rules, tc.NftablesRuleState{
			Family:  attachment.Chain.Family,
			Table:   attachment.Chain.Table,
			Chain:   attachment.Chain.Name,
			Handle:  uint64(index + 41),
			Comment: attachment.Rule.Comment,
		})
	}

	return plan, snapshot, nftSnapshot
}

func testLimitDesiredStateForSelection(t *testing.T, target discovery.RuntimeTarget, selection limitTargetSelection, direction tc.Direction, rateBytes int64) limiter.DesiredState {
	t.Helper()

	runtime, err := discovery.SessionRuntimeFromTarget(target)
	if err != nil {
		t.Fatalf("expected runtime binding to succeed, got %v", err)
	}

	session := discovery.Session{Runtime: runtime}
	selection.apply(&session)
	if err := session.Validate(); err != nil {
		t.Fatalf("expected session validation to succeed, got %v", err)
	}

	targetRule, err := selection.policyTarget(runtime)
	if err != nil {
		t.Fatalf("expected policy target construction to succeed, got %v", err)
	}

	evaluation, err := (policy.Evaluator{}).Evaluate([]policy.Policy{
		{
			Name:   "cli-limit-request",
			Target: targetRule,
			Limits: limitPolicyForDirection(direction, rateBytes),
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

func testLimitDesiredState(t *testing.T, target discovery.RuntimeTarget, connection string, direction tc.Direction, rateBytes int64) limiter.DesiredState {
	t.Helper()

	return testLimitDesiredStateForSelection(t, target, limitTargetSelection{Connection: connection}, direction, rateBytes)
}

func testObservedClassForSelection(t *testing.T, target discovery.RuntimeTarget, selection limitTargetSelection, device string, direction tc.Direction, desiredRate int64, observedRate int64) tc.ClassState {
	t.Helper()

	desired := testLimitDesiredStateForSelection(t, target, selection, direction, desiredRate)
	inspectPlan, err := (tc.Planner{}).Plan(limiter.Action{
		Kind:    limiter.ActionInspect,
		Subject: desired.Subject,
	}, tc.Scope{
		Device:    device,
		Direction: direction,
	})
	if err != nil {
		t.Fatalf("expected inspect plan to succeed, got %v", err)
	}

	return tc.ClassState{
		Kind:               "htb",
		ClassID:            inspectPlan.Handles.ClassID,
		Parent:             inspectPlan.Handles.RootHandle,
		RateBytesPerSecond: observedRate,
	}
}

func testParsedObservedClassSnapshotForSelection(t *testing.T, target discovery.RuntimeTarget, selection limitTargetSelection, device string, direction tc.Direction, desiredRate int64, observedRate string) tc.Snapshot {
	t.Helper()

	desired := testLimitDesiredStateForSelection(t, target, selection, direction, desiredRate)
	inspectPlan, err := (tc.Planner{}).Plan(limiter.Action{
		Kind:    limiter.ActionInspect,
		Subject: desired.Subject,
	}, tc.Scope{
		Device:    device,
		Direction: direction,
	})
	if err != nil {
		t.Fatalf("expected inspect plan to succeed, got %v", err)
	}

	snapshot, err := tc.ParseSnapshot(device, []tc.Result{
		{
			Step: "show-class",
			Stdout: fmt.Sprintf(
				`[{"kind":"htb","classid":"%s","parent":"%s","options":{"rate":"%s","ceil":"%s"}}]`,
				inspectPlan.Handles.ClassID,
				inspectPlan.Handles.RootHandle,
				observedRate,
				observedRate,
			),
		},
	})
	if err != nil {
		t.Fatalf("expected parsed observed class snapshot to succeed, got %v", err)
	}

	return snapshot
}

func testObservedClass(t *testing.T, target discovery.RuntimeTarget, connection string, device string, direction tc.Direction, desiredRate int64, observedRate int64) tc.ClassState {
	t.Helper()

	return testObservedClassForSelection(t, target, limitTargetSelection{Connection: connection}, device, direction, desiredRate, observedRate)
}

func testObservedDirectAttachmentFilterForSelection(t *testing.T, target discovery.RuntimeTarget, selection limitTargetSelection, device string, direction tc.Direction, desiredRate int64) tc.FilterState {
	t.Helper()

	desired := testLimitDesiredStateForSelection(t, target, selection, direction, desiredRate)
	inspectPlan, err := (tc.Planner{}).Plan(limiter.Action{
		Kind:    limiter.ActionInspect,
		Subject: desired.Subject,
	}, tc.Scope{
		Device:    device,
		Direction: direction,
	})
	if err != nil {
		t.Fatalf("expected inspect plan to succeed, got %v", err)
	}
	if len(inspectPlan.AttachmentExecution.Rules) == 0 {
		t.Fatalf("expected inspect plan to expose direct attachment execution rules, got %#v", inspectPlan.AttachmentExecution)
	}

	addr, err := netip.ParseAddr(inspectPlan.AttachmentExecution.Rules[0].Identity.Value)
	if err != nil {
		t.Fatalf("expected direct attachment identity to parse as an ip address, got %v", err)
	}
	protocol := "ipv6"
	if addr.Unmap().Is4() {
		protocol = "ip"
	}

	return tc.FilterState{
		Kind:       "u32",
		Parent:     inspectPlan.Handles.RootHandle,
		Protocol:   protocol,
		Preference: inspectPlan.AttachmentExecution.Rules[0].Preference,
		FlowID:     inspectPlan.Handles.ClassID,
	}
}

func testInboundSelectorResult() discovery.InboundMarkSelectorResult {
	return discovery.InboundMarkSelectorResult{
		Selector: &discovery.InboundMarkSelector{
			Tag:           "api-in",
			Network:       "tcp",
			ListenAddress: "127.0.0.1",
			Port:          8443,
			Expression:    []string{"ip", "daddr", "127.0.0.1", "tcp", "dport", "8443"},
			Description:   `tcp listener 127.0.0.1:8443 for inbound tag "api-in"`,
		},
	}
}

func testOutboundSelectorResult() discovery.OutboundMarkSelectorResult {
	return discovery.OutboundMarkSelectorResult{
		Selector: &discovery.OutboundMarkSelector{
			Tag:         "proxy-out",
			SocketMark:  513,
			Expression:  []string{"meta", "mark", "0x201"},
			Description: `configured outbound socket mark 0x201 for outbound tag "proxy-out"`,
		},
	}
}

func testObservedInboundMarkAttachmentState(t *testing.T, target discovery.RuntimeTarget, device string, direction tc.Direction, desiredRate int64) (tc.FilterState, tc.NftablesSnapshot) {
	t.Helper()

	desired := testLimitDesiredStateForSelection(t, target, limitTargetSelection{Inbound: "api-in"}, direction, desiredRate)
	inspectPlan, err := (tc.Planner{}).Plan(limiter.Action{
		Kind:    limiter.ActionInspect,
		Subject: desired.Subject,
	}, tc.Scope{
		Device:    device,
		Direction: direction,
	})
	if err != nil {
		t.Fatalf("expected inbound inspect plan to succeed, got %v", err)
	}

	execution, err := tc.BuildMarkAttachmentExecution(tc.MarkAttachmentInput{
		Identity: *inspectPlan.Binding.Identity,
		Scope: tc.Scope{
			Device:    device,
			Direction: direction,
		},
		ClassID: inspectPlan.Handles.ClassID,
		Selector: tc.MarkAttachmentSelector{
			Expression:  append([]string(nil), testInboundSelectorResult().Selector.Expression...),
			Description: testInboundSelectorResult().Selector.Description,
		},
		Confidence: tc.BindingConfidenceHigh,
	})
	if err != nil {
		t.Fatalf("expected inbound mark attachment execution to build, got %v", err)
	}

	filter := tc.FilterState{
		Kind:       "fw",
		Parent:     execution.Filter.Parent,
		Protocol:   execution.Filter.Protocol,
		Preference: execution.Filter.Preference,
		Handle:     "0x" + strings.TrimPrefix(strings.ToLower(fmt.Sprintf("%x", execution.Filter.Mark)), "0x") + "/0x" + strings.TrimPrefix(strings.ToLower(fmt.Sprintf("%x", execution.Filter.Mask)), "0x"),
		FlowID:     execution.Filter.ClassID,
	}
	nftSnapshot := tc.NftablesSnapshot{
		Tables: []tc.NftablesTableState{{
			Family: execution.Table.Family,
			Name:   execution.Table.Name,
		}},
		Chains: []tc.NftablesChainState{
			{
				Family:   execution.Chain.Family,
				Table:    execution.Chain.Table,
				Name:     execution.Chain.Name,
				Type:     execution.Chain.Type,
				Hook:     execution.Chain.Hook,
				Priority: execution.Chain.Priority,
			},
			{
				Family:   execution.RestoreChain.Family,
				Table:    execution.RestoreChain.Table,
				Name:     execution.RestoreChain.Name,
				Type:     execution.RestoreChain.Type,
				Hook:     execution.RestoreChain.Hook,
				Priority: execution.RestoreChain.Priority,
			},
		},
		Rules: []tc.NftablesRuleState{
			{
				Family:  execution.Chain.Family,
				Table:   execution.Chain.Table,
				Chain:   execution.Chain.Name,
				Handle:  17,
				Comment: execution.Rule.Comment,
			},
			{
				Family:  execution.RestoreChain.Family,
				Table:   execution.RestoreChain.Table,
				Chain:   execution.RestoreChain.Name,
				Handle:  18,
				Comment: execution.RestoreRule.Comment,
			},
		},
	}

	return filter, nftSnapshot
}

func testObservedOutboundMarkAttachmentState(t *testing.T, target discovery.RuntimeTarget, device string, direction tc.Direction, desiredRate int64) (tc.FilterState, tc.NftablesSnapshot) {
	t.Helper()

	desired := testLimitDesiredStateForSelection(t, target, limitTargetSelection{Outbound: "proxy-out"}, direction, desiredRate)
	inspectPlan, err := (tc.Planner{}).Plan(limiter.Action{
		Kind:    limiter.ActionInspect,
		Subject: desired.Subject,
	}, tc.Scope{
		Device:    device,
		Direction: direction,
	})
	if err != nil {
		t.Fatalf("expected outbound inspect plan to succeed, got %v", err)
	}

	execution, err := tc.BuildMarkAttachmentExecution(tc.MarkAttachmentInput{
		Identity: *inspectPlan.Binding.Identity,
		Scope: tc.Scope{
			Device:    device,
			Direction: direction,
		},
		ClassID: inspectPlan.Handles.ClassID,
		Selector: tc.MarkAttachmentSelector{
			Expression:  append([]string(nil), testOutboundSelectorResult().Selector.Expression...),
			Description: testOutboundSelectorResult().Selector.Description,
		},
		PacketMark: testOutboundSelectorResult().Selector.SocketMark,
		Confidence: tc.BindingConfidenceMedium,
	})
	if err != nil {
		t.Fatalf("expected outbound mark attachment execution to build, got %v", err)
	}

	filter := tc.FilterState{
		Kind:       "fw",
		Parent:     execution.Filter.Parent,
		Protocol:   execution.Filter.Protocol,
		Preference: execution.Filter.Preference,
		Handle:     "0x" + strings.TrimPrefix(strings.ToLower(fmt.Sprintf("%x", execution.Filter.Mark)), "0x") + "/0x" + strings.TrimPrefix(strings.ToLower(fmt.Sprintf("%x", execution.Filter.Mask)), "0x"),
		FlowID:     execution.Filter.ClassID,
	}
	nftSnapshot := tc.NftablesSnapshot{
		Tables: []tc.NftablesTableState{{
			Family: execution.Table.Family,
			Name:   execution.Table.Name,
		}},
		Chains: []tc.NftablesChainState{{
			Family:   execution.Chain.Family,
			Table:    execution.Chain.Table,
			Name:     execution.Chain.Name,
			Type:     execution.Chain.Type,
			Hook:     execution.Chain.Hook,
			Priority: execution.Chain.Priority,
		}},
		Rules: []tc.NftablesRuleState{{
			Family:  execution.Chain.Family,
			Table:   execution.Chain.Table,
			Chain:   execution.Chain.Name,
			Handle:  27,
			Comment: execution.Rule.Comment,
		}},
	}

	return filter, nftSnapshot
}

func testObservedRootQDisc(handle string) tc.QDiscState {
	return tc.QDiscState{
		Kind:   "htb",
		Handle: handle,
		Parent: "root",
	}
}

func testPolicyCoexistenceEvaluation(t *testing.T) policy.Evaluation {
	t.Helper()

	target := testLimitTarget()
	session := discovery.Session{
		ID:      "conn-1",
		Runtime: testLimitRuntime(t, target),
		Policy: discovery.SessionPolicyIdentity{
			UUID: "user-a",
		},
		Client: discovery.SessionClient{
			IP: "203.0.113.10",
		},
		Route: discovery.SessionRoute{
			InboundTag:  "api-in",
			OutboundTag: "direct",
		},
	}

	evaluation, err := (policy.Evaluator{}).Evaluate([]policy.Policy{
		{
			Name: "outbound-limit",
			Target: policy.Target{
				Kind:  policy.TargetKindOutbound,
				Value: "direct",
			},
			Limits: policy.LimitPolicy{
				Upload: &policy.RateLimit{BytesPerSecond: 8192},
			},
		},
		{
			Name: "ip-limit",
			Target: policy.Target{
				Kind:  policy.TargetKindIP,
				Value: "203.0.113.10",
			},
			Limits: policy.LimitPolicy{
				Upload: &policy.RateLimit{BytesPerSecond: 4096},
			},
		},
		{
			Name: "uuid-upload-tightest",
			Target: policy.Target{
				Kind:  policy.TargetKindUUID,
				Value: "user-a",
			},
			Limits: policy.LimitPolicy{
				Upload: &policy.RateLimit{BytesPerSecond: 2048},
			},
		},
		{
			Name: "uuid-download",
			Target: policy.Target{
				Kind:  policy.TargetKindUUID,
				Value: "user-a",
			},
			Limits: policy.LimitPolicy{
				Download: &policy.RateLimit{BytesPerSecond: 6144},
			},
		},
	}, session)
	if err != nil {
		t.Fatalf("expected coexistence evaluation to succeed, got %v", err)
	}

	return evaluation
}

func testPolicyExcludedCoexistenceEvaluation(t *testing.T) policy.Evaluation {
	t.Helper()

	target := testLimitTarget()
	session := discovery.Session{
		ID:      "conn-1",
		Runtime: testLimitRuntime(t, target),
		Policy: discovery.SessionPolicyIdentity{
			UUID: "user-a",
		},
		Client: discovery.SessionClient{
			IP: "203.0.113.10",
		},
		Route: discovery.SessionRoute{
			InboundTag:  "api-in",
			OutboundTag: "direct",
		},
	}

	evaluation, err := (policy.Evaluator{}).Evaluate([]policy.Policy{
		{
			Name: "outbound-limit",
			Target: policy.Target{
				Kind:  policy.TargetKindOutbound,
				Value: "direct",
			},
			Limits: policy.LimitPolicy{
				Upload: &policy.RateLimit{BytesPerSecond: 8192},
			},
		},
		{
			Name: "uuid-limit",
			Target: policy.Target{
				Kind:  policy.TargetKindUUID,
				Value: "user-a",
			},
			Limits: policy.LimitPolicy{
				Upload: &policy.RateLimit{BytesPerSecond: 4096},
			},
		},
		{
			Name: "ip-limit",
			Target: policy.Target{
				Kind:  policy.TargetKindIP,
				Value: "203.0.113.10",
			},
			Limits: policy.LimitPolicy{
				Upload: &policy.RateLimit{BytesPerSecond: 2048},
			},
		},
		{
			Name:   "uuid-exclude",
			Effect: policy.EffectExclude,
			Target: policy.Target{
				Kind:  policy.TargetKindUUID,
				Value: "user-a",
			},
		},
	}, session)
	if err != nil {
		t.Fatalf("expected excluded coexistence evaluation to succeed, got %v", err)
	}

	return evaluation
}

func TestRunLimitDryRunReportsApplyDecision(t *testing.T) {
	service := &stubDiscoveryService{
		result: discovery.Result{
			Targets: []discovery.RuntimeTarget{testLimitTarget()},
		},
	}
	inspector := &stubTCInspector{
		snapshot: tc.Snapshot{
			Device: "eth0",
		},
	}
	app := NewApp(service)
	app.tcInspector = inspector

	var stdout bytes.Buffer
	var stderr bytes.Buffer

	exitCode := app.Run([]string{
		"limit",
		"--pid", "1001",
		"--connection", "conn-1",
		"--device", "eth0",
		"--direction", "upload",
		"--rate", "2048",
	}, &stdout, &stderr)

	if exitCode != 0 {
		t.Fatalf("expected exit code 0, got %d", exitCode)
	}

	output := stdout.String()
	for _, fragment := range []string{
		"Request:",
		"Mode: dry-run",
		"Runtime: host process 1001",
		"Target: connection conn-1",
		"Plan:",
		"Observed tc state: available",
		"Reconcile decision: apply",
		"Decision reason: no applied state was observed",
		"Planned action: apply",
		"Planned commands:",
		"Outcome: preview ready",
		"No system changes were made.",
	} {
		if !strings.Contains(output, fragment) {
			t.Fatalf("expected dry-run output to contain %q, got %q", fragment, output)
		}
	}

	if len(inspector.requests) != 1 || inspector.requests[0].Device != "eth0" {
		t.Fatalf("expected inspector to run once for eth0, got %#v", inspector.requests)
	}
	if stderr.Len() != 0 {
		t.Fatalf("expected no stderr output, got %q", stderr.String())
	}
}

func TestRunLimitDryRunShowsClassOnlyAttachmentStatusForConnection(t *testing.T) {
	service := &stubDiscoveryService{
		result: discovery.Result{
			Targets: []discovery.RuntimeTarget{testLimitTarget()},
		},
	}
	inspector := &stubTCInspector{
		snapshot: tc.Snapshot{
			Device: "eth0",
		},
	}
	app := NewApp(service)
	app.tcInspector = inspector

	var stdout bytes.Buffer
	var stderr bytes.Buffer

	exitCode := app.Run([]string{
		"limit",
		"--pid", "1001",
		"--connection", "conn-1",
		"--device", "eth0",
		"--direction", "upload",
		"--rate", "2048",
	}, &stdout, &stderr)

	if exitCode != 0 {
		t.Fatalf("expected exit code 0, got %d", exitCode)
	}

	output := stdout.String()
	for _, fragment := range []string{
		"Direct shaping readiness: ready",
		"Direct attachment readiness: partial",
		"Direct attachment execution readiness: unavailable",
		"Direct attachment note: connection targets currently remain class-oriented; tc can plan class shaping and clean up observed class state, but real apply execution requires a trustworthy runtime-aware traffic classifier",
		"Direct attachment execution note: concrete direct attachment execution for connection session ids is unavailable until a trustworthy runtime-aware traffic classifier exists",
	} {
		if !strings.Contains(output, fragment) {
			t.Fatalf("expected connection direct attachment output to contain %q, got %q", fragment, output)
		}
	}
	if stderr.Len() != 0 {
		t.Fatalf("expected no stderr output, got %q", stderr.String())
	}
}

func TestWriteLimitTextShowsPolicyCoexistenceSummary(t *testing.T) {
	report := limitReport{
		Mode:        "dry-run",
		Operation:   limitOperationApply,
		Runtime:     testLimitTarget(),
		TargetKind:  policy.TargetKindUUID,
		TargetValue: "user-a",
		Scope:       tc.Scope{Device: "eth0", Direction: tc.DirectionUpload},
		RateBytes:   2048,
		PolicyEvaluation: limitPolicyEvaluationFromEvaluation(
			testPolicyCoexistenceEvaluation(t),
		),
		Observation: limitObservationReport{},
		Decision: limitDecisionReport{
			Kind:   limiter.DecisionApply,
			Reason: "test decision",
		},
	}

	var stdout bytes.Buffer
	writeLimitText(&stdout, report)

	output := stdout.String()
	for _, expected := range []string{
		"Precedence order: connection > uuid > ip > inbound > outbound",
		"Matched rules: 4 total",
		"Winning kind: uuid",
		"Effective selection reason: uuid precedence selected the effective rule set over matching ip and outbound rules; 2 winning uuid matches merged; the tightest per-direction values became effective",
		"Effective limits: upload=2048 bytes/s, download=6144 bytes/s",
		"Winning matches:",
		"uuid-upload-tightest [uuid user-a, effect=limit, precedence=4]",
		"uuid-download [uuid user-a, effect=limit, precedence=4]",
		"Non-winning matches:",
		"ip-limit [ip 203.0.113.10, effect=limit, precedence=3]",
		"outbound-limit [outbound direct, effect=limit, precedence=1]",
	} {
		if !strings.Contains(output, expected) {
			t.Fatalf("expected policy coexistence text output to contain %q, got %q", expected, output)
		}
	}
}

func TestWriteLimitTextShowsExecuteNoOpPlanSummary(t *testing.T) {
	target := testLimitTarget()
	subject := limiter.Subject{
		Kind:  policy.TargetKindIP,
		Value: "203.0.113.10",
		Binding: limiter.RuntimeBinding{
			Runtime: testLimitRuntime(t, target),
		},
	}

	report := limitReport{
		Mode:        "execute",
		Operation:   limitOperationApply,
		Runtime:     target,
		TargetKind:  policy.TargetKindIP,
		TargetValue: "203.0.113.10",
		Scope:       tc.Scope{Device: "eth0", Direction: tc.DirectionUpload},
		RateBytes:   2048,
		Observation: limitObservationReport{
			Available:       true,
			Reconcilable:    true,
			Matched:         true,
			ExpectedClassID: "1:d3e",
			ObservedClassID: "1:d3e",
		},
		Decision: limitDecisionReport{
			Kind:   limiter.DecisionReplace,
			Reason: "applied state requires reconcile planning",
		},
		Plan: &tc.Plan{
			Action: limiter.Action{Kind: limiter.ActionReconcile, Subject: subject},
			Scope:  tc.Scope{Device: "eth0", Direction: tc.DirectionUpload},
			Binding: tc.Binding{
				RequestedSubject: subject,
				EffectiveSubject: subject,
				Identity: &tc.TrafficIdentity{
					Kind:  tc.IdentityKindClientIP,
					Value: "203.0.113.10",
				},
				Readiness:  tc.BindingReadinessReady,
				Confidence: tc.BindingConfidenceHigh,
			},
			Handles: tc.Handles{RootHandle: "1:", ClassID: "1:d3e"},
			NoOp:    true,
		},
	}

	var stdout bytes.Buffer
	writeLimitText(&stdout, report)

	output := stdout.String()
	if !strings.Contains(output, "Local tc state already matches the requested limit.") {
		t.Fatalf("expected execute no-op plan summary, got %q", output)
	}
	if !strings.Contains(output, "No commands were executed.") {
		t.Fatalf("expected explicit no-command summary for execute no-op plan, got %q", output)
	}
}

func TestWriteLimitReportJSONIncludesPolicyCoexistenceSummary(t *testing.T) {
	report := limitReport{
		Mode:        "dry-run",
		Operation:   limitOperationApply,
		Runtime:     testLimitTarget(),
		TargetKind:  policy.TargetKindUUID,
		TargetValue: "user-a",
		Scope:       tc.Scope{Device: "eth0", Direction: tc.DirectionUpload},
		RateBytes:   2048,
		PolicyEvaluation: limitPolicyEvaluationFromEvaluation(
			testPolicyCoexistenceEvaluation(t),
		),
		Observation: limitObservationReport{},
		Decision: limitDecisionReport{
			Kind:   limiter.DecisionApply,
			Reason: "test decision",
		},
	}

	var stdout bytes.Buffer
	if err := writeLimitReport(&stdout, discovery.OutputFormatJSON, report); err != nil {
		t.Fatalf("expected JSON rendering to succeed, got %v", err)
	}

	var payload struct {
		PolicyEvaluation struct {
			PrecedenceOrder   string `json:"precedence_order"`
			WinningKind       string `json:"winning_kind"`
			WinningPrecedence int    `json:"winning_precedence"`
			EffectiveReason   string `json:"effective_reason"`
			Winning           []struct {
				Policy struct {
					Name string `json:"name"`
				} `json:"policy"`
			} `json:"winning"`
			NonWinning []struct {
				Policy struct {
					Name string `json:"name"`
				} `json:"policy"`
			} `json:"non_winning"`
		} `json:"policy_evaluation"`
	}
	if err := json.Unmarshal(stdout.Bytes(), &payload); err != nil {
		t.Fatalf("expected JSON output to unmarshal, got %v", err)
	}

	if payload.PolicyEvaluation.PrecedenceOrder != policy.DescribeTargetKindPrecedence() {
		t.Fatalf("unexpected precedence order in JSON payload: %#v", payload)
	}
	if payload.PolicyEvaluation.WinningKind != string(policy.TargetKindUUID) || payload.PolicyEvaluation.WinningPrecedence != policy.TargetKindUUID.Precedence() {
		t.Fatalf("unexpected winning kind payload: %#v", payload)
	}
	if len(payload.PolicyEvaluation.Winning) != 2 || len(payload.PolicyEvaluation.NonWinning) != 2 {
		t.Fatalf("unexpected winning/non-winning payload counts: %#v", payload)
	}
	if payload.PolicyEvaluation.Winning[0].Policy.Name != "uuid-upload-tightest" ||
		payload.PolicyEvaluation.Winning[1].Policy.Name != "uuid-download" {
		t.Fatalf("unexpected winning policy payload: %#v", payload)
	}
	if payload.PolicyEvaluation.NonWinning[0].Policy.Name != "ip-limit" ||
		payload.PolicyEvaluation.NonWinning[1].Policy.Name != "outbound-limit" {
		t.Fatalf("unexpected non-winning policy payload: %#v", payload)
	}
	if !strings.Contains(payload.PolicyEvaluation.EffectiveReason, "uuid precedence selected the effective rule set") {
		t.Fatalf("unexpected effective reason payload: %#v", payload)
	}
}

func TestWriteLimitTextShowsExcludedPolicyCoexistenceSummary(t *testing.T) {
	report := limitReport{
		Mode:        "dry-run",
		Operation:   limitOperationApply,
		Runtime:     testLimitTarget(),
		TargetKind:  policy.TargetKindUUID,
		TargetValue: "user-a",
		Scope:       tc.Scope{Device: "eth0", Direction: tc.DirectionUpload},
		RateBytes:   2048,
		PolicyEvaluation: limitPolicyEvaluationFromEvaluation(
			testPolicyExcludedCoexistenceEvaluation(t),
		),
		Observation: limitObservationReport{},
		Decision: limitDecisionReport{
			Kind:   limiter.DecisionNoOp,
			Reason: "winning exclude suppressed the effective limit",
		},
	}

	var stdout bytes.Buffer
	writeLimitText(&stdout, report)

	output := stdout.String()
	for _, expected := range []string{
		"Precedence order: connection > uuid > ip > inbound > outbound",
		"Matched rules: 4 total",
		"Winning kind: uuid",
		"Effective selection reason: uuid precedence selected the effective rule set over matching ip and outbound rules; exclude rules at the winning precedence suppressed 1 matching uuid limit rule",
		"Winning matches:",
		"uuid-exclude [uuid user-a, effect=exclude, precedence=4]",
		"Non-winning matches:",
		"uuid-limit [uuid user-a, effect=limit, precedence=4]",
		"ip-limit [ip 203.0.113.10, effect=limit, precedence=3]",
		"outbound-limit [outbound direct, effect=limit, precedence=1]",
	} {
		if !strings.Contains(output, expected) {
			t.Fatalf("expected excluded coexistence text output to contain %q, got %q", expected, output)
		}
	}
	if strings.Contains(output, "Effective limits:") {
		t.Fatalf("expected excluded coexistence output to omit effective limits, got %q", output)
	}
}

func TestWriteLimitReportJSONIncludesExcludedPolicyCoexistenceSummary(t *testing.T) {
	report := limitReport{
		Mode:        "dry-run",
		Operation:   limitOperationApply,
		Runtime:     testLimitTarget(),
		TargetKind:  policy.TargetKindUUID,
		TargetValue: "user-a",
		Scope:       tc.Scope{Device: "eth0", Direction: tc.DirectionUpload},
		RateBytes:   2048,
		PolicyEvaluation: limitPolicyEvaluationFromEvaluation(
			testPolicyExcludedCoexistenceEvaluation(t),
		),
		Observation: limitObservationReport{},
		Decision: limitDecisionReport{
			Kind:   limiter.DecisionNoOp,
			Reason: "winning exclude suppressed the effective limit",
		},
	}

	var stdout bytes.Buffer
	if err := writeLimitReport(&stdout, discovery.OutputFormatJSON, report); err != nil {
		t.Fatalf("expected JSON rendering to succeed, got %v", err)
	}

	var payload struct {
		PolicyEvaluation struct {
			WinningKind     string `json:"winning_kind"`
			EffectiveReason string `json:"effective_reason"`
			EffectiveLimits struct {
				Upload *struct {
					BytesPerSecond int64 `json:"bytes_per_second"`
				} `json:"upload"`
			} `json:"effective_limits"`
			Winning []struct {
				Policy struct {
					Name string `json:"name"`
				} `json:"policy"`
			} `json:"winning"`
			NonWinning []struct {
				Policy struct {
					Name string `json:"name"`
				} `json:"policy"`
			} `json:"non_winning"`
		} `json:"policy_evaluation"`
	}
	if err := json.Unmarshal(stdout.Bytes(), &payload); err != nil {
		t.Fatalf("expected JSON output to unmarshal, got %v", err)
	}

	if payload.PolicyEvaluation.WinningKind != string(policy.TargetKindUUID) {
		t.Fatalf("unexpected winning kind payload: %#v", payload)
	}
	if payload.PolicyEvaluation.EffectiveLimits.Upload != nil {
		t.Fatalf("expected excluded coexistence payload to omit effective limits, got %#v", payload)
	}
	if len(payload.PolicyEvaluation.Winning) != 1 || payload.PolicyEvaluation.Winning[0].Policy.Name != "uuid-exclude" {
		t.Fatalf("unexpected winning policy payload: %#v", payload)
	}
	if len(payload.PolicyEvaluation.NonWinning) != 3 {
		t.Fatalf("unexpected non-winning policy payload count: %#v", payload)
	}
	if payload.PolicyEvaluation.NonWinning[0].Policy.Name != "uuid-limit" ||
		payload.PolicyEvaluation.NonWinning[1].Policy.Name != "ip-limit" ||
		payload.PolicyEvaluation.NonWinning[2].Policy.Name != "outbound-limit" {
		t.Fatalf("unexpected non-winning policy payload order: %#v", payload)
	}
	if !strings.Contains(payload.PolicyEvaluation.EffectiveReason, "exclude rules at the winning precedence suppressed 1 matching uuid limit rule") {
		t.Fatalf("unexpected effective reason payload: %#v", payload)
	}
}

func TestRunLimitIPDryRunReportsApplyDecision(t *testing.T) {
	service := &stubDiscoveryService{
		result: discovery.Result{
			Targets: []discovery.RuntimeTarget{testLimitTarget()},
		},
	}
	inspector := &stubTCInspector{
		snapshot: tc.Snapshot{
			Device: "eth0",
		},
	}
	app := NewApp(service)
	app.tcInspector = inspector

	var stdout bytes.Buffer
	var stderr bytes.Buffer

	exitCode := app.Run([]string{
		"limit",
		"--pid", "1001",
		"--ip", "203.0.113.10",
		"--device", "eth0",
		"--direction", "upload",
		"--rate", "2048",
	}, &stdout, &stderr)

	if exitCode != 0 {
		t.Fatalf("expected exit code 0, got %d", exitCode)
	}

	output := stdout.String()
	for _, fragment := range []string{
		"Mode: dry-run",
		"Runtime: host process 1001",
		"Target: ip 203.0.113.10",
		"Observed tc state: available",
		"Reconcile decision: apply",
		"Decision reason: no applied state was observed",
		"Planned action: apply",
		"Planned commands:",
		"No system changes were made.",
	} {
		if !strings.Contains(output, fragment) {
			t.Fatalf("expected IP dry-run output to contain %q, got %q", fragment, output)
		}
	}
	if len(inspector.requests) != 1 || inspector.requests[0].Device != "eth0" {
		t.Fatalf("expected inspector to run once for eth0, got %#v", inspector.requests)
	}
	if stderr.Len() != 0 {
		t.Fatalf("expected no stderr output, got %q", stderr.String())
	}
}

func TestRunLimitIPDryRunShowsConcreteAttachmentRules(t *testing.T) {
	service := &stubDiscoveryService{
		result: discovery.Result{
			Targets: []discovery.RuntimeTarget{testLimitTarget()},
		},
	}
	inspector := &stubTCInspector{
		snapshot: tc.Snapshot{
			Device: "eth0",
		},
	}
	app := NewApp(service)
	app.tcInspector = inspector

	var stdout bytes.Buffer
	var stderr bytes.Buffer

	exitCode := app.Run([]string{
		"limit",
		"--pid", "1001",
		"--ip", "203.0.113.10",
		"--device", "eth0",
		"--direction", "upload",
		"--rate", "2048",
	}, &stdout, &stderr)

	if exitCode != 0 {
		t.Fatalf("expected exit code 0, got %d", exitCode)
	}

	output := stdout.String()
	for _, fragment := range []string{
		"Direct shaping readiness: ready",
		"Direct attachment readiness: ready",
		"Direct attachment execution readiness: ready",
		"Direct attachment execution rules:",
		"client_ip 203.0.113.10/32",
		"tc filter replace dev eth0",
	} {
		if !strings.Contains(output, fragment) {
			t.Fatalf("expected direct ip output to contain %q, got %q", fragment, output)
		}
	}
	if stderr.Len() != 0 {
		t.Fatalf("expected no stderr output, got %q", stderr.String())
	}
}

func TestRunLimitIPv6DryRunShowsConcreteAttachmentRulesConservatively(t *testing.T) {
	service := &stubDiscoveryService{
		result: discovery.Result{
			Targets: []discovery.RuntimeTarget{testLimitTarget()},
		},
	}
	inspector := &stubTCInspector{
		snapshot: tc.Snapshot{
			Device: "eth0",
		},
	}
	app := NewApp(service)
	app.tcInspector = inspector

	var stdout bytes.Buffer
	var stderr bytes.Buffer

	exitCode := app.Run([]string{
		"limit",
		"--pid", "1001",
		"--ip", "2001:0db8::0010",
		"--device", "eth0",
		"--direction", "upload",
		"--rate", "2048",
	}, &stdout, &stderr)

	if exitCode != 0 {
		t.Fatalf("expected exit code 0, got %d", exitCode)
	}

	output := stdout.String()
	for _, fragment := range []string{
		"Target: ip 2001:db8::10",
		"Direct attachment readiness: ready",
		"Direct attachment execution readiness: ready",
		"Direct attachment confidence: medium",
		"assumes no ipv6 extension headers",
		"client_ip 2001:db8::10/128",
		"protocol ipv6",
		"match source_ip",
		"tc filter replace dev eth0",
	} {
		if !strings.Contains(output, fragment) {
			t.Fatalf("expected ipv6 direct ip output to contain %q, got %q", fragment, output)
		}
	}
	if stderr.Len() != 0 {
		t.Fatalf("expected no stderr output, got %q", stderr.String())
	}
}

func TestRunLimitIPDryRunReportsNoOpDecision(t *testing.T) {
	target := testLimitTarget()
	service := &stubDiscoveryService{
		result: discovery.Result{
			Targets: []discovery.RuntimeTarget{target},
		},
	}
	inspector := &stubTCInspector{
		snapshot: tc.Snapshot{
			Device: "eth0",
			Classes: []tc.ClassState{
				testObservedClassForSelection(t, target, limitTargetSelection{IP: "203.0.113.10"}, "eth0", tc.DirectionUpload, 2048, 2048),
			},
			Filters: []tc.FilterState{
				testObservedDirectAttachmentFilterForSelection(t, target, limitTargetSelection{IP: "203.0.113.10"}, "eth0", tc.DirectionUpload, 2048),
			},
		},
	}
	app := NewApp(service)
	app.tcInspector = inspector

	var stdout bytes.Buffer
	var stderr bytes.Buffer

	exitCode := app.Run([]string{
		"limit",
		"--pid", "1001",
		"--ip", "203.0.113.10",
		"--device", "eth0",
		"--direction", "upload",
		"--rate", "2048",
	}, &stdout, &stderr)

	if exitCode != 0 {
		t.Fatalf("expected exit code 0, got %d", exitCode)
	}

	output := stdout.String()
	for _, fragment := range []string{
		"Target: ip 203.0.113.10",
		"Matching applied state: yes",
		"Matching attachment rules: yes",
		"Observed rate: 2048 bytes/s",
		"Reconcile decision: no_op",
		"No tc changes are required.",
	} {
		if !strings.Contains(output, fragment) {
			t.Fatalf("expected IP no-op output to contain %q, got %q", fragment, output)
		}
	}
	if strings.Contains(output, "Planned commands:") {
		t.Fatalf("expected no-op output to omit planned commands, got %q", output)
	}
	if stderr.Len() != 0 {
		t.Fatalf("expected no stderr output, got %q", stderr.String())
	}
}

func TestRunLimitMappedIPv4DryRunMatchesCanonicalObservedState(t *testing.T) {
	target := testLimitTarget()
	service := &stubDiscoveryService{
		result: discovery.Result{
			Targets: []discovery.RuntimeTarget{target},
		},
	}
	inspector := &stubTCInspector{
		snapshot: tc.Snapshot{
			Device: "eth0",
			Classes: []tc.ClassState{
				testObservedClassForSelection(t, target, limitTargetSelection{IP: "203.0.113.10"}, "eth0", tc.DirectionUpload, 2048, 2048),
			},
			Filters: []tc.FilterState{
				testObservedDirectAttachmentFilterForSelection(t, target, limitTargetSelection{IP: "203.0.113.10"}, "eth0", tc.DirectionUpload, 2048),
			},
		},
	}
	app := NewApp(service)
	app.tcInspector = inspector

	var stdout bytes.Buffer
	var stderr bytes.Buffer

	exitCode := app.Run([]string{
		"limit",
		"--pid", "1001",
		"--ip", "::ffff:203.0.113.10",
		"--device", "eth0",
		"--direction", "upload",
		"--rate", "2048",
	}, &stdout, &stderr)

	if exitCode != 0 {
		t.Fatalf("expected exit code 0, got %d", exitCode)
	}

	output := stdout.String()
	for _, fragment := range []string{
		"Target: ip 203.0.113.10",
		"Matching applied state: yes",
		"Matching attachment rules: yes",
		"Reconcile decision: no_op",
		"No tc changes are required.",
	} {
		if !strings.Contains(output, fragment) {
			t.Fatalf("expected mapped IPv4 no-op output to contain %q, got %q", fragment, output)
		}
	}
	if stderr.Len() != 0 {
		t.Fatalf("expected no stderr output, got %q", stderr.String())
	}
}

func TestRunLimitMappedIPv4DryRunReportsNoOpFromParsedObservedClassRate(t *testing.T) {
	target := testLimitTarget()
	snapshot := testParsedObservedClassSnapshotForSelection(t, target, limitTargetSelection{IP: "203.0.113.10"}, "eth0", tc.DirectionUpload, 2048, "16.384Kbit")
	snapshot.Filters = []tc.FilterState{
		testObservedDirectAttachmentFilterForSelection(t, target, limitTargetSelection{IP: "203.0.113.10"}, "eth0", tc.DirectionUpload, 2048),
	}

	service := &stubDiscoveryService{
		result: discovery.Result{
			Targets: []discovery.RuntimeTarget{target},
		},
	}
	inspector := &stubTCInspector{snapshot: snapshot}
	app := NewApp(service)
	app.tcInspector = inspector

	var stdout bytes.Buffer
	var stderr bytes.Buffer

	exitCode := app.Run([]string{
		"limit",
		"--pid", "1001",
		"--ip", "::ffff:203.0.113.10",
		"--device", "eth0",
		"--direction", "upload",
		"--rate", "2048",
	}, &stdout, &stderr)

	if exitCode != 0 {
		t.Fatalf("expected exit code 0, got %d", exitCode)
	}

	output := stdout.String()
	for _, fragment := range []string{
		"Target: ip 203.0.113.10",
		"Observed rate: 2048 bytes/s",
		"Matching applied state: yes",
		"Matching attachment rules: yes",
		"Reconcile decision: no_op",
		"No tc changes are required.",
	} {
		if !strings.Contains(output, fragment) {
			t.Fatalf("expected parsed mapped IPv4 no-op output to contain %q, got %q", fragment, output)
		}
	}
	if stderr.Len() != 0 {
		t.Fatalf("expected no stderr output, got %q", stderr.String())
	}
}

func TestRunLimitIPv6DryRunReportsNoOpFromParsedObservedClassRate(t *testing.T) {
	target := testLimitTarget()
	snapshot := testParsedObservedClassSnapshotForSelection(t, target, limitTargetSelection{IP: "::1"}, "eth0", tc.DirectionUpload, 2048, "16.384Kbit")
	snapshot.Filters = []tc.FilterState{
		testObservedDirectAttachmentFilterForSelection(t, target, limitTargetSelection{IP: "::1"}, "eth0", tc.DirectionUpload, 2048),
	}

	service := &stubDiscoveryService{
		result: discovery.Result{
			Targets: []discovery.RuntimeTarget{target},
		},
	}
	inspector := &stubTCInspector{snapshot: snapshot}
	app := NewApp(service)
	app.tcInspector = inspector

	var stdout bytes.Buffer
	var stderr bytes.Buffer

	exitCode := app.Run([]string{
		"limit",
		"--pid", "1001",
		"--ip", "0:0:0:0:0:0:0:1",
		"--device", "eth0",
		"--direction", "upload",
		"--rate", "2048",
	}, &stdout, &stderr)

	if exitCode != 0 {
		t.Fatalf("expected exit code 0, got %d", exitCode)
	}

	output := stdout.String()
	for _, fragment := range []string{
		"Target: ip ::1",
		"Observed rate: 2048 bytes/s",
		"Matching applied state: yes",
		"Matching attachment rules: yes",
		"Reconcile decision: no_op",
		"No tc changes are required.",
	} {
		if !strings.Contains(output, fragment) {
			t.Fatalf("expected parsed ipv6 no-op output to contain %q, got %q", fragment, output)
		}
	}
	if stderr.Len() != 0 {
		t.Fatalf("expected no stderr output, got %q", stderr.String())
	}
}

func TestRunLimitIPDryRunReappliesWhenAttachmentRuleIsMissing(t *testing.T) {
	target := testLimitTarget()
	observedClass := testObservedClassForSelection(t, target, limitTargetSelection{IP: "203.0.113.10"}, "eth0", tc.DirectionUpload, 2048, 2048)
	service := &stubDiscoveryService{
		result: discovery.Result{
			Targets: []discovery.RuntimeTarget{target},
		},
	}
	inspector := &stubTCInspector{
		snapshot: tc.Snapshot{
			Device:  "eth0",
			QDiscs:  []tc.QDiscState{testObservedRootQDisc("1:")},
			Classes: []tc.ClassState{observedClass},
		},
	}
	app := NewApp(service)
	app.tcInspector = inspector

	var stdout bytes.Buffer
	var stderr bytes.Buffer

	exitCode := app.Run([]string{
		"limit",
		"--pid", "1001",
		"--ip", "203.0.113.10",
		"--device", "eth0",
		"--direction", "upload",
		"--rate", "2048",
	}, &stdout, &stderr)

	if exitCode != 0 {
		t.Fatalf("expected exit code 0, got %d", exitCode)
	}

	output := stdout.String()
	for _, fragment := range []string{
		"Matching applied state: yes",
		"Matching attachment rules: no",
		"Reconcile decision: apply",
		"Decision reason: matching direct class already satisfies the requested rate, but the expected direct attachment rules were not observed; reapply the class and concrete attachment rules",
		"tc filter replace dev eth0",
	} {
		if !strings.Contains(output, fragment) {
			t.Fatalf("expected missing-attachment output to contain %q, got %q", fragment, output)
		}
	}
	if stderr.Len() != 0 {
		t.Fatalf("expected no stderr output, got %q", stderr.String())
	}
}

func TestRunLimitMappedIPv4DryRunReappliesWhenCanonicalAttachmentRuleIsMissing(t *testing.T) {
	target := testLimitTarget()
	observedClass := testObservedClassForSelection(t, target, limitTargetSelection{IP: "203.0.113.10"}, "eth0", tc.DirectionUpload, 2048, 2048)
	service := &stubDiscoveryService{
		result: discovery.Result{
			Targets: []discovery.RuntimeTarget{target},
		},
	}
	inspector := &stubTCInspector{
		snapshot: tc.Snapshot{
			Device:  "eth0",
			QDiscs:  []tc.QDiscState{testObservedRootQDisc("1:")},
			Classes: []tc.ClassState{observedClass},
		},
	}
	app := NewApp(service)
	app.tcInspector = inspector

	var stdout bytes.Buffer
	var stderr bytes.Buffer

	exitCode := app.Run([]string{
		"limit",
		"--pid", "1001",
		"--ip", "::ffff:203.0.113.10",
		"--device", "eth0",
		"--direction", "upload",
		"--rate", "2048",
	}, &stdout, &stderr)

	if exitCode != 0 {
		t.Fatalf("expected exit code 0, got %d", exitCode)
	}

	output := stdout.String()
	for _, fragment := range []string{
		"Target: ip 203.0.113.10",
		"Matching applied state: yes",
		"Matching attachment rules: no",
		"Reconcile decision: apply",
		"tc filter replace dev eth0",
	} {
		if !strings.Contains(output, fragment) {
			t.Fatalf("expected mapped IPv4 missing-attachment output to contain %q, got %q", fragment, output)
		}
	}
	if stderr.Len() != 0 {
		t.Fatalf("expected no stderr output, got %q", stderr.String())
	}
}

func TestRunLimitInboundDryRunReportsApplyDecision(t *testing.T) {
	service := &stubDiscoveryService{
		result: discovery.Result{
			Targets: []discovery.RuntimeTarget{testLimitTarget()},
		},
	}
	inspector := &stubTCInspector{
		snapshot: tc.Snapshot{
			Device: "eth0",
		},
	}
	nftInspector := &stubNftInspector{}
	selectorDeriver := &stubInboundSelectorDeriver{result: testInboundSelectorResult()}
	app := NewApp(service)
	app.tcInspector = inspector
	app.nftInspector = nftInspector
	app.inboundSelector = selectorDeriver

	var stdout bytes.Buffer
	var stderr bytes.Buffer

	exitCode := app.Run([]string{
		"limit",
		"--pid", "1001",
		"--inbound", "api-in",
		"--device", "eth0",
		"--direction", "upload",
		"--rate", "2048",
	}, &stdout, &stderr)

	if exitCode != 0 {
		t.Fatalf("expected exit code 0, got %d", exitCode)
	}

	output := stdout.String()
	for _, fragment := range []string{
		"Mode: dry-run",
		"Runtime: host process 1001",
		"Target: inbound api-in",
		"Direct shaping readiness: ready",
		"Direct attachment readiness: ready",
		"Direct attachment execution readiness: ready",
		`Direct attachment note: tcp listener 127.0.0.1:8443 for inbound tag "api-in"`,
		"Direct attachment execution note: nftables input marking plus output mark restoration and tc fw classification target the selected inbound class",
		"Observed tc state: available",
		"Reconcile decision: apply",
		"Decision reason: no applied state was observed",
		"Planned action: apply",
		"Planned commands:",
		"nft add table inet raylimit",
		"tc filter replace dev eth0 parent 1: protocol all",
		"No system changes were made.",
	} {
		if !strings.Contains(output, fragment) {
			t.Fatalf("expected inbound dry-run output to contain %q, got %q", fragment, output)
		}
	}
	if len(inspector.requests) != 1 || inspector.requests[0].Device != "eth0" {
		t.Fatalf("expected inspector to run once for eth0, got %#v", inspector.requests)
	}
	if nftInspector.requests != 1 {
		t.Fatalf("expected nft inspector to run once, got %d", nftInspector.requests)
	}
	if len(selectorDeriver.requests) != 2 || selectorDeriver.requests[0].tag != "api-in" {
		t.Fatalf("expected inbound selector derivation for inspect and action plans, got %#v", selectorDeriver.requests)
	}
	if stderr.Len() != 0 {
		t.Fatalf("expected no stderr output, got %q", stderr.String())
	}
}

func TestRunLimitInboundDryRunReportsNoOpDecision(t *testing.T) {
	target := testLimitTarget()
	service := &stubDiscoveryService{
		result: discovery.Result{
			Targets: []discovery.RuntimeTarget{target},
		},
	}
	inspector := &stubTCInspector{
		snapshot: tc.Snapshot{
			Device: "eth0",
			Classes: []tc.ClassState{
				testObservedClassForSelection(t, target, limitTargetSelection{Inbound: "api-in"}, "eth0", tc.DirectionUpload, 2048, 2048),
			},
		},
	}
	filter, nftSnapshot := testObservedInboundMarkAttachmentState(t, target, "eth0", tc.DirectionUpload, 2048)
	inspector.snapshot.Filters = []tc.FilterState{filter}
	nftInspector := &stubNftInspector{snapshot: nftSnapshot}
	selectorDeriver := &stubInboundSelectorDeriver{result: testInboundSelectorResult()}
	app := NewApp(service)
	app.tcInspector = inspector
	app.nftInspector = nftInspector
	app.inboundSelector = selectorDeriver

	var stdout bytes.Buffer
	var stderr bytes.Buffer

	exitCode := app.Run([]string{
		"limit",
		"--pid", "1001",
		"--inbound", "api-in",
		"--device", "eth0",
		"--direction", "upload",
		"--rate", "2048",
	}, &stdout, &stderr)

	if exitCode != 0 {
		t.Fatalf("expected exit code 0, got %d", exitCode)
	}

	output := stdout.String()
	for _, fragment := range []string{
		"Target: inbound api-in",
		"Matching applied state: yes",
		"Matching attachment rules: yes",
		"Observed rate: 2048 bytes/s",
		"Reconcile decision: no_op",
		"No tc changes are required.",
	} {
		if !strings.Contains(output, fragment) {
			t.Fatalf("expected inbound no-op output to contain %q, got %q", fragment, output)
		}
	}
	if strings.Contains(output, "Planned commands:") {
		t.Fatalf("expected no-op output to omit planned commands, got %q", output)
	}
	if stderr.Len() != 0 {
		t.Fatalf("expected no stderr output, got %q", stderr.String())
	}
}

func TestRunLimitInboundExecuteBlocksNoOpWithoutConcreteAttachmentBackend(t *testing.T) {
	target := testLimitTarget()
	service := &stubDiscoveryService{
		result: discovery.Result{
			Targets: []discovery.RuntimeTarget{target},
		},
	}
	inspector := &stubTCInspector{
		snapshot: tc.Snapshot{
			Device: "eth0",
			Classes: []tc.ClassState{
				testObservedClassForSelection(t, target, limitTargetSelection{Inbound: "api-in"}, "eth0", tc.DirectionUpload, 2048, 2048),
			},
		},
	}
	runner := &stubTCRunner{}
	app := NewApp(service)
	app.tcInspector = inspector
	app.tcRunner = runner
	app.inboundSelector = &stubInboundSelectorDeriver{
		result: discovery.InboundMarkSelectorResult{
			Reason: `concrete inbound attachment for tag "api-in" requires readable Xray config hints; no config path hint is available for inbound tag "api-in"`,
		},
	}
	app.privilegeStatus = func() privilege.Status {
		return privilege.Status{EUID: 0, IsRoot: true}
	}

	var stdout bytes.Buffer
	var stderr bytes.Buffer

	exitCode := app.Run([]string{
		"limit",
		"--pid", "1001",
		"--inbound", "api-in",
		"--device", "eth0",
		"--direction", "upload",
		"--rate", "2048",
		"--execute",
	}, &stdout, &stderr)

	if exitCode != 1 {
		t.Fatalf("expected exit code 1, got %d", exitCode)
	}

	output := stdout.String()
	if !strings.Contains(output, "Reconcile decision: no_op") {
		t.Fatalf("expected no-op decision output, got %q", output)
	}
	if !strings.Contains(output, "Execution status: blocked") {
		t.Fatalf("expected blocked execution output, got %q", output)
	}
	if !strings.Contains(output, "Outcome: blocked") {
		t.Fatalf("expected blocked outcome summary, got %q", output)
	}
	if !strings.Contains(output, "No commands were executed.") {
		t.Fatalf("expected explicit no-command summary, got %q", output)
	}
	if !strings.Contains(output, "real inbound apply execution requires one concrete inbound mark-backed attachment path") {
		t.Fatalf("expected inbound execution blocker note, got %q", output)
	}
	if len(runner.commands) != 0 {
		t.Fatalf("expected blocked inbound execute to avoid runner calls, got %#v", runner.commands)
	}
	if !strings.Contains(stderr.String(), "error execution: real inbound apply execution requires one concrete inbound mark-backed attachment path") {
		t.Fatalf("expected structured inbound execution blocker, got %q", stderr.String())
	}
}

func TestRunLimitInboundExecuteBlocksReplacePlanWithoutConcreteAttachmentBackend(t *testing.T) {
	target := testLimitTarget()
	service := &stubDiscoveryService{
		result: discovery.Result{
			Targets: []discovery.RuntimeTarget{target},
		},
	}
	inspector := &stubTCInspector{
		snapshot: tc.Snapshot{
			Device: "eth0",
			Classes: []tc.ClassState{
				testObservedClassForSelection(t, target, limitTargetSelection{Inbound: "api-in"}, "eth0", tc.DirectionDownload, 4096, 1024),
			},
		},
	}
	runner := &stubTCRunner{
		result: tc.Result{
			Stdout: "ok",
		},
	}
	app := NewApp(service)
	app.tcInspector = inspector
	app.tcRunner = runner
	app.inboundSelector = &stubInboundSelectorDeriver{
		result: discovery.InboundMarkSelectorResult{
			Reason: `concrete inbound attachment for tag "api-in" requires readable Xray config hints; no config path hint is available for inbound tag "api-in"`,
		},
	}
	app.privilegeStatus = func() privilege.Status {
		return privilege.Status{EUID: 0, IsRoot: true}
	}

	var stdout bytes.Buffer
	var stderr bytes.Buffer

	exitCode := app.Run([]string{
		"limit",
		"--pid", "1001",
		"--inbound", "api-in",
		"--device", "eth0",
		"--direction", "download",
		"--rate", "4096",
		"--execute",
	}, &stdout, &stderr)

	if exitCode != 1 {
		t.Fatalf("expected exit code 1, got %d", exitCode)
	}

	if len(runner.commands) != 0 {
		t.Fatalf("expected blocked inbound execute to avoid runner calls, got %#v", runner.commands)
	}

	output := stdout.String()
	if !strings.Contains(output, "Reconcile decision: replace") {
		t.Fatalf("expected replace decision output, got %q", output)
	}
	if !strings.Contains(output, "Planned action: reconcile") {
		t.Fatalf("expected reconcile action output, got %q", output)
	}
	if !strings.Contains(output, "Execution status: blocked") {
		t.Fatalf("expected blocked execution summary, got %q", output)
	}
	if !strings.Contains(output, "tc class replace dev eth0") {
		t.Fatalf("expected class-oriented plan preview to remain visible, got %q", output)
	}
	if !strings.Contains(stderr.String(), "error execution: real inbound apply execution requires one concrete inbound mark-backed attachment path") {
		t.Fatalf("expected structured inbound execution blocker, got %q", stderr.String())
	}
}

func TestRunLimitOutboundDryRunReportsApplyDecision(t *testing.T) {
	service := &stubDiscoveryService{
		result: discovery.Result{
			Targets: []discovery.RuntimeTarget{testLimitTarget()},
		},
	}
	inspector := &stubTCInspector{
		snapshot: tc.Snapshot{
			Device: "eth0",
		},
	}
	nftInspector := &stubNftInspector{}
	selectorDeriver := &stubOutboundSelectorDeriver{result: testOutboundSelectorResult()}
	app := NewApp(service)
	app.tcInspector = inspector
	app.nftInspector = nftInspector
	app.outboundSelector = selectorDeriver

	var stdout bytes.Buffer
	var stderr bytes.Buffer

	exitCode := app.Run([]string{
		"limit",
		"--pid", "1001",
		"--outbound", "proxy-out",
		"--device", "eth0",
		"--direction", "upload",
		"--rate", "2048",
	}, &stdout, &stderr)

	if exitCode != 0 {
		t.Fatalf("expected exit code 0, got %d", exitCode)
	}

	output := stdout.String()
	for _, fragment := range []string{
		"Mode: dry-run",
		"Runtime: host process 1001",
		"Target: outbound proxy-out",
		"Direct shaping readiness: ready",
		"Direct attachment readiness: ready",
		"Direct attachment execution readiness: ready",
		`Direct attachment note: configured outbound socket mark 0x201 for outbound tag "proxy-out"`,
		"Direct attachment execution note: nftables output matching on the selected outbound socket mark plus tc fw classification target the selected outbound class",
		"Observed tc state: available",
		"Reconcile decision: apply",
		"Decision reason: no applied state was observed",
		"Planned action: apply",
		"Planned commands:",
		"nft add table inet raylimit",
		"tc filter replace dev eth0 parent 1: protocol all",
		"No system changes were made.",
	} {
		if !strings.Contains(output, fragment) {
			t.Fatalf("expected outbound dry-run output to contain %q, got %q", fragment, output)
		}
	}
	if len(inspector.requests) != 1 || inspector.requests[0].Device != "eth0" {
		t.Fatalf("expected inspector to run once for eth0, got %#v", inspector.requests)
	}
	if nftInspector.requests != 1 {
		t.Fatalf("expected nft inspector to run once, got %d", nftInspector.requests)
	}
	if len(selectorDeriver.requests) != 2 || selectorDeriver.requests[0].tag != "proxy-out" {
		t.Fatalf("expected outbound selector derivation for inspect and action plans, got %#v", selectorDeriver.requests)
	}
	if stderr.Len() != 0 {
		t.Fatalf("expected no stderr output, got %q", stderr.String())
	}
}

func TestRunLimitOutboundDryRunReportsNoOpDecision(t *testing.T) {
	target := testLimitTarget()
	service := &stubDiscoveryService{
		result: discovery.Result{
			Targets: []discovery.RuntimeTarget{target},
		},
	}
	inspector := &stubTCInspector{
		snapshot: tc.Snapshot{
			Device: "eth0",
			Classes: []tc.ClassState{
				testObservedClassForSelection(t, target, limitTargetSelection{Outbound: "proxy-out"}, "eth0", tc.DirectionUpload, 2048, 2048),
			},
		},
	}
	filter, nftSnapshot := testObservedOutboundMarkAttachmentState(t, target, "eth0", tc.DirectionUpload, 2048)
	inspector.snapshot.Filters = []tc.FilterState{filter}
	nftInspector := &stubNftInspector{snapshot: nftSnapshot}
	selectorDeriver := &stubOutboundSelectorDeriver{result: testOutboundSelectorResult()}
	app := NewApp(service)
	app.tcInspector = inspector
	app.nftInspector = nftInspector
	app.outboundSelector = selectorDeriver

	var stdout bytes.Buffer
	var stderr bytes.Buffer

	exitCode := app.Run([]string{
		"limit",
		"--pid", "1001",
		"--outbound", "proxy-out",
		"--device", "eth0",
		"--direction", "upload",
		"--rate", "2048",
	}, &stdout, &stderr)

	if exitCode != 0 {
		t.Fatalf("expected exit code 0, got %d", exitCode)
	}

	output := stdout.String()
	for _, fragment := range []string{
		"Target: outbound proxy-out",
		"Matching applied state: yes",
		"Observed rate: 2048 bytes/s",
		"Reconcile decision: no_op",
		"No tc changes are required.",
	} {
		if !strings.Contains(output, fragment) {
			t.Fatalf("expected outbound no-op output to contain %q, got %q", fragment, output)
		}
	}
	if strings.Contains(output, "Planned commands:") {
		t.Fatalf("expected no-op output to omit planned commands, got %q", output)
	}
	if nftInspector.requests != 1 {
		t.Fatalf("expected nft inspector to run once, got %d", nftInspector.requests)
	}
	if stderr.Len() != 0 {
		t.Fatalf("expected no stderr output, got %q", stderr.String())
	}
}

func TestRunLimitOutboundDryRunReappliesWhenMarkBackedAttachmentRulesAreMissing(t *testing.T) {
	target := testLimitTarget()
	observedClass := testObservedClassForSelection(t, target, limitTargetSelection{Outbound: "proxy-out"}, "eth0", tc.DirectionUpload, 2048, 2048)
	service := &stubDiscoveryService{
		result: discovery.Result{
			Targets: []discovery.RuntimeTarget{target},
		},
	}
	inspector := &stubTCInspector{
		snapshot: tc.Snapshot{
			Device:  "eth0",
			QDiscs:  []tc.QDiscState{testObservedRootQDisc("1:")},
			Classes: []tc.ClassState{observedClass},
		},
	}
	nftInspector := &stubNftInspector{snapshot: tc.NftablesSnapshot{}}
	app := NewApp(service)
	app.tcInspector = inspector
	app.nftInspector = nftInspector
	app.outboundSelector = &stubOutboundSelectorDeriver{result: testOutboundSelectorResult()}

	var stdout bytes.Buffer
	var stderr bytes.Buffer

	exitCode := app.Run([]string{
		"limit",
		"--pid", "1001",
		"--outbound", "proxy-out",
		"--device", "eth0",
		"--direction", "upload",
		"--rate", "2048",
	}, &stdout, &stderr)

	if exitCode != 0 {
		t.Fatalf("expected exit code 0, got %d", exitCode)
	}

	output := stdout.String()
	for _, fragment := range []string{
		"Target: outbound proxy-out",
		"Matching applied state: yes",
		"Matching attachment rules: no",
		"Reconcile decision: apply",
		"Decision reason: matching class already satisfies the requested rate, but the expected mark-backed attachment rules were not observed; reapply the class and concrete attachment rules",
		"nft add table inet raylimit",
		"tc filter replace dev eth0",
	} {
		if !strings.Contains(output, fragment) {
			t.Fatalf("expected outbound missing-attachment output to contain %q, got %q", fragment, output)
		}
	}
	if nftInspector.requests != 1 {
		t.Fatalf("expected outbound nft inspection, got %d", nftInspector.requests)
	}
	if stderr.Len() != 0 {
		t.Fatalf("expected no stderr output, got %q", stderr.String())
	}
}

func TestRunLimitOutboundExecuteBlocksApplyWithoutConcreteSocketMarkSelector(t *testing.T) {
	service := &stubDiscoveryService{
		result: discovery.Result{
			Targets: []discovery.RuntimeTarget{testLimitTarget()},
		},
	}
	inspector := &stubTCInspector{
		snapshot: tc.Snapshot{
			Device: "eth0",
		},
	}
	runner := &stubTCRunner{}
	app := NewApp(service)
	app.tcInspector = inspector
	app.tcRunner = runner
	app.outboundSelector = &stubOutboundSelectorDeriver{
		result: discovery.OutboundMarkSelectorResult{
			Reason: `concrete outbound attachment for tag "proxy-out" requires readable Xray config hints; no config path hint is available for outbound tag "proxy-out"`,
		},
	}
	app.privilegeStatus = func() privilege.Status {
		return privilege.Status{EUID: 0, IsRoot: true}
	}

	var stdout bytes.Buffer
	var stderr bytes.Buffer

	exitCode := app.Run([]string{
		"limit",
		"--pid", "1001",
		"--outbound", "proxy-out",
		"--device", "eth0",
		"--direction", "upload",
		"--rate", "2048",
		"--execute",
	}, &stdout, &stderr)

	if exitCode != 1 {
		t.Fatalf("expected exit code 1, got %d", exitCode)
	}
	if !strings.Contains(stdout.String(), "Execution status: blocked") {
		t.Fatalf("expected blocked execution output, got %q", stdout.String())
	}
	if !strings.Contains(stdout.String(), "real outbound apply execution requires one concrete outbound mark-backed attachment path") {
		t.Fatalf("expected outbound execution blocker note, got %q", stdout.String())
	}
	if len(runner.commands) != 0 {
		t.Fatalf("expected blocked outbound execute to avoid runner calls, got %#v", runner.commands)
	}
	if !strings.Contains(stderr.String(), "error execution: real outbound apply execution requires one concrete outbound mark-backed attachment path") {
		t.Fatalf("expected structured outbound execution blocker, got %q", stderr.String())
	}
}

func TestRunLimitDryRunReportsNoOpDecision(t *testing.T) {
	target := testLimitTarget()
	service := &stubDiscoveryService{
		result: discovery.Result{
			Targets: []discovery.RuntimeTarget{target},
		},
	}
	inspector := &stubTCInspector{
		snapshot: tc.Snapshot{
			Device: "eth0",
			Classes: []tc.ClassState{
				testObservedClass(t, target, "conn-1", "eth0", tc.DirectionUpload, 2048, 2048),
			},
		},
	}
	app := NewApp(service)
	app.tcInspector = inspector

	var stdout bytes.Buffer
	var stderr bytes.Buffer

	exitCode := app.Run([]string{
		"limit",
		"--pid", "1001",
		"--connection", "conn-1",
		"--device", "eth0",
		"--direction", "upload",
		"--rate", "2048",
	}, &stdout, &stderr)

	if exitCode != 0 {
		t.Fatalf("expected exit code 0, got %d", exitCode)
	}

	output := stdout.String()
	if !strings.Contains(output, "Reconcile decision: no_op") {
		t.Fatalf("expected no-op decision output, got %q", output)
	}
	if !strings.Contains(output, "Observed rate: 2048 bytes/s") {
		t.Fatalf("expected observed rate output, got %q", output)
	}
	if !strings.Contains(output, "No tc changes are required.") {
		t.Fatalf("expected no-op summary, got %q", output)
	}
	if strings.Contains(output, "Planned commands:") {
		t.Fatalf("expected no-op output to omit planned commands, got %q", output)
	}
	if stderr.Len() != 0 {
		t.Fatalf("expected no stderr output, got %q", stderr.String())
	}
}

func TestRunLimitConnectionExecuteBlocksNoOpWithoutConcreteAttachmentBackend(t *testing.T) {
	target := testLimitTarget()
	service := &stubDiscoveryService{
		result: discovery.Result{
			Targets: []discovery.RuntimeTarget{target},
		},
	}
	inspector := &stubTCInspector{
		snapshot: tc.Snapshot{
			Device: "eth0",
			Classes: []tc.ClassState{
				testObservedClass(t, target, "conn-1", "eth0", tc.DirectionUpload, 2048, 2048),
			},
		},
	}
	runner := &stubTCRunner{}
	app := NewApp(service)
	app.tcInspector = inspector
	app.tcRunner = runner
	app.privilegeStatus = func() privilege.Status {
		return privilege.Status{EUID: 0, IsRoot: true}
	}

	var stdout bytes.Buffer
	var stderr bytes.Buffer

	exitCode := app.Run([]string{
		"limit",
		"--pid", "1001",
		"--connection", "conn-1",
		"--device", "eth0",
		"--direction", "upload",
		"--rate", "2048",
		"--execute",
	}, &stdout, &stderr)

	if exitCode != 1 {
		t.Fatalf("expected exit code 1, got %d", exitCode)
	}

	output := stdout.String()
	if !strings.Contains(output, "Reconcile decision: no_op") {
		t.Fatalf("expected no-op decision output, got %q", output)
	}
	if !strings.Contains(output, "Execution status: blocked") {
		t.Fatalf("expected blocked-execution output, got %q", output)
	}
	if !strings.Contains(output, "No commands were executed.") {
		t.Fatalf("expected explicit no-command summary, got %q", output)
	}
	if !strings.Contains(output, "real connection apply execution remains unavailable until a trustworthy runtime-aware traffic classifier exists") {
		t.Fatalf("expected connection backend blocker note, got %q", output)
	}
	if len(runner.commands) != 0 {
		t.Fatalf("expected no-op execute to avoid tc runner calls, got %#v", runner.commands)
	}
	if !strings.Contains(stderr.String(), "error execution: real connection apply execution remains unavailable until a trustworthy runtime-aware traffic classifier exists") {
		t.Fatalf("expected structured connection execution blocker, got %q", stderr.String())
	}
}

func TestRunLimitConnectionExecuteBlocksReplacePlanWithoutConcreteAttachmentBackend(t *testing.T) {
	target := testLimitTarget()
	service := &stubDiscoveryService{
		result: discovery.Result{
			Targets: []discovery.RuntimeTarget{target},
		},
	}
	inspector := &stubTCInspector{
		snapshot: tc.Snapshot{
			Device: "eth0",
			Classes: []tc.ClassState{
				testObservedClass(t, target, "conn-1", "eth0", tc.DirectionDownload, 4096, 1024),
			},
		},
	}
	runner := &stubTCRunner{
		result: tc.Result{
			Stdout: "ok",
		},
	}
	app := NewApp(service)
	app.tcInspector = inspector
	app.tcRunner = runner
	app.privilegeStatus = func() privilege.Status {
		return privilege.Status{EUID: 0, IsRoot: true}
	}

	var stdout bytes.Buffer
	var stderr bytes.Buffer

	exitCode := app.Run([]string{
		"limit",
		"--pid", "1001",
		"--connection", "conn-1",
		"--device", "eth0",
		"--direction", "download",
		"--rate", "4096",
		"--execute",
	}, &stdout, &stderr)

	if exitCode != 1 {
		t.Fatalf("expected exit code 1, got %d", exitCode)
	}

	if len(runner.commands) != 0 {
		t.Fatalf("expected blocked connection execute to avoid runner calls, got %#v", runner.commands)
	}

	output := stdout.String()
	if !strings.Contains(output, "Reconcile decision: replace") {
		t.Fatalf("expected replace decision output, got %q", output)
	}
	if !strings.Contains(output, "Planned action: reconcile") {
		t.Fatalf("expected reconcile action output, got %q", output)
	}
	if !strings.Contains(output, "Execution status: blocked") {
		t.Fatalf("expected blocked execution summary, got %q", output)
	}
	if !strings.Contains(output, "tc class replace dev eth0") {
		t.Fatalf("expected class-oriented plan preview to remain visible, got %q", output)
	}
	if !strings.Contains(stderr.String(), "error execution: real connection apply execution remains unavailable until a trustworthy runtime-aware traffic classifier exists") {
		t.Fatalf("expected structured connection execution blocker, got %q", stderr.String())
	}
}

func TestRunLimitRemoveExecuteUsesRunner(t *testing.T) {
	target := testLimitTarget()
	service := &stubDiscoveryService{
		result: discovery.Result{
			Targets: []discovery.RuntimeTarget{target},
		},
	}
	inspector := &stubTCInspector{
		snapshot: tc.Snapshot{
			Device: "eth0",
			Classes: []tc.ClassState{
				testObservedClass(t, target, "conn-1", "eth0", tc.DirectionUpload, 2048, 2048),
			},
		},
	}
	runner := &stubTCRunner{
		result: tc.Result{
			Stdout: "ok",
		},
	}
	app := NewApp(service)
	app.tcInspector = inspector
	app.tcRunner = runner
	app.privilegeStatus = func() privilege.Status {
		return privilege.Status{EUID: 0, IsRoot: true}
	}

	var stdout bytes.Buffer
	var stderr bytes.Buffer

	exitCode := app.Run([]string{
		"limit",
		"--pid", "1001",
		"--connection", "conn-1",
		"--device", "eth0",
		"--direction", "upload",
		"--remove",
		"--execute",
	}, &stdout, &stderr)

	if exitCode != 0 {
		t.Fatalf("expected exit code 0, got %d", exitCode)
	}

	if len(runner.commands) != 1 {
		t.Fatalf("expected one tc remove command, got %#v", runner.commands)
	}

	output := stdout.String()
	if !strings.Contains(output, "Operation: remove") {
		t.Fatalf("expected remove output, got %q", output)
	}
	if !strings.Contains(output, "Executed 1 command(s).") {
		t.Fatalf("expected execution summary, got %q", output)
	}
	if !strings.Contains(output, "Outcome: executed") {
		t.Fatalf("expected executed outcome summary, got %q", output)
	}
	if stderr.Len() != 0 {
		t.Fatalf("expected no stderr output, got %q", stderr.String())
	}
}

func TestRunLimitRemoveExecuteUsesRunnerAndCleansRootQDisc(t *testing.T) {
	target := testLimitTarget()
	observedClass := testObservedClass(t, target, "conn-1", "eth0", tc.DirectionUpload, 2048, 2048)
	service := &stubDiscoveryService{
		result: discovery.Result{
			Targets: []discovery.RuntimeTarget{target},
		},
	}
	inspector := &stubTCInspector{
		snapshot: tc.Snapshot{
			Device:  "eth0",
			QDiscs:  []tc.QDiscState{testObservedRootQDisc("1:")},
			Classes: []tc.ClassState{observedClass},
		},
	}
	runner := &stubTCRunner{
		result: tc.Result{
			Stdout: "ok",
		},
	}
	app := NewApp(service)
	app.tcInspector = inspector
	app.tcRunner = runner
	app.privilegeStatus = func() privilege.Status {
		return privilege.Status{EUID: 0, IsRoot: true}
	}

	var stdout bytes.Buffer
	var stderr bytes.Buffer

	exitCode := app.Run([]string{
		"limit",
		"--pid", "1001",
		"--connection", "conn-1",
		"--device", "eth0",
		"--direction", "upload",
		"--remove",
		"--execute",
	}, &stdout, &stderr)

	if exitCode != 0 {
		t.Fatalf("expected exit code 0, got %d", exitCode)
	}

	if len(runner.commands) != 2 {
		t.Fatalf("expected class delete plus root qdisc delete, got %#v", runner.commands)
	}
	if runner.commands[1].Args[0] != "qdisc" || runner.commands[1].Args[1] != "del" || runner.commands[1].Args[len(runner.commands[1].Args)-1] != "root" {
		t.Fatalf("unexpected root qdisc cleanup command: %#v", runner.commands[1])
	}

	output := stdout.String()
	for _, fragment := range []string{
		"Operation: remove",
		"Cleanup scope: class plus root qdisc",
		"Executed 2 command(s).",
	} {
		if !strings.Contains(output, fragment) {
			t.Fatalf("expected cleanup execute output to contain %q, got %q", fragment, output)
		}
	}
	if stderr.Len() != 0 {
		t.Fatalf("expected no stderr output, got %q", stderr.String())
	}
}

func TestRunLimitHandlesUnavailableTCStateInDryRun(t *testing.T) {
	service := &stubDiscoveryService{
		result: discovery.Result{
			Targets: []discovery.RuntimeTarget{testLimitTarget()},
		},
	}
	inspector := &stubTCInspector{
		err: errors.New("run tc failed: executable file not found"),
	}
	app := NewApp(service)
	app.tcInspector = inspector

	var stdout bytes.Buffer
	var stderr bytes.Buffer

	exitCode := app.Run([]string{
		"limit",
		"--pid", "1001",
		"--ip", "203.0.113.10",
		"--device", "eth0",
		"--direction", "upload",
		"--rate", "2048",
	}, &stdout, &stderr)

	if exitCode != 0 {
		t.Fatalf("expected exit code 0, got %d", exitCode)
	}

	output := stdout.String()
	if !strings.Contains(output, "Observed tc state: unavailable") {
		t.Fatalf("expected unavailable observation output, got %q", output)
	}
	if !strings.Contains(output, "Reconcile decision: apply") {
		t.Fatalf("expected apply decision output, got %q", output)
	}
	if !strings.Contains(output, "Observation note: tc state inspection failed: run tc failed: executable file not found") {
		t.Fatalf("expected observation error output, got %q", output)
	}
	if stderr.Len() != 0 {
		t.Fatalf("expected no stderr output, got %q", stderr.String())
	}
}

func TestRunLimitRemoveDryRunReportsNoOpWhenNothingMatches(t *testing.T) {
	service := &stubDiscoveryService{
		result: discovery.Result{
			Targets: []discovery.RuntimeTarget{testLimitTarget()},
		},
	}
	inspector := &stubTCInspector{
		snapshot: tc.Snapshot{
			Device: "eth0",
		},
	}
	app := NewApp(service)
	app.tcInspector = inspector

	var stdout bytes.Buffer
	var stderr bytes.Buffer

	exitCode := app.Run([]string{
		"limit",
		"--pid", "1001",
		"--connection", "conn-1",
		"--device", "eth0",
		"--direction", "upload",
		"--remove",
	}, &stdout, &stderr)

	if exitCode != 0 {
		t.Fatalf("expected exit code 0, got %d", exitCode)
	}

	output := stdout.String()
	for _, fragment := range []string{
		"Operation: remove",
		"Requested removal: upload limit on eth0",
		"Matching applied state: no",
		"Reconcile decision: no_op",
		"No tc changes are required.",
	} {
		if !strings.Contains(output, fragment) {
			t.Fatalf("expected remove no-op output to contain %q, got %q", fragment, output)
		}
	}

	if strings.Contains(output, "Planned commands:") {
		t.Fatalf("expected no-op remove output to omit planned commands, got %q", output)
	}
	if stderr.Len() != 0 {
		t.Fatalf("expected no stderr output, got %q", stderr.String())
	}
}

func TestRunLimitRemoveDryRunReportsRemoveDecision(t *testing.T) {
	target := testLimitTarget()
	service := &stubDiscoveryService{
		result: discovery.Result{
			Targets: []discovery.RuntimeTarget{target},
		},
	}
	inspector := &stubTCInspector{
		snapshot: tc.Snapshot{
			Device: "eth0",
			Classes: []tc.ClassState{
				testObservedClass(t, target, "conn-1", "eth0", tc.DirectionUpload, 2048, 2048),
			},
		},
	}
	app := NewApp(service)
	app.tcInspector = inspector

	var stdout bytes.Buffer
	var stderr bytes.Buffer

	exitCode := app.Run([]string{
		"limit",
		"--pid", "1001",
		"--connection", "conn-1",
		"--device", "eth0",
		"--direction", "upload",
		"--remove",
	}, &stdout, &stderr)

	if exitCode != 0 {
		t.Fatalf("expected exit code 0, got %d", exitCode)
	}

	output := stdout.String()
	for _, fragment := range []string{
		"Operation: remove",
		"Matching applied state: yes",
		"Reconcile decision: remove",
		"Planned action: remove",
		"Cleanup scope: class only",
		"tc class del dev eth0 classid",
	} {
		if !strings.Contains(output, fragment) {
			t.Fatalf("expected remove output to contain %q, got %q", fragment, output)
		}
	}

	if stderr.Len() != 0 {
		t.Fatalf("expected no stderr output, got %q", stderr.String())
	}
}

func TestRunLimitRemoveDryRunKeepsRootQDiscWhenAdditionalStateRemains(t *testing.T) {
	target := testLimitTarget()
	observedClass := testObservedClass(t, target, "conn-1", "eth0", tc.DirectionUpload, 2048, 2048)
	service := &stubDiscoveryService{
		result: discovery.Result{
			Targets: []discovery.RuntimeTarget{target},
		},
	}
	inspector := &stubTCInspector{
		snapshot: tc.Snapshot{
			Device:  "eth0",
			QDiscs:  []tc.QDiscState{testObservedRootQDisc("1:")},
			Classes: []tc.ClassState{observedClass},
			Filters: []tc.FilterState{{Kind: "u32", Parent: "1:", Protocol: "ip"}},
		},
	}
	app := NewApp(service)
	app.tcInspector = inspector

	var stdout bytes.Buffer
	var stderr bytes.Buffer

	exitCode := app.Run([]string{
		"limit",
		"--pid", "1001",
		"--connection", "conn-1",
		"--device", "eth0",
		"--direction", "upload",
		"--remove",
	}, &stdout, &stderr)

	if exitCode != 0 {
		t.Fatalf("expected exit code 0, got %d", exitCode)
	}

	output := stdout.String()
	for _, fragment := range []string{
		"Operation: remove",
		"Matching applied state: yes",
		"Cleanup scope: class only",
		"tc class del dev eth0 classid",
	} {
		if !strings.Contains(output, fragment) {
			t.Fatalf("expected conservative cleanup output to contain %q, got %q", fragment, output)
		}
	}
	if strings.Contains(output, "tc qdisc del dev eth0 root") {
		t.Fatalf("expected root qdisc to remain planned intact when additional state exists, got %q", output)
	}
	if stderr.Len() != 0 {
		t.Fatalf("expected no stderr output, got %q", stderr.String())
	}
}

func TestRunLimitRemoveDryRunPlansFullCleanupWhenManagedStateIsAlone(t *testing.T) {
	target := testLimitTarget()
	observedClass := testObservedClass(t, target, "conn-1", "eth0", tc.DirectionUpload, 2048, 2048)
	service := &stubDiscoveryService{
		result: discovery.Result{
			Targets: []discovery.RuntimeTarget{target},
		},
	}
	inspector := &stubTCInspector{
		snapshot: tc.Snapshot{
			Device:  "eth0",
			QDiscs:  []tc.QDiscState{testObservedRootQDisc("1:")},
			Classes: []tc.ClassState{observedClass},
		},
	}
	app := NewApp(service)
	app.tcInspector = inspector

	var stdout bytes.Buffer
	var stderr bytes.Buffer

	exitCode := app.Run([]string{
		"limit",
		"--pid", "1001",
		"--connection", "conn-1",
		"--device", "eth0",
		"--direction", "upload",
		"--remove",
	}, &stdout, &stderr)

	if exitCode != 0 {
		t.Fatalf("expected exit code 0, got %d", exitCode)
	}

	output := stdout.String()
	for _, fragment := range []string{
		"Operation: remove",
		"Matching applied state: yes",
		"Cleanup scope: class plus root qdisc",
		"tc class del dev eth0 classid",
		"tc qdisc del dev eth0 root",
	} {
		if !strings.Contains(output, fragment) {
			t.Fatalf("expected full cleanup output to contain %q, got %q", fragment, output)
		}
	}
	if stderr.Len() != 0 {
		t.Fatalf("expected no stderr output, got %q", stderr.String())
	}
}

func TestRunLimitIPRemoveDryRunPlansFullCleanupWhenManagedAttachmentStateIsAlone(t *testing.T) {
	target := testLimitTarget()
	observedClass := testObservedClassForSelection(t, target, limitTargetSelection{IP: "203.0.113.10"}, "eth0", tc.DirectionUpload, 2048, 2048)
	observedFilter := testObservedDirectAttachmentFilterForSelection(t, target, limitTargetSelection{IP: "203.0.113.10"}, "eth0", tc.DirectionUpload, 2048)
	service := &stubDiscoveryService{
		result: discovery.Result{
			Targets: []discovery.RuntimeTarget{target},
		},
	}
	inspector := &stubTCInspector{
		snapshot: tc.Snapshot{
			Device:  "eth0",
			QDiscs:  []tc.QDiscState{testObservedRootQDisc("1:")},
			Classes: []tc.ClassState{observedClass},
			Filters: []tc.FilterState{observedFilter},
		},
	}
	app := NewApp(service)
	app.tcInspector = inspector

	var stdout bytes.Buffer
	var stderr bytes.Buffer

	exitCode := app.Run([]string{
		"limit",
		"--pid", "1001",
		"--ip", "203.0.113.10",
		"--device", "eth0",
		"--direction", "upload",
		"--remove",
	}, &stdout, &stderr)

	if exitCode != 0 {
		t.Fatalf("expected exit code 0, got %d", exitCode)
	}

	output := stdout.String()
	for _, fragment := range []string{
		"Operation: remove",
		"Matching applied state: yes",
		"Matching attachment rules: yes",
		"Cleanup scope: class plus root qdisc",
		"tc filter del dev eth0",
		"tc class del dev eth0 classid",
		"tc qdisc del dev eth0 root",
	} {
		if !strings.Contains(output, fragment) {
			t.Fatalf("expected ip full cleanup output to contain %q, got %q", fragment, output)
		}
	}
	if stderr.Len() != 0 {
		t.Fatalf("expected no stderr output, got %q", stderr.String())
	}
}

func TestRunLimitMappedIPv4RemoveDryRunPlansCanonicalManagedCleanup(t *testing.T) {
	target := testLimitTarget()
	observedClass := testObservedClassForSelection(t, target, limitTargetSelection{IP: "203.0.113.10"}, "eth0", tc.DirectionUpload, 2048, 2048)
	observedFilter := testObservedDirectAttachmentFilterForSelection(t, target, limitTargetSelection{IP: "203.0.113.10"}, "eth0", tc.DirectionUpload, 2048)
	service := &stubDiscoveryService{
		result: discovery.Result{
			Targets: []discovery.RuntimeTarget{target},
		},
	}
	inspector := &stubTCInspector{
		snapshot: tc.Snapshot{
			Device:  "eth0",
			QDiscs:  []tc.QDiscState{testObservedRootQDisc("1:")},
			Classes: []tc.ClassState{observedClass},
			Filters: []tc.FilterState{observedFilter},
		},
	}
	app := NewApp(service)
	app.tcInspector = inspector

	var stdout bytes.Buffer
	var stderr bytes.Buffer

	exitCode := app.Run([]string{
		"limit",
		"--pid", "1001",
		"--ip", "::ffff:203.0.113.10",
		"--device", "eth0",
		"--direction", "upload",
		"--remove",
	}, &stdout, &stderr)

	if exitCode != 0 {
		t.Fatalf("expected exit code 0, got %d", exitCode)
	}

	output := stdout.String()
	for _, fragment := range []string{
		"Target: ip 203.0.113.10",
		"Matching applied state: yes",
		"Matching attachment rules: yes",
		"Cleanup scope: class plus root qdisc",
		"tc filter del dev eth0",
		"tc class del dev eth0 classid",
		"tc qdisc del dev eth0 root",
	} {
		if !strings.Contains(output, fragment) {
			t.Fatalf("expected mapped IPv4 cleanup output to contain %q, got %q", fragment, output)
		}
	}
	if stderr.Len() != 0 {
		t.Fatalf("expected no stderr output, got %q", stderr.String())
	}
}

func TestRunLimitIPRemoveDryRunPlansAttachmentCleanupWhenManagedFilterRemainsAfterClassDisappears(t *testing.T) {
	target := testLimitTarget()
	observedFilter := testObservedDirectAttachmentFilterForSelection(t, target, limitTargetSelection{IP: "203.0.113.10"}, "eth0", tc.DirectionUpload, 2048)
	service := &stubDiscoveryService{
		result: discovery.Result{
			Targets: []discovery.RuntimeTarget{target},
		},
	}
	inspector := &stubTCInspector{
		snapshot: tc.Snapshot{
			Device: "eth0",
			QDiscs: []tc.QDiscState{testObservedRootQDisc("1:")},
			Filters: []tc.FilterState{
				observedFilter,
			},
		},
	}
	app := NewApp(service)
	app.tcInspector = inspector

	var stdout bytes.Buffer
	var stderr bytes.Buffer

	exitCode := app.Run([]string{
		"limit",
		"--pid", "1001",
		"--ip", "203.0.113.10",
		"--device", "eth0",
		"--direction", "upload",
		"--remove",
	}, &stdout, &stderr)

	if exitCode != 0 {
		t.Fatalf("expected exit code 0, got %d", exitCode)
	}

	output := stdout.String()
	for _, fragment := range []string{
		"Operation: remove",
		"Matching applied state: no",
		"Matching attachment rules: yes",
		"Reconcile decision: remove",
		"Decision reason: managed direct attachment rules were observed for the selected target limit",
		"Cleanup scope: attachment rules plus root qdisc",
		"tc filter del dev eth0",
		"tc qdisc del dev eth0 root",
	} {
		if !strings.Contains(output, fragment) {
			t.Fatalf("expected stale direct attachment cleanup output to contain %q, got %q", fragment, output)
		}
	}
	if strings.Contains(output, "tc class del dev eth0 classid") {
		t.Fatalf("expected attachment-only cleanup output to avoid a stale class delete, got %q", output)
	}
	if stderr.Len() != 0 {
		t.Fatalf("expected no stderr output, got %q", stderr.String())
	}
}

func TestRunLimitIPRemoveExecuteCleansAttachmentOnlyStateWhenClassIsAlreadyGone(t *testing.T) {
	target := testLimitTarget()
	observedFilter := testObservedDirectAttachmentFilterForSelection(t, target, limitTargetSelection{IP: "203.0.113.10"}, "eth0", tc.DirectionUpload, 2048)
	service := &stubDiscoveryService{
		result: discovery.Result{
			Targets: []discovery.RuntimeTarget{target},
		},
	}
	inspector := &stubTCInspector{
		snapshot: tc.Snapshot{
			Device:  "eth0",
			QDiscs:  []tc.QDiscState{testObservedRootQDisc("1:")},
			Filters: []tc.FilterState{observedFilter},
		},
	}
	runner := &stubTCRunner{
		result: tc.Result{
			Stdout: "ok",
		},
	}
	app := NewApp(service)
	app.tcInspector = inspector
	app.tcRunner = runner
	app.privilegeStatus = func() privilege.Status {
		return privilege.Status{EUID: 0, IsRoot: true}
	}

	var stdout bytes.Buffer
	var stderr bytes.Buffer

	exitCode := app.Run([]string{
		"limit",
		"--pid", "1001",
		"--ip", "203.0.113.10",
		"--device", "eth0",
		"--direction", "upload",
		"--remove",
		"--execute",
	}, &stdout, &stderr)

	if exitCode != 0 {
		t.Fatalf("expected exit code 0, got %d", exitCode)
	}
	if len(runner.commands) != 2 {
		t.Fatalf("expected direct attachment cleanup plus root qdisc cleanup without a class delete, got %#v", runner.commands)
	}
	if runner.commands[0].Args[0] != "filter" || runner.commands[1].Args[0] != "qdisc" {
		t.Fatalf("expected direct attachment filter delete followed by root qdisc delete, got %#v", runner.commands)
	}
	if !strings.Contains(stdout.String(), "Cleanup scope: attachment rules plus root qdisc") {
		t.Fatalf("expected attachment-only cleanup scope output, got %q", stdout.String())
	}
	if !strings.Contains(stdout.String(), "Executed 2 command(s).") {
		t.Fatalf("expected attachment-only remove execute summary, got %q", stdout.String())
	}
	if stderr.Len() != 0 {
		t.Fatalf("expected no stderr output, got %q", stderr.String())
	}
}

func TestRunLimitRemoveHandlesUnavailableTCStateInDryRun(t *testing.T) {
	service := &stubDiscoveryService{
		result: discovery.Result{
			Targets: []discovery.RuntimeTarget{testLimitTarget()},
		},
	}
	inspector := &stubTCInspector{
		err: errors.New("run tc failed: executable file not found"),
	}
	app := NewApp(service)
	app.tcInspector = inspector

	var stdout bytes.Buffer
	var stderr bytes.Buffer

	exitCode := app.Run([]string{
		"limit",
		"--pid", "1001",
		"--connection", "conn-1",
		"--device", "eth0",
		"--direction", "upload",
		"--remove",
	}, &stdout, &stderr)

	if exitCode != 0 {
		t.Fatalf("expected exit code 0, got %d", exitCode)
	}

	output := stdout.String()
	if !strings.Contains(output, "Observed tc state: unavailable") {
		t.Fatalf("expected unavailable observation output, got %q", output)
	}
	if !strings.Contains(output, "Reconcile decision: remove") {
		t.Fatalf("expected remove decision output, got %q", output)
	}
	if !strings.Contains(output, "Observation note: tc state inspection failed: run tc failed: executable file not found") {
		t.Fatalf("expected observation error output, got %q", output)
	}
	if !strings.Contains(output, "Planned action: remove") {
		t.Fatalf("expected fallback remove plan output, got %q", output)
	}
	if stderr.Len() != 0 {
		t.Fatalf("expected no stderr output, got %q", stderr.String())
	}
}

func TestRunLimitIPExecuteRejectsMissingObservedStateWithoutOverride(t *testing.T) {
	service := &stubDiscoveryService{
		result: discovery.Result{
			Targets: []discovery.RuntimeTarget{testLimitTarget()},
		},
	}
	inspector := &stubTCInspector{
		err: errors.New("run tc failed: executable file not found"),
	}
	runner := &stubTCRunner{}
	app := NewApp(service)
	app.tcInspector = inspector
	app.tcRunner = runner
	app.privilegeStatus = func() privilege.Status {
		return privilege.Status{EUID: 0, IsRoot: true}
	}

	var stdout bytes.Buffer
	var stderr bytes.Buffer

	exitCode := app.Run([]string{
		"limit",
		"--pid", "1001",
		"--ip", "203.0.113.10",
		"--device", "eth0",
		"--direction", "upload",
		"--rate", "2048",
		"--execute",
	}, &stdout, &stderr)

	if exitCode != 1 {
		t.Fatalf("expected exit code 1, got %d", exitCode)
	}

	if !strings.Contains(stderr.String(), "--allow-missing-tc-state") {
		t.Fatalf("expected missing-observed-state guidance, got %q", stderr.String())
	}
	if !strings.Contains(stdout.String(), "Execution status: blocked") {
		t.Fatalf("expected blocked-execution output, got %q", stdout.String())
	}
	if !strings.Contains(stdout.String(), "No commands were executed.") {
		t.Fatalf("expected blocked-execution summary, got %q", stdout.String())
	}
	if len(runner.commands) != 0 {
		t.Fatalf("expected execution to stop before tc runner, got %#v", runner.commands)
	}
}

func TestRunLimitRemoveExecuteRejectsMissingObservedStateWithoutOverride(t *testing.T) {
	service := &stubDiscoveryService{
		result: discovery.Result{
			Targets: []discovery.RuntimeTarget{testLimitTarget()},
		},
	}
	inspector := &stubTCInspector{
		err: errors.New("run tc failed: executable file not found"),
	}
	runner := &stubTCRunner{}
	app := NewApp(service)
	app.tcInspector = inspector
	app.tcRunner = runner
	app.privilegeStatus = func() privilege.Status {
		return privilege.Status{EUID: 0, IsRoot: true}
	}

	var stdout bytes.Buffer
	var stderr bytes.Buffer

	exitCode := app.Run([]string{
		"limit",
		"--pid", "1001",
		"--connection", "conn-1",
		"--device", "eth0",
		"--direction", "upload",
		"--remove",
		"--execute",
	}, &stdout, &stderr)

	if exitCode != 1 {
		t.Fatalf("expected exit code 1, got %d", exitCode)
	}

	if !strings.Contains(stderr.String(), "--allow-missing-tc-state") {
		t.Fatalf("expected missing-observed-state guidance, got %q", stderr.String())
	}
	if !strings.Contains(stdout.String(), "Execution status: blocked") {
		t.Fatalf("expected blocked-execution output, got %q", stdout.String())
	}
	if !strings.Contains(stdout.String(), "No commands were executed.") {
		t.Fatalf("expected blocked-execution summary, got %q", stdout.String())
	}
	if len(runner.commands) != 0 {
		t.Fatalf("expected execution to stop before tc runner, got %#v", runner.commands)
	}
}

func TestRunLimitConnectionExecuteBlocksWithoutConcreteAttachmentBackendEvenWhenRootIsAvailable(t *testing.T) {
	service := &stubDiscoveryService{
		result: discovery.Result{
			Targets: []discovery.RuntimeTarget{testLimitTarget()},
		},
	}
	inspector := &stubTCInspector{
		snapshot: tc.Snapshot{
			Device: "eth0",
		},
	}
	runner := &stubTCRunner{}
	app := NewApp(service)
	app.tcInspector = inspector
	app.tcRunner = runner
	app.privilegeStatus = func() privilege.Status {
		return privilege.Status{EUID: 0, IsRoot: true}
	}

	var stdout bytes.Buffer
	var stderr bytes.Buffer

	exitCode := app.Run([]string{
		"limit",
		"--pid", "1001",
		"--connection", "conn-1",
		"--device", "eth0",
		"--direction", "upload",
		"--rate", "2048",
		"--execute",
	}, &stdout, &stderr)

	if exitCode != 1 {
		t.Fatalf("expected exit code 1, got %d", exitCode)
	}

	if !strings.Contains(stdout.String(), "Reconcile decision: apply") {
		t.Fatalf("expected reconcile output before backend block, got %q", stdout.String())
	}
	if !strings.Contains(stdout.String(), "Execution status: blocked") {
		t.Fatalf("expected blocked-execution output, got %q", stdout.String())
	}
	if !strings.Contains(stdout.String(), "No commands were executed.") {
		t.Fatalf("expected blocked-execution summary, got %q", stdout.String())
	}
	if !strings.Contains(stderr.String(), "error execution:") || !strings.Contains(stderr.String(), "real connection apply execution remains unavailable until a trustworthy runtime-aware traffic classifier exists") {
		t.Fatalf("expected connection backend blocker, got %q", stderr.String())
	}
	if len(runner.commands) != 0 {
		t.Fatalf("expected backend blocker to avoid runner calls, got %#v", runner.commands)
	}
}

func TestRunLimitIPExecuteRejectsNonRootExecution(t *testing.T) {
	service := &stubDiscoveryService{
		result: discovery.Result{
			Targets: []discovery.RuntimeTarget{testLimitTarget()},
		},
	}
	inspector := &stubTCInspector{
		snapshot: tc.Snapshot{
			Device: "eth0",
		},
	}
	runner := &stubTCRunner{}
	app := NewApp(service)
	app.tcInspector = inspector
	app.tcRunner = runner
	app.privilegeStatus = func() privilege.Status {
		return privilege.Status{EUID: 1000}
	}

	var stdout bytes.Buffer
	var stderr bytes.Buffer

	exitCode := app.Run([]string{
		"limit",
		"--pid", "1001",
		"--ip", "203.0.113.10",
		"--device", "eth0",
		"--direction", "upload",
		"--rate", "2048",
		"--execute",
	}, &stdout, &stderr)

	if exitCode != 1 {
		t.Fatalf("expected exit code 1, got %d", exitCode)
	}

	if !strings.Contains(stdout.String(), "Target: ip 203.0.113.10") {
		t.Fatalf("expected IP target output before privilege failure, got %q", stdout.String())
	}
	if !strings.Contains(stdout.String(), "Reconcile decision: apply") {
		t.Fatalf("expected reconcile output before privilege failure, got %q", stdout.String())
	}
	if !strings.Contains(stderr.String(), "tc execution requires root privileges") {
		t.Fatalf("expected privilege error, got %q", stderr.String())
	}
	if len(runner.commands) != 0 {
		t.Fatalf("expected privilege failure to avoid runner calls, got %#v", runner.commands)
	}
}

func TestRunLimitInboundRemoveExecuteUsesRunnerAndCleansRootQDisc(t *testing.T) {
	target := testLimitTarget()
	observedClass := testObservedClassForSelection(t, target, limitTargetSelection{Inbound: "api-in"}, "eth0", tc.DirectionUpload, 2048, 2048)
	service := &stubDiscoveryService{
		result: discovery.Result{
			Targets: []discovery.RuntimeTarget{target},
		},
	}
	inspector := &stubTCInspector{
		snapshot: tc.Snapshot{
			Device:  "eth0",
			QDiscs:  []tc.QDiscState{testObservedRootQDisc("1:")},
			Classes: []tc.ClassState{observedClass},
		},
	}
	runner := &stubTCRunner{
		result: tc.Result{
			Stdout: "ok",
		},
	}
	app := NewApp(service)
	app.tcInspector = inspector
	app.tcRunner = runner
	app.privilegeStatus = func() privilege.Status {
		return privilege.Status{EUID: 0, IsRoot: true}
	}

	var stdout bytes.Buffer
	var stderr bytes.Buffer

	exitCode := app.Run([]string{
		"limit",
		"--pid", "1001",
		"--inbound", "api-in",
		"--device", "eth0",
		"--direction", "upload",
		"--remove",
		"--execute",
	}, &stdout, &stderr)

	if exitCode != 0 {
		t.Fatalf("expected exit code 0, got %d", exitCode)
	}

	if len(runner.commands) != 2 {
		t.Fatalf("expected class delete plus root qdisc delete, got %#v", runner.commands)
	}
	if runner.commands[1].Args[0] != "qdisc" || runner.commands[1].Args[1] != "del" || runner.commands[1].Args[len(runner.commands[1].Args)-1] != "root" {
		t.Fatalf("expected root qdisc cleanup command, got %#v", runner.commands[1])
	}

	output := stdout.String()
	if !strings.Contains(output, "Operation: remove") {
		t.Fatalf("expected remove output, got %q", output)
	}
	if !strings.Contains(output, "Target: inbound api-in") {
		t.Fatalf("expected inbound target output, got %q", output)
	}
	if !strings.Contains(output, "Cleanup scope: class plus root qdisc") {
		t.Fatalf("expected root qdisc cleanup scope output, got %q", output)
	}
	if !strings.Contains(output, "Executed 2 command(s).") {
		t.Fatalf("expected execution summary, got %q", output)
	}
	if stderr.Len() != 0 {
		t.Fatalf("expected no stderr output, got %q", stderr.String())
	}
}

func TestRunLimitInboundRemoveExecuteRejectsNonRootExecution(t *testing.T) {
	target := testLimitTarget()
	service := &stubDiscoveryService{
		result: discovery.Result{
			Targets: []discovery.RuntimeTarget{target},
		},
	}
	inspector := &stubTCInspector{
		snapshot: tc.Snapshot{
			Device: "eth0",
			Classes: []tc.ClassState{
				testObservedClassForSelection(t, target, limitTargetSelection{Inbound: "api-in"}, "eth0", tc.DirectionUpload, 2048, 2048),
			},
		},
	}
	runner := &stubTCRunner{}
	app := NewApp(service)
	app.tcInspector = inspector
	app.tcRunner = runner
	app.privilegeStatus = func() privilege.Status {
		return privilege.Status{EUID: 1000}
	}

	var stdout bytes.Buffer
	var stderr bytes.Buffer

	exitCode := app.Run([]string{
		"limit",
		"--pid", "1001",
		"--inbound", "api-in",
		"--device", "eth0",
		"--direction", "upload",
		"--remove",
		"--execute",
	}, &stdout, &stderr)

	if exitCode != 1 {
		t.Fatalf("expected exit code 1, got %d", exitCode)
	}

	if !strings.Contains(stdout.String(), "Target: inbound api-in") {
		t.Fatalf("expected inbound target output before privilege failure, got %q", stdout.String())
	}
	if !strings.Contains(stdout.String(), "Operation: remove") {
		t.Fatalf("expected remove output before privilege failure, got %q", stdout.String())
	}
	if !strings.Contains(stderr.String(), "tc execution requires root privileges") {
		t.Fatalf("expected privilege error, got %q", stderr.String())
	}
	if len(runner.commands) != 0 {
		t.Fatalf("expected privilege failure to avoid runner calls, got %#v", runner.commands)
	}
}

func TestRunLimitInboundRemoveExecuteBlocksWithoutSelectorWhenManagedMarkStateExists(t *testing.T) {
	target := testLimitTarget()
	observedClass := testObservedClassForSelection(t, target, limitTargetSelection{Inbound: "api-in"}, "eth0", tc.DirectionUpload, 2048, 2048)
	filter, nftSnapshot := testObservedInboundMarkAttachmentState(t, target, "eth0", tc.DirectionUpload, 2048)
	service := &stubDiscoveryService{
		result: discovery.Result{
			Targets: []discovery.RuntimeTarget{target},
		},
	}
	inspector := &stubTCInspector{
		snapshot: tc.Snapshot{
			Device:  "eth0",
			QDiscs:  []tc.QDiscState{testObservedRootQDisc("1:")},
			Classes: []tc.ClassState{observedClass},
			Filters: []tc.FilterState{filter},
		},
	}
	nftInspector := &stubNftInspector{snapshot: nftSnapshot}
	runner := &stubTCRunner{}
	app := NewApp(service)
	app.tcInspector = inspector
	app.nftInspector = nftInspector
	app.tcRunner = runner
	app.inboundSelector = &stubInboundSelectorDeriver{
		result: discovery.InboundMarkSelectorResult{
			Reason: `concrete inbound attachment for tag "api-in" requires readable Xray config hints; no config path hint is available for inbound tag "api-in"`,
		},
	}
	app.privilegeStatus = func() privilege.Status {
		return privilege.Status{EUID: 0, IsRoot: true}
	}

	var stdout bytes.Buffer
	var stderr bytes.Buffer

	exitCode := app.Run([]string{
		"limit",
		"--pid", "1001",
		"--inbound", "api-in",
		"--device", "eth0",
		"--direction", "upload",
		"--remove",
		"--execute",
	}, &stdout, &stderr)

	if exitCode != 1 {
		t.Fatalf("expected exit code 1, got %d", exitCode)
	}
	if !strings.Contains(stdout.String(), "Execution status: blocked") {
		t.Fatalf("expected blocked execution output, got %q", stdout.String())
	}
	if !strings.Contains(stdout.String(), "real inbound remove execution requires the same concrete inbound mark-backed attachment path used for apply cleanup") {
		t.Fatalf("expected inbound remove blocker note, got %q", stdout.String())
	}
	if len(runner.commands) != 0 {
		t.Fatalf("expected blocked inbound remove to avoid runner calls, got %#v", runner.commands)
	}
	if !strings.Contains(stderr.String(), "error execution: real inbound remove execution requires the same concrete inbound mark-backed attachment path used for apply cleanup") {
		t.Fatalf("expected structured inbound remove blocker, got %q", stderr.String())
	}
}

func TestRunLimitInboundRemoveExecuteBlocksWhenObservedNFTStateIsUnavailable(t *testing.T) {
	target := testLimitTarget()
	observedClass := testObservedClassForSelection(t, target, limitTargetSelection{Inbound: "api-in"}, "eth0", tc.DirectionUpload, 2048, 2048)
	filter, _ := testObservedInboundMarkAttachmentState(t, target, "eth0", tc.DirectionUpload, 2048)
	service := &stubDiscoveryService{
		result: discovery.Result{
			Targets: []discovery.RuntimeTarget{target},
		},
	}
	inspector := &stubTCInspector{
		snapshot: tc.Snapshot{
			Device:  "eth0",
			QDiscs:  []tc.QDiscState{testObservedRootQDisc("1:")},
			Classes: []tc.ClassState{observedClass},
			Filters: []tc.FilterState{filter},
		},
	}
	nftInspector := &stubNftInspector{err: errors.New("nft unavailable")}
	runner := &stubTCRunner{}
	app := NewApp(service)
	app.tcInspector = inspector
	app.nftInspector = nftInspector
	app.tcRunner = runner
	app.inboundSelector = &stubInboundSelectorDeriver{
		result: discovery.InboundMarkSelectorResult{
			Reason: `concrete inbound attachment for tag "api-in" requires readable Xray config hints; no config path hint is available for inbound tag "api-in"`,
		},
	}
	app.privilegeStatus = func() privilege.Status {
		return privilege.Status{EUID: 0, IsRoot: true}
	}

	var stdout bytes.Buffer
	var stderr bytes.Buffer

	exitCode := app.Run([]string{
		"limit",
		"--pid", "1001",
		"--inbound", "api-in",
		"--device", "eth0",
		"--direction", "upload",
		"--remove",
		"--execute",
	}, &stdout, &stderr)

	if exitCode != 1 {
		t.Fatalf("expected exit code 1, got %d", exitCode)
	}
	if !strings.Contains(stdout.String(), "Execution status: blocked") {
		t.Fatalf("expected blocked execution output, got %q", stdout.String())
	}
	if !strings.Contains(stdout.String(), "real inbound remove execution requires observed nftables state when concrete inbound mark-backed cleanup cannot be derived from current config") {
		t.Fatalf("expected inbound nft observation blocker note, got %q", stdout.String())
	}
	if len(runner.commands) != 0 {
		t.Fatalf("expected blocked inbound remove to avoid runner calls, got %#v", runner.commands)
	}
	if !strings.Contains(stderr.String(), "error execution: real inbound remove execution requires observed nftables state when concrete inbound mark-backed cleanup cannot be derived from current config") {
		t.Fatalf("expected structured inbound nft observation blocker, got %q", stderr.String())
	}
}

func TestRunLimitOutboundExecuteRejectsNonRootExecution(t *testing.T) {
	service := &stubDiscoveryService{
		result: discovery.Result{
			Targets: []discovery.RuntimeTarget{testLimitTarget()},
		},
	}
	inspector := &stubTCInspector{
		snapshot: tc.Snapshot{
			Device: "eth0",
		},
	}
	runner := &stubTCRunner{}
	nftInspector := &stubNftInspector{}
	selectorDeriver := &stubOutboundSelectorDeriver{result: testOutboundSelectorResult()}
	app := NewApp(service)
	app.tcInspector = inspector
	app.nftInspector = nftInspector
	app.outboundSelector = selectorDeriver
	app.tcRunner = runner
	app.privilegeStatus = func() privilege.Status {
		return privilege.Status{EUID: 1000}
	}

	var stdout bytes.Buffer
	var stderr bytes.Buffer

	exitCode := app.Run([]string{
		"limit",
		"--pid", "1001",
		"--outbound", "proxy-out",
		"--device", "eth0",
		"--direction", "upload",
		"--rate", "2048",
		"--execute",
	}, &stdout, &stderr)

	if exitCode != 1 {
		t.Fatalf("expected exit code 1, got %d", exitCode)
	}

	if !strings.Contains(stdout.String(), "Target: outbound proxy-out") {
		t.Fatalf("expected outbound target output before privilege failure, got %q", stdout.String())
	}
	if !strings.Contains(stdout.String(), "Reconcile decision: apply") {
		t.Fatalf("expected reconcile output before privilege failure, got %q", stdout.String())
	}
	if !strings.Contains(stderr.String(), "tc execution requires root privileges") {
		t.Fatalf("expected privilege error, got %q", stderr.String())
	}
	if len(runner.commands) != 0 {
		t.Fatalf("expected privilege failure to avoid runner calls, got %#v", runner.commands)
	}
}

func TestRunLimitOutboundExecuteRunsConcreteMarkBackedPlan(t *testing.T) {
	service := &stubDiscoveryService{
		result: discovery.Result{
			Targets: []discovery.RuntimeTarget{testLimitTarget()},
		},
	}
	inspector := &stubTCInspector{
		snapshot: tc.Snapshot{
			Device: "eth0",
		},
	}
	nftInspector := &stubNftInspector{}
	selectorDeriver := &stubOutboundSelectorDeriver{result: testOutboundSelectorResult()}
	runner := &stubTCRunner{
		result: tc.Result{
			Stdout: "ok",
		},
	}
	app := NewApp(service)
	app.tcInspector = inspector
	app.nftInspector = nftInspector
	app.outboundSelector = selectorDeriver
	app.tcRunner = runner
	app.privilegeStatus = func() privilege.Status {
		return privilege.Status{EUID: 0, IsRoot: true}
	}

	var stdout bytes.Buffer
	var stderr bytes.Buffer

	exitCode := app.Run([]string{
		"limit",
		"--pid", "1001",
		"--outbound", "proxy-out",
		"--device", "eth0",
		"--direction", "upload",
		"--rate", "2048",
		"--execute",
		"--format", "json",
	}, &stdout, &stderr)

	if exitCode != 0 {
		t.Fatalf("expected exit code 0, got %d", exitCode)
	}

	var payload struct {
		Mode             string            `json:"mode"`
		ExecutionBlocked bool              `json:"execution_blocked"`
		TargetKind       policy.TargetKind `json:"target_kind"`
		DirectAttachment struct {
			AttachmentReadiness          tc.BindingReadiness `json:"attachment_readiness"`
			AttachmentExecutionReadiness tc.BindingReadiness `json:"attachment_execution_readiness"`
			AttachmentExecutionNote      string              `json:"attachment_execution_note"`
		} `json:"direct_attachment"`
		Plan struct {
			Steps []tc.Step `json:"steps"`
		} `json:"plan"`
		Results []tc.Result `json:"results"`
	}
	if err := json.Unmarshal(stdout.Bytes(), &payload); err != nil {
		t.Fatalf("expected valid JSON output, got %v", err)
	}

	if payload.Mode != "execute" || payload.TargetKind != policy.TargetKindOutbound || payload.ExecutionBlocked {
		t.Fatalf("unexpected outbound execute payload, got %#v", payload)
	}
	if payload.DirectAttachment.AttachmentReadiness != tc.BindingReadinessReady ||
		payload.DirectAttachment.AttachmentExecutionReadiness != tc.BindingReadinessReady ||
		!strings.Contains(payload.DirectAttachment.AttachmentExecutionNote, "selected outbound socket mark") {
		t.Fatalf("unexpected outbound direct attachment payload, got %#v", payload.DirectAttachment)
	}
	if len(payload.Plan.Steps) != 6 || len(payload.Results) != 6 {
		t.Fatalf("expected executed outbound mark-backed plan, got %#v", payload)
	}
	if len(runner.commands) != 6 {
		t.Fatalf("expected outbound execute to run six commands, got %#v", runner.commands)
	}
	if !strings.Contains(strings.Join(runner.commands[2].Args, " "), "add table inet raylimit") {
		t.Fatalf("expected nft table creation in runner calls, got %#v", runner.commands)
	}
	if !strings.Contains(strings.Join(runner.commands[5].Args, " "), "filter replace dev eth0") {
		t.Fatalf("expected tc fw filter creation in runner calls, got %#v", runner.commands)
	}
	if stderr.Len() != 0 {
		t.Fatalf("expected no stderr output, got %q", stderr.String())
	}
}

func TestRunLimitOutboundRemoveExecuteCleansObservedMarkBackedState(t *testing.T) {
	target := testLimitTarget()
	observedClass := testObservedClassForSelection(t, target, limitTargetSelection{Outbound: "proxy-out"}, "eth0", tc.DirectionUpload, 2048, 2048)
	filter, nftSnapshot := testObservedOutboundMarkAttachmentState(t, target, "eth0", tc.DirectionUpload, 2048)
	service := &stubDiscoveryService{
		result: discovery.Result{
			Targets: []discovery.RuntimeTarget{target},
		},
	}
	inspector := &stubTCInspector{
		snapshot: tc.Snapshot{
			Device:  "eth0",
			QDiscs:  []tc.QDiscState{testObservedRootQDisc("1:")},
			Classes: []tc.ClassState{observedClass},
			Filters: []tc.FilterState{filter},
		},
	}
	nftInspector := &stubNftInspector{snapshot: nftSnapshot}
	selectorDeriver := &stubOutboundSelectorDeriver{result: testOutboundSelectorResult()}
	runner := &stubTCRunner{
		result: tc.Result{
			Stdout: "ok",
		},
	}
	app := NewApp(service)
	app.tcInspector = inspector
	app.nftInspector = nftInspector
	app.outboundSelector = selectorDeriver
	app.tcRunner = runner
	app.privilegeStatus = func() privilege.Status {
		return privilege.Status{EUID: 0, IsRoot: true}
	}

	var stdout bytes.Buffer
	var stderr bytes.Buffer

	exitCode := app.Run([]string{
		"limit",
		"--pid", "1001",
		"--outbound", "proxy-out",
		"--device", "eth0",
		"--direction", "upload",
		"--remove",
		"--execute",
	}, &stdout, &stderr)

	if exitCode != 0 {
		t.Fatalf("expected exit code 0, got %d", exitCode)
	}
	if len(runner.commands) != 5 {
		t.Fatalf("expected mark-backed cleanup plus class/root qdisc delete, got %#v", runner.commands)
	}
	if !strings.Contains(strings.Join(runner.commands[0].Args, " "), "filter del dev eth0") {
		t.Fatalf("expected outbound fw filter cleanup first, got %#v", runner.commands[0])
	}
	if !strings.Contains(strings.Join(runner.commands[1].Args, " "), "delete rule inet raylimit") {
		t.Fatalf("expected outbound nft rule cleanup, got %#v", runner.commands[1])
	}
	if !strings.Contains(strings.Join(runner.commands[2].Args, " "), "delete chain inet raylimit") {
		t.Fatalf("expected outbound nft chain cleanup, got %#v", runner.commands[2])
	}
	if runner.commands[4].Args[0] != "qdisc" || runner.commands[4].Args[1] != "del" || runner.commands[4].Args[len(runner.commands[4].Args)-1] != "root" {
		t.Fatalf("expected root qdisc cleanup command, got %#v", runner.commands[4])
	}

	output := stdout.String()
	if !strings.Contains(output, "Target: outbound proxy-out") {
		t.Fatalf("expected outbound target output, got %q", output)
	}
	if !strings.Contains(output, "Cleanup scope: class plus root qdisc") {
		t.Fatalf("expected root qdisc cleanup scope, got %q", output)
	}
	if !strings.Contains(output, "Executed 5 command(s).") {
		t.Fatalf("expected execution summary, got %q", output)
	}
	if stderr.Len() != 0 {
		t.Fatalf("expected no stderr output, got %q", stderr.String())
	}
}

func TestRunLimitOutboundRemoveExecuteBlocksWithoutSelectorWhenManagedMarkStateExists(t *testing.T) {
	target := testLimitTarget()
	observedClass := testObservedClassForSelection(t, target, limitTargetSelection{Outbound: "proxy-out"}, "eth0", tc.DirectionUpload, 2048, 2048)
	filter, nftSnapshot := testObservedOutboundMarkAttachmentState(t, target, "eth0", tc.DirectionUpload, 2048)
	service := &stubDiscoveryService{
		result: discovery.Result{
			Targets: []discovery.RuntimeTarget{target},
		},
	}
	inspector := &stubTCInspector{
		snapshot: tc.Snapshot{
			Device:  "eth0",
			QDiscs:  []tc.QDiscState{testObservedRootQDisc("1:")},
			Classes: []tc.ClassState{observedClass},
			Filters: []tc.FilterState{filter},
		},
	}
	nftInspector := &stubNftInspector{snapshot: nftSnapshot}
	runner := &stubTCRunner{}
	app := NewApp(service)
	app.tcInspector = inspector
	app.nftInspector = nftInspector
	app.tcRunner = runner
	app.outboundSelector = &stubOutboundSelectorDeriver{
		result: discovery.OutboundMarkSelectorResult{
			Reason: `concrete outbound attachment for tag "proxy-out" requires readable Xray config hints; no config path hint is available for outbound tag "proxy-out"`,
		},
	}
	app.privilegeStatus = func() privilege.Status {
		return privilege.Status{EUID: 0, IsRoot: true}
	}

	var stdout bytes.Buffer
	var stderr bytes.Buffer

	exitCode := app.Run([]string{
		"limit",
		"--pid", "1001",
		"--outbound", "proxy-out",
		"--device", "eth0",
		"--direction", "upload",
		"--remove",
		"--execute",
	}, &stdout, &stderr)

	if exitCode != 1 {
		t.Fatalf("expected exit code 1, got %d", exitCode)
	}
	if !strings.Contains(stdout.String(), "Execution status: blocked") {
		t.Fatalf("expected blocked execution output, got %q", stdout.String())
	}
	if !strings.Contains(stdout.String(), "real outbound remove execution requires the same concrete outbound mark-backed attachment path used for apply cleanup") {
		t.Fatalf("expected outbound remove blocker note, got %q", stdout.String())
	}
	if len(runner.commands) != 0 {
		t.Fatalf("expected blocked outbound remove to avoid runner calls, got %#v", runner.commands)
	}
	if !strings.Contains(stderr.String(), "error execution: real outbound remove execution requires the same concrete outbound mark-backed attachment path used for apply cleanup") {
		t.Fatalf("expected structured outbound remove blocker, got %q", stderr.String())
	}
}

func TestRunLimitOutboundRemoveExecuteBlocksWhenObservedNFTStateIsUnavailable(t *testing.T) {
	target := testLimitTarget()
	observedClass := testObservedClassForSelection(t, target, limitTargetSelection{Outbound: "proxy-out"}, "eth0", tc.DirectionUpload, 2048, 2048)
	filter, _ := testObservedOutboundMarkAttachmentState(t, target, "eth0", tc.DirectionUpload, 2048)
	service := &stubDiscoveryService{
		result: discovery.Result{
			Targets: []discovery.RuntimeTarget{target},
		},
	}
	inspector := &stubTCInspector{
		snapshot: tc.Snapshot{
			Device:  "eth0",
			QDiscs:  []tc.QDiscState{testObservedRootQDisc("1:")},
			Classes: []tc.ClassState{observedClass},
			Filters: []tc.FilterState{filter},
		},
	}
	nftInspector := &stubNftInspector{err: errors.New("nft unavailable")}
	runner := &stubTCRunner{}
	app := NewApp(service)
	app.tcInspector = inspector
	app.nftInspector = nftInspector
	app.tcRunner = runner
	app.outboundSelector = &stubOutboundSelectorDeriver{
		result: discovery.OutboundMarkSelectorResult{
			Reason: `concrete outbound attachment for tag "proxy-out" requires readable Xray config hints; no config path hint is available for outbound tag "proxy-out"`,
		},
	}
	app.privilegeStatus = func() privilege.Status {
		return privilege.Status{EUID: 0, IsRoot: true}
	}

	var stdout bytes.Buffer
	var stderr bytes.Buffer

	exitCode := app.Run([]string{
		"limit",
		"--pid", "1001",
		"--outbound", "proxy-out",
		"--device", "eth0",
		"--direction", "upload",
		"--remove",
		"--execute",
	}, &stdout, &stderr)

	if exitCode != 1 {
		t.Fatalf("expected exit code 1, got %d", exitCode)
	}
	if !strings.Contains(stdout.String(), "Execution status: blocked") {
		t.Fatalf("expected blocked execution output, got %q", stdout.String())
	}
	if !strings.Contains(stdout.String(), "real outbound remove execution requires observed nftables state when concrete outbound mark-backed cleanup cannot be derived from current config") {
		t.Fatalf("expected outbound nft observation blocker note, got %q", stdout.String())
	}
	if len(runner.commands) != 0 {
		t.Fatalf("expected blocked outbound remove to avoid runner calls, got %#v", runner.commands)
	}
	if !strings.Contains(stderr.String(), "error execution: real outbound remove execution requires observed nftables state when concrete outbound mark-backed cleanup cannot be derived from current config") {
		t.Fatalf("expected structured outbound nft observation blocker, got %q", stderr.String())
	}
}

func TestRunLimitRemoveExecuteRejectsNonRootExecution(t *testing.T) {
	target := testLimitTarget()
	service := &stubDiscoveryService{
		result: discovery.Result{
			Targets: []discovery.RuntimeTarget{target},
		},
	}
	inspector := &stubTCInspector{
		snapshot: tc.Snapshot{
			Device: "eth0",
			Classes: []tc.ClassState{
				testObservedClass(t, target, "conn-1", "eth0", tc.DirectionUpload, 2048, 2048),
			},
		},
	}
	runner := &stubTCRunner{}
	app := NewApp(service)
	app.tcInspector = inspector
	app.tcRunner = runner
	app.privilegeStatus = func() privilege.Status {
		return privilege.Status{EUID: 1000}
	}

	var stdout bytes.Buffer
	var stderr bytes.Buffer

	exitCode := app.Run([]string{
		"limit",
		"--pid", "1001",
		"--connection", "conn-1",
		"--device", "eth0",
		"--direction", "upload",
		"--remove",
		"--execute",
	}, &stdout, &stderr)

	if exitCode != 1 {
		t.Fatalf("expected exit code 1, got %d", exitCode)
	}

	if !strings.Contains(stdout.String(), "Reconcile decision: remove") {
		t.Fatalf("expected reconcile output before privilege failure, got %q", stdout.String())
	}
	if !strings.Contains(stderr.String(), "tc execution requires root privileges") {
		t.Fatalf("expected privilege error, got %q", stderr.String())
	}
	if len(runner.commands) != 0 {
		t.Fatalf("expected privilege failure to avoid runner calls, got %#v", runner.commands)
	}
}

func TestRunLimitRejectsMissingTargetSelection(t *testing.T) {
	app := NewApp(&stubDiscoveryService{})

	var stdout bytes.Buffer
	var stderr bytes.Buffer

	exitCode := app.Run([]string{
		"limit",
		"--pid", "1001",
		"--device", "eth0",
		"--direction", "upload",
		"--rate", "2048",
	}, &stdout, &stderr)

	if exitCode != 2 {
		t.Fatalf("expected exit code 2, got %d", exitCode)
	}

	if stdout.Len() != 0 {
		t.Fatalf("expected no stdout output, got %q", stdout.String())
	}

	if !strings.Contains(stderr.String(), "select one limit target with --connection, --uuid, --ip, --inbound, or --outbound") {
		t.Fatalf("expected missing-target error, got %q", stderr.String())
	}
}

func TestRunLimitRejectsMultipleTargetSelections(t *testing.T) {
	app := NewApp(&stubDiscoveryService{})

	var stdout bytes.Buffer
	var stderr bytes.Buffer

	exitCode := app.Run([]string{
		"limit",
		"--pid", "1001",
		"--connection", "conn-1",
		"--uuid", "user-a",
		"--device", "eth0",
		"--direction", "upload",
		"--rate", "2048",
	}, &stdout, &stderr)

	if exitCode != 2 {
		t.Fatalf("expected exit code 2, got %d", exitCode)
	}

	if !strings.Contains(stderr.String(), "error validation: select exactly one limit target with --connection, --uuid, --ip, --inbound, or --outbound") {
		t.Fatalf("expected multiple-target validation error, got %q", stderr.String())
	}
}

func TestRunLimitRejectsInvalidIPTargetValue(t *testing.T) {
	service := &stubDiscoveryService{}
	app := NewApp(service)

	var stdout bytes.Buffer
	var stderr bytes.Buffer

	exitCode := app.Run([]string{
		"limit",
		"--pid", "1001",
		"--ip", "not-an-ip",
		"--device", "eth0",
		"--direction", "upload",
		"--rate", "2048",
	}, &stdout, &stderr)

	if exitCode != 2 {
		t.Fatalf("expected exit code 2, got %d", exitCode)
	}
	if !strings.Contains(stderr.String(), `error validation: invalid IP address "not-an-ip" for --ip`) {
		t.Fatalf("expected invalid IP usage error, got %q", stderr.String())
	}
	if service.calls != 0 {
		t.Fatalf("expected invalid IP validation to stop before discovery, got %d calls", service.calls)
	}
}

func TestRunLimitRejectsEmptyInboundTargetValue(t *testing.T) {
	service := &stubDiscoveryService{}
	app := NewApp(service)

	var stdout bytes.Buffer
	var stderr bytes.Buffer

	exitCode := app.Run([]string{
		"limit",
		"--pid", "1001",
		"--inbound", "",
		"--device", "eth0",
		"--direction", "upload",
		"--rate", "2048",
	}, &stdout, &stderr)

	if exitCode != 2 {
		t.Fatalf("expected exit code 2, got %d", exitCode)
	}
	if !strings.Contains(stderr.String(), "select one limit target with --connection, --uuid, --ip, --inbound, or --outbound") {
		t.Fatalf("expected empty inbound usage error, got %q", stderr.String())
	}
	if service.calls != 0 {
		t.Fatalf("expected invalid inbound validation to stop before discovery, got %d calls", service.calls)
	}
}

func TestRunLimitRejectsEmptyOutboundTargetValue(t *testing.T) {
	service := &stubDiscoveryService{}
	app := NewApp(service)

	var stdout bytes.Buffer
	var stderr bytes.Buffer

	exitCode := app.Run([]string{
		"limit",
		"--pid", "1001",
		"--outbound", "",
		"--device", "eth0",
		"--direction", "upload",
		"--rate", "2048",
	}, &stdout, &stderr)

	if exitCode != 2 {
		t.Fatalf("expected exit code 2, got %d", exitCode)
	}
	if !strings.Contains(stderr.String(), "select one limit target with --connection, --uuid, --ip, --inbound, or --outbound") {
		t.Fatalf("expected empty outbound usage error, got %q", stderr.String())
	}
	if service.calls != 0 {
		t.Fatalf("expected invalid outbound validation to stop before discovery, got %d calls", service.calls)
	}
}

func TestRunLimitRejectsMissingRuntimeSelection(t *testing.T) {
	app := NewApp(&stubDiscoveryService{})

	var stdout bytes.Buffer
	var stderr bytes.Buffer

	exitCode := app.Run([]string{
		"limit",
		"--connection", "conn-1",
		"--device", "eth0",
		"--direction", "upload",
		"--rate", "2048",
	}, &stdout, &stderr)

	if exitCode != 2 {
		t.Fatalf("expected exit code 2, got %d", exitCode)
	}

	if stdout.Len() != 0 {
		t.Fatalf("expected no stdout output, got %q", stdout.String())
	}

	if !strings.Contains(stderr.String(), "error validation: select one runtime with --pid, --container, or --name") {
		t.Fatalf("expected runtime-selection error, got %q", stderr.String())
	}
}

func TestRunLimitRejectsMultipleRuntimeSelections(t *testing.T) {
	app := NewApp(&stubDiscoveryService{})

	var stdout bytes.Buffer
	var stderr bytes.Buffer

	exitCode := app.Run([]string{
		"limit",
		"--pid", "1001",
		"--name", "edge-a",
		"--connection", "conn-1",
		"--device", "eth0",
		"--direction", "upload",
		"--rate", "2048",
	}, &stdout, &stderr)

	if exitCode != 2 {
		t.Fatalf("expected exit code 2, got %d", exitCode)
	}

	if !strings.Contains(stderr.String(), "select exactly one runtime with --pid, --container, or --name") {
		t.Fatalf("expected multiple-runtime validation error, got %q", stderr.String())
	}
}

func TestRunLimitRejectsNegativePID(t *testing.T) {
	app := NewApp(&stubDiscoveryService{})

	var stdout bytes.Buffer
	var stderr bytes.Buffer

	exitCode := app.Run([]string{
		"limit",
		"--pid", "-1",
		"--connection", "conn-1",
		"--device", "eth0",
		"--direction", "upload",
		"--rate", "2048",
	}, &stdout, &stderr)

	if exitCode != 2 {
		t.Fatalf("expected exit code 2, got %d", exitCode)
	}

	if !strings.Contains(stderr.String(), "pid must be greater than zero when provided") {
		t.Fatalf("expected negative-pid validation error, got %q", stderr.String())
	}
}

func TestRunLimitRejectsInvalidDirection(t *testing.T) {
	app := NewApp(&stubDiscoveryService{})

	var stdout bytes.Buffer
	var stderr bytes.Buffer

	exitCode := app.Run([]string{
		"limit",
		"--pid", "1001",
		"--connection", "conn-1",
		"--device", "eth0",
		"--direction", "sideways",
		"--rate", "2048",
	}, &stdout, &stderr)

	if exitCode != 2 {
		t.Fatalf("expected exit code 2, got %d", exitCode)
	}

	if stdout.Len() != 0 {
		t.Fatalf("expected no stdout output, got %q", stdout.String())
	}

	if !strings.Contains(stderr.String(), `unsupported direction "sideways"`) {
		t.Fatalf("expected invalid-direction error, got %q", stderr.String())
	}
}

func TestRunLimitRejectsInvalidRate(t *testing.T) {
	app := NewApp(&stubDiscoveryService{})

	var stdout bytes.Buffer
	var stderr bytes.Buffer

	exitCode := app.Run([]string{
		"limit",
		"--pid", "1001",
		"--connection", "conn-1",
		"--device", "eth0",
		"--direction", "upload",
		"--rate", "0",
	}, &stdout, &stderr)

	if exitCode != 2 {
		t.Fatalf("expected exit code 2, got %d", exitCode)
	}

	if stdout.Len() != 0 {
		t.Fatalf("expected no stdout output, got %q", stdout.String())
	}

	if !strings.Contains(stderr.String(), "rate must be greater than zero") {
		t.Fatalf("expected invalid-rate error, got %q", stderr.String())
	}
}

func TestRunLimitRejectsRateWithRemove(t *testing.T) {
	app := NewApp(&stubDiscoveryService{})

	var stdout bytes.Buffer
	var stderr bytes.Buffer

	exitCode := app.Run([]string{
		"limit",
		"--pid", "1001",
		"--connection", "conn-1",
		"--device", "eth0",
		"--direction", "upload",
		"--remove",
		"--rate", "2048",
	}, &stdout, &stderr)

	if exitCode != 2 {
		t.Fatalf("expected exit code 2, got %d", exitCode)
	}

	if !strings.Contains(stderr.String(), "cannot use --rate with --remove") {
		t.Fatalf("expected remove-rate validation error, got %q", stderr.String())
	}
}

func TestRunLimitRejectsAllowMissingTCStateWithoutExecute(t *testing.T) {
	app := NewApp(&stubDiscoveryService{})

	var stdout bytes.Buffer
	var stderr bytes.Buffer

	exitCode := app.Run([]string{
		"limit",
		"--pid", "1001",
		"--connection", "conn-1",
		"--device", "eth0",
		"--direction", "upload",
		"--rate", "2048",
		"--allow-missing-tc-state",
	}, &stdout, &stderr)

	if exitCode != 2 {
		t.Fatalf("expected exit code 2, got %d", exitCode)
	}

	if !strings.Contains(stderr.String(), "cannot use --allow-missing-tc-state without --execute") {
		t.Fatalf("expected allow-missing validation error, got %q", stderr.String())
	}
}

func TestRunLimitHandlesMultipleRuntimeMatches(t *testing.T) {
	service := &stubDiscoveryService{
		result: discovery.Result{
			Targets: []discovery.RuntimeTarget{
				testLimitTarget(),
				{
					Source: discovery.DiscoverySourceHostProcess,
					Identity: discovery.RuntimeIdentity{
						Name:   "edge-a",
						Binary: "xray",
					},
					HostProcess: &discovery.HostProcessCandidate{PID: 1002},
				},
			},
		},
	}
	app := NewApp(service)

	var stdout bytes.Buffer
	var stderr bytes.Buffer

	exitCode := app.Run([]string{
		"limit",
		"--name", "edge-a",
		"--connection", "conn-1",
		"--device", "eth0",
		"--direction", "upload",
		"--rate", "2048",
	}, &stdout, &stderr)

	if exitCode != 1 {
		t.Fatalf("expected exit code 1, got %d", exitCode)
	}

	if stdout.Len() != 0 {
		t.Fatalf("expected no stdout output, got %q", stdout.String())
	}

	if !strings.Contains(stderr.String(), "error selection: multiple runtime targets matched; refine the selection | count=2") {
		t.Fatalf("expected multiple-match error, got %q", stderr.String())
	}
}

func TestRunLimitShowsJSONOutput(t *testing.T) {
	service := &stubDiscoveryService{
		result: discovery.Result{
			Targets: []discovery.RuntimeTarget{testLimitTarget()},
		},
	}
	inspector := &stubTCInspector{
		snapshot: tc.Snapshot{
			Device: "eth0",
		},
	}
	app := NewApp(service)
	app.tcInspector = inspector

	var stdout bytes.Buffer
	var stderr bytes.Buffer

	exitCode := app.Run([]string{
		"limit",
		"--pid", "1001",
		"--connection", "conn-1",
		"--device", "eth0",
		"--direction", "upload",
		"--rate", "2048",
		"--format", "json",
	}, &stdout, &stderr)

	if exitCode != 0 {
		t.Fatalf("expected exit code 0, got %d", exitCode)
	}

	var payload struct {
		Mode             string            `json:"mode"`
		Operation        limitOperation    `json:"operation"`
		TargetKind       policy.TargetKind `json:"target_kind"`
		TargetValue      string            `json:"target_value"`
		ConnectionID     string            `json:"connection_id"`
		DirectAttachment struct {
			AttachmentReadiness          tc.BindingReadiness `json:"attachment_readiness"`
			AttachmentExecutionReadiness tc.BindingReadiness `json:"attachment_execution_readiness"`
		} `json:"direct_attachment"`
		Observation struct {
			Available bool `json:"available"`
			Matched   bool `json:"matched"`
		} `json:"observation"`
		Decision struct {
			Kind string `json:"kind"`
		} `json:"decision"`
		Plan *tc.Plan `json:"plan"`
	}
	if err := json.Unmarshal(stdout.Bytes(), &payload); err != nil {
		t.Fatalf("expected valid JSON output, got %v", err)
	}

	if payload.Mode != "dry-run" {
		t.Fatalf("expected dry-run mode, got %#v", payload)
	}
	if payload.Operation != limitOperationApply {
		t.Fatalf("unexpected JSON operation, got %#v", payload)
	}
	if payload.TargetKind != policy.TargetKindConnection {
		t.Fatalf("unexpected JSON target kind, got %#v", payload)
	}
	if payload.TargetValue != "conn-1" {
		t.Fatalf("unexpected JSON target value: %#v", payload)
	}
	if payload.ConnectionID != "conn-1" {
		t.Fatalf("unexpected JSON connection id: %#v", payload)
	}
	if payload.DirectAttachment.AttachmentReadiness != tc.BindingReadinessPartial ||
		payload.DirectAttachment.AttachmentExecutionReadiness != tc.BindingReadinessUnavailable {
		t.Fatalf("unexpected direct attachment readiness payload: %#v", payload.DirectAttachment)
	}
	if !payload.Observation.Available {
		t.Fatalf("expected JSON observation availability, got %#v", payload)
	}
	if payload.Observation.Matched {
		t.Fatalf("expected JSON observation to show no match, got %#v", payload)
	}
	if payload.Decision.Kind != string(limiter.DecisionApply) {
		t.Fatalf("unexpected JSON decision: %#v", payload)
	}
	if payload.Plan == nil || len(payload.Plan.Steps) != 2 {
		t.Fatalf("expected JSON plan with two steps, got %#v", payload.Plan)
	}
	if stderr.Len() != 0 {
		t.Fatalf("expected no stderr output, got %q", stderr.String())
	}
}

func TestRunLimitConnectionExecuteShowsBlockedJSONOutput(t *testing.T) {
	service := &stubDiscoveryService{
		result: discovery.Result{
			Targets: []discovery.RuntimeTarget{testLimitTarget()},
		},
	}
	inspector := &stubTCInspector{
		snapshot: tc.Snapshot{
			Device: "eth0",
		},
	}
	runner := &stubTCRunner{}
	app := NewApp(service)
	app.tcInspector = inspector
	app.tcRunner = runner
	app.privilegeStatus = func() privilege.Status {
		return privilege.Status{EUID: 0, IsRoot: true}
	}

	var stdout bytes.Buffer
	var stderr bytes.Buffer

	exitCode := app.Run([]string{
		"limit",
		"--pid", "1001",
		"--connection", "conn-1",
		"--device", "eth0",
		"--direction", "upload",
		"--rate", "2048",
		"--execute",
		"--format", "json",
	}, &stdout, &stderr)

	if exitCode != 1 {
		t.Fatalf("expected exit code 1, got %d", exitCode)
	}

	var payload struct {
		Mode             string            `json:"mode"`
		TargetKind       policy.TargetKind `json:"target_kind"`
		ExecutionBlocked bool              `json:"execution_blocked"`
		ExecutionNote    string            `json:"execution_note"`
		DirectAttachment struct {
			AttachmentReadiness          tc.BindingReadiness `json:"attachment_readiness"`
			AttachmentExecutionReadiness tc.BindingReadiness `json:"attachment_execution_readiness"`
			AttachmentExecutionNote      string              `json:"attachment_execution_note"`
		} `json:"direct_attachment"`
		Decision struct {
			Kind string `json:"kind"`
		} `json:"decision"`
		Plan *tc.Plan `json:"plan"`
	}
	if err := json.Unmarshal(stdout.Bytes(), &payload); err != nil {
		t.Fatalf("expected valid JSON output, got %v", err)
	}

	if payload.Mode != "execute" || payload.TargetKind != policy.TargetKindConnection {
		t.Fatalf("unexpected connection execute payload, got %#v", payload)
	}
	if !payload.ExecutionBlocked || !strings.Contains(payload.ExecutionNote, "real connection apply execution remains unavailable until a trustworthy runtime-aware traffic classifier exists") {
		t.Fatalf("expected blocked connection execution payload, got %#v", payload)
	}
	if payload.DirectAttachment.AttachmentReadiness != tc.BindingReadinessPartial ||
		payload.DirectAttachment.AttachmentExecutionReadiness != tc.BindingReadinessUnavailable ||
		!strings.Contains(payload.DirectAttachment.AttachmentExecutionNote, "connection session ids") {
		t.Fatalf("unexpected direct attachment payload, got %#v", payload.DirectAttachment)
	}
	if payload.Decision.Kind != string(limiter.DecisionApply) {
		t.Fatalf("unexpected decision payload, got %#v", payload)
	}
	if payload.Plan == nil || len(payload.Plan.Steps) != 2 {
		t.Fatalf("expected blocked connection execute to retain a preview plan, got %#v", payload.Plan)
	}
	if len(runner.commands) != 0 {
		t.Fatalf("expected blocked connection execute to avoid runner calls, got %#v", runner.commands)
	}
	if !strings.Contains(stderr.String(), "error execution: real connection apply execution remains unavailable until a trustworthy runtime-aware traffic classifier exists") {
		t.Fatalf("expected structured backend blocker, got %q", stderr.String())
	}
}

func TestRunLimitIPShowsJSONOutput(t *testing.T) {
	service := &stubDiscoveryService{
		result: discovery.Result{
			Targets: []discovery.RuntimeTarget{testLimitTarget()},
		},
	}
	inspector := &stubTCInspector{
		snapshot: tc.Snapshot{
			Device: "eth0",
		},
	}
	app := NewApp(service)
	app.tcInspector = inspector

	var stdout bytes.Buffer
	var stderr bytes.Buffer

	exitCode := app.Run([]string{
		"limit",
		"--pid", "1001",
		"--ip", "203.0.113.10",
		"--device", "eth0",
		"--direction", "upload",
		"--rate", "2048",
		"--format", "json",
	}, &stdout, &stderr)

	if exitCode != 0 {
		t.Fatalf("expected exit code 0, got %d", exitCode)
	}

	var payload struct {
		TargetKind       policy.TargetKind `json:"target_kind"`
		TargetValue      string            `json:"target_value"`
		DirectAttachment struct {
			AttachmentReadiness          tc.BindingReadiness       `json:"attachment_readiness"`
			AttachmentExecutionReadiness tc.BindingReadiness       `json:"attachment_execution_readiness"`
			AttachmentExecution          []tc.DirectAttachmentRule `json:"attachment_execution"`
		} `json:"direct_attachment"`
		Observation struct {
			Available         bool  `json:"available"`
			Matched           bool  `json:"matched"`
			AttachmentMatched *bool `json:"attachment_matched"`
		} `json:"observation"`
		Decision struct {
			Kind string `json:"kind"`
		} `json:"decision"`
		Plan *tc.Plan `json:"plan"`
	}
	if err := json.Unmarshal(stdout.Bytes(), &payload); err != nil {
		t.Fatalf("expected valid JSON output, got %v", err)
	}

	if payload.TargetKind != policy.TargetKindIP {
		t.Fatalf("unexpected IP target kind, got %#v", payload)
	}
	if payload.TargetValue != "203.0.113.10" {
		t.Fatalf("unexpected IP target value, got %#v", payload)
	}
	if payload.DirectAttachment.AttachmentReadiness != tc.BindingReadinessReady ||
		payload.DirectAttachment.AttachmentExecutionReadiness != tc.BindingReadinessReady ||
		len(payload.DirectAttachment.AttachmentExecution) != 1 {
		t.Fatalf("unexpected direct attachment payload, got %#v", payload.DirectAttachment)
	}
	if !payload.Observation.Available {
		t.Fatalf("expected JSON observation availability, got %#v", payload)
	}
	if payload.Observation.Matched {
		t.Fatalf("expected JSON observation to show no match, got %#v", payload)
	}
	if payload.Observation.AttachmentMatched == nil || *payload.Observation.AttachmentMatched {
		t.Fatalf("expected attachment observation to report a comparable missing direct attachment rule set, got %#v", payload.Observation)
	}
	if payload.Decision.Kind != string(limiter.DecisionApply) {
		t.Fatalf("unexpected IP decision kind, got %#v", payload)
	}
	if payload.Plan == nil || len(payload.Plan.Steps) != 3 {
		t.Fatalf("expected JSON plan with three steps, got %#v", payload.Plan)
	}
	if stderr.Len() != 0 {
		t.Fatalf("expected no stderr output, got %q", stderr.String())
	}
}

func TestRunLimitInboundShowsJSONOutput(t *testing.T) {
	service := &stubDiscoveryService{
		result: discovery.Result{
			Targets: []discovery.RuntimeTarget{testLimitTarget()},
		},
	}
	inspector := &stubTCInspector{
		snapshot: tc.Snapshot{
			Device: "eth0",
		},
	}
	nftInspector := &stubNftInspector{}
	selectorDeriver := &stubInboundSelectorDeriver{result: testInboundSelectorResult()}
	app := NewApp(service)
	app.tcInspector = inspector
	app.nftInspector = nftInspector
	app.inboundSelector = selectorDeriver

	var stdout bytes.Buffer
	var stderr bytes.Buffer

	exitCode := app.Run([]string{
		"limit",
		"--pid", "1001",
		"--inbound", "api-in",
		"--device", "eth0",
		"--direction", "upload",
		"--rate", "2048",
		"--format", "json",
	}, &stdout, &stderr)

	if exitCode != 0 {
		t.Fatalf("expected exit code 0, got %d", exitCode)
	}

	var payload struct {
		TargetKind       policy.TargetKind `json:"target_kind"`
		TargetValue      string            `json:"target_value"`
		DirectAttachment struct {
			AttachmentReadiness          tc.BindingReadiness `json:"attachment_readiness"`
			AttachmentExecutionReadiness tc.BindingReadiness `json:"attachment_execution_readiness"`
			Note                         string              `json:"note"`
			AttachmentExecutionNote      string              `json:"attachment_execution_note"`
		} `json:"direct_attachment"`
		Observation struct {
			Available bool `json:"available"`
			Matched   bool `json:"matched"`
		} `json:"observation"`
		Decision struct {
			Kind string `json:"kind"`
		} `json:"decision"`
		Plan *tc.Plan `json:"plan"`
	}
	if err := json.Unmarshal(stdout.Bytes(), &payload); err != nil {
		t.Fatalf("expected valid JSON output, got %v", err)
	}

	if payload.TargetKind != policy.TargetKindInbound {
		t.Fatalf("unexpected inbound target kind, got %#v", payload)
	}
	if payload.TargetValue != "api-in" {
		t.Fatalf("unexpected inbound target value, got %#v", payload)
	}
	if payload.DirectAttachment.AttachmentReadiness != tc.BindingReadinessReady ||
		payload.DirectAttachment.AttachmentExecutionReadiness != tc.BindingReadinessReady {
		t.Fatalf("unexpected inbound direct attachment payload, got %#v", payload.DirectAttachment)
	}
	if !strings.Contains(payload.DirectAttachment.Note, `tcp listener 127.0.0.1:8443 for inbound tag "api-in"`) ||
		!strings.Contains(payload.DirectAttachment.AttachmentExecutionNote, "nftables input marking plus output mark restoration") {
		t.Fatalf("unexpected inbound direct attachment notes, got %#v", payload.DirectAttachment)
	}
	if !payload.Observation.Available {
		t.Fatalf("expected JSON observation availability, got %#v", payload)
	}
	if payload.Observation.Matched {
		t.Fatalf("expected JSON observation to show no match, got %#v", payload)
	}
	if payload.Decision.Kind != string(limiter.DecisionApply) {
		t.Fatalf("unexpected inbound decision kind, got %#v", payload)
	}
	if payload.Plan == nil || len(payload.Plan.Steps) != 8 {
		t.Fatalf("expected JSON plan with mark-backed steps, got %#v", payload.Plan)
	}
	if stderr.Len() != 0 {
		t.Fatalf("expected no stderr output, got %q", stderr.String())
	}
}

func TestRunLimitInboundExecuteShowsBlockedJSONOutput(t *testing.T) {
	service := &stubDiscoveryService{
		result: discovery.Result{
			Targets: []discovery.RuntimeTarget{testLimitTarget()},
		},
	}
	inspector := &stubTCInspector{
		snapshot: tc.Snapshot{
			Device: "eth0",
		},
	}
	runner := &stubTCRunner{}
	app := NewApp(service)
	app.tcInspector = inspector
	app.tcRunner = runner
	app.inboundSelector = &stubInboundSelectorDeriver{
		result: discovery.InboundMarkSelectorResult{
			Reason: `concrete inbound attachment for tag "api-in" requires readable Xray config hints; no config path hint is available for inbound tag "api-in"`,
		},
	}
	app.privilegeStatus = func() privilege.Status {
		return privilege.Status{EUID: 0, IsRoot: true}
	}

	var stdout bytes.Buffer
	var stderr bytes.Buffer

	exitCode := app.Run([]string{
		"limit",
		"--pid", "1001",
		"--inbound", "api-in",
		"--device", "eth0",
		"--direction", "upload",
		"--rate", "2048",
		"--execute",
		"--format", "json",
	}, &stdout, &stderr)

	if exitCode != 1 {
		t.Fatalf("expected exit code 1, got %d", exitCode)
	}

	var payload struct {
		Mode             string            `json:"mode"`
		TargetKind       policy.TargetKind `json:"target_kind"`
		ExecutionBlocked bool              `json:"execution_blocked"`
		ExecutionNote    string            `json:"execution_note"`
		DirectAttachment struct {
			AttachmentReadiness          tc.BindingReadiness `json:"attachment_readiness"`
			AttachmentExecutionReadiness tc.BindingReadiness `json:"attachment_execution_readiness"`
			AttachmentExecutionNote      string              `json:"attachment_execution_note"`
		} `json:"direct_attachment"`
		Decision struct {
			Kind string `json:"kind"`
		} `json:"decision"`
		Plan *tc.Plan `json:"plan"`
	}
	if err := json.Unmarshal(stdout.Bytes(), &payload); err != nil {
		t.Fatalf("expected valid JSON output, got %v", err)
	}

	if payload.Mode != "execute" || payload.TargetKind != policy.TargetKindInbound {
		t.Fatalf("unexpected inbound execute payload, got %#v", payload)
	}
	if !payload.ExecutionBlocked || !strings.Contains(payload.ExecutionNote, "real inbound apply execution requires one concrete inbound mark-backed attachment path") {
		t.Fatalf("expected blocked inbound execution payload, got %#v", payload)
	}
	if payload.DirectAttachment.AttachmentReadiness != tc.BindingReadinessUnavailable ||
		payload.DirectAttachment.AttachmentExecutionReadiness != tc.BindingReadinessUnavailable ||
		!strings.Contains(payload.DirectAttachment.AttachmentExecutionNote, "config hints") {
		t.Fatalf("unexpected direct attachment payload, got %#v", payload.DirectAttachment)
	}
	if payload.Decision.Kind != string(limiter.DecisionApply) {
		t.Fatalf("unexpected decision payload, got %#v", payload)
	}
	if payload.Plan == nil || len(payload.Plan.Steps) != 2 {
		t.Fatalf("expected blocked inbound execute to retain a preview plan, got %#v", payload.Plan)
	}
	if len(runner.commands) != 0 {
		t.Fatalf("expected blocked inbound execute to avoid runner calls, got %#v", runner.commands)
	}
	if !strings.Contains(stderr.String(), "error execution: real inbound apply execution requires one concrete inbound mark-backed attachment path") {
		t.Fatalf("expected structured backend blocker, got %q", stderr.String())
	}
}

func TestRunLimitInboundExecuteRunsMarkBackedApplyWhenSelectorIsAvailable(t *testing.T) {
	service := &stubDiscoveryService{
		result: discovery.Result{
			Targets: []discovery.RuntimeTarget{testLimitTarget()},
		},
	}
	inspector := &stubTCInspector{
		snapshot: tc.Snapshot{
			Device: "eth0",
		},
	}
	nftInspector := &stubNftInspector{}
	selectorDeriver := &stubInboundSelectorDeriver{result: testInboundSelectorResult()}
	runner := &stubTCRunner{
		result: tc.Result{
			Stdout: "ok",
		},
	}
	app := NewApp(service)
	app.tcInspector = inspector
	app.nftInspector = nftInspector
	app.inboundSelector = selectorDeriver
	app.tcRunner = runner
	app.privilegeStatus = func() privilege.Status {
		return privilege.Status{EUID: 0, IsRoot: true}
	}

	var stdout bytes.Buffer
	var stderr bytes.Buffer

	exitCode := app.Run([]string{
		"limit",
		"--pid", "1001",
		"--inbound", "api-in",
		"--device", "eth0",
		"--direction", "upload",
		"--rate", "2048",
		"--execute",
		"--format", "json",
	}, &stdout, &stderr)

	if exitCode != 0 {
		t.Fatalf("expected exit code 0, got %d", exitCode)
	}

	var payload struct {
		Mode             string            `json:"mode"`
		ExecutionBlocked bool              `json:"execution_blocked"`
		TargetKind       policy.TargetKind `json:"target_kind"`
		DirectAttachment struct {
			AttachmentReadiness          tc.BindingReadiness `json:"attachment_readiness"`
			AttachmentExecutionReadiness tc.BindingReadiness `json:"attachment_execution_readiness"`
			AttachmentExecutionNote      string              `json:"attachment_execution_note"`
		} `json:"direct_attachment"`
		Plan struct {
			Steps []tc.Step `json:"steps"`
		} `json:"plan"`
		Results []tc.Result `json:"results"`
	}
	if err := json.Unmarshal(stdout.Bytes(), &payload); err != nil {
		t.Fatalf("expected valid JSON output, got %v", err)
	}

	if payload.Mode != "execute" || payload.TargetKind != policy.TargetKindInbound || payload.ExecutionBlocked {
		t.Fatalf("unexpected inbound execute payload, got %#v", payload)
	}
	if payload.DirectAttachment.AttachmentReadiness != tc.BindingReadinessReady ||
		payload.DirectAttachment.AttachmentExecutionReadiness != tc.BindingReadinessReady ||
		!strings.Contains(payload.DirectAttachment.AttachmentExecutionNote, "nftables input marking plus output mark restoration") {
		t.Fatalf("unexpected direct attachment payload, got %#v", payload.DirectAttachment)
	}
	if len(payload.Plan.Steps) != 8 || len(payload.Results) != 8 {
		t.Fatalf("expected executed mark-backed plan, got %#v", payload)
	}
	if len(runner.commands) != 8 {
		t.Fatalf("expected mark-backed execute to run eight commands, got %#v", runner.commands)
	}
	if !strings.Contains(strings.Join(runner.commands[2].Args, " "), "add table inet raylimit") {
		t.Fatalf("expected nft table creation in runner calls, got %#v", runner.commands)
	}
	if !strings.Contains(strings.Join(runner.commands[7].Args, " "), "filter replace dev eth0") {
		t.Fatalf("expected tc fw filter creation in runner calls, got %#v", runner.commands)
	}
	if stderr.Len() != 0 {
		t.Fatalf("expected no stderr output, got %q", stderr.String())
	}
}

func TestRunLimitOutboundShowsReadyJSONOutput(t *testing.T) {
	service := &stubDiscoveryService{
		result: discovery.Result{
			Targets: []discovery.RuntimeTarget{testLimitTarget()},
		},
	}
	inspector := &stubTCInspector{
		snapshot: tc.Snapshot{
			Device: "eth0",
		},
	}
	nftInspector := &stubNftInspector{}
	selectorDeriver := &stubOutboundSelectorDeriver{result: testOutboundSelectorResult()}
	app := NewApp(service)
	app.tcInspector = inspector
	app.nftInspector = nftInspector
	app.outboundSelector = selectorDeriver

	var stdout bytes.Buffer
	var stderr bytes.Buffer

	exitCode := app.Run([]string{
		"limit",
		"--pid", "1001",
		"--outbound", "proxy-out",
		"--device", "eth0",
		"--direction", "upload",
		"--rate", "2048",
		"--format", "json",
	}, &stdout, &stderr)

	if exitCode != 0 {
		t.Fatalf("expected exit code 0, got %d", exitCode)
	}

	var payload struct {
		TargetKind       policy.TargetKind `json:"target_kind"`
		TargetValue      string            `json:"target_value"`
		DirectAttachment struct {
			AttachmentReadiness          tc.BindingReadiness `json:"attachment_readiness"`
			AttachmentExecutionReadiness tc.BindingReadiness `json:"attachment_execution_readiness"`
			Note                         string              `json:"note"`
			AttachmentExecutionNote      string              `json:"attachment_execution_note"`
		} `json:"direct_attachment"`
		Observation struct {
			Available bool `json:"available"`
			Matched   bool `json:"matched"`
		} `json:"observation"`
		Decision struct {
			Kind string `json:"kind"`
		} `json:"decision"`
		Plan *tc.Plan `json:"plan"`
	}
	if err := json.Unmarshal(stdout.Bytes(), &payload); err != nil {
		t.Fatalf("expected valid JSON output, got %v", err)
	}

	if payload.TargetKind != policy.TargetKindOutbound {
		t.Fatalf("unexpected outbound target kind, got %#v", payload)
	}
	if payload.TargetValue != "proxy-out" {
		t.Fatalf("unexpected outbound target value, got %#v", payload)
	}
	if payload.DirectAttachment.AttachmentReadiness != tc.BindingReadinessReady ||
		payload.DirectAttachment.AttachmentExecutionReadiness != tc.BindingReadinessReady {
		t.Fatalf("unexpected outbound direct attachment payload, got %#v", payload.DirectAttachment)
	}
	if !strings.Contains(payload.DirectAttachment.Note, `configured outbound socket mark 0x201 for outbound tag "proxy-out"`) ||
		!strings.Contains(payload.DirectAttachment.AttachmentExecutionNote, "selected outbound socket mark") {
		t.Fatalf("unexpected outbound direct attachment notes, got %#v", payload.DirectAttachment)
	}
	if !payload.Observation.Available {
		t.Fatalf("expected JSON observation availability, got %#v", payload)
	}
	if payload.Observation.Matched {
		t.Fatalf("expected JSON observation to show no match, got %#v", payload)
	}
	if payload.Decision.Kind != string(limiter.DecisionApply) {
		t.Fatalf("unexpected outbound decision kind, got %#v", payload)
	}
	if payload.Plan == nil || len(payload.Plan.Steps) != 6 {
		t.Fatalf("expected JSON mark-backed plan with six steps, got %#v", payload.Plan)
	}
	if stderr.Len() != 0 {
		t.Fatalf("expected no stderr output, got %q", stderr.String())
	}
}

func TestRunLimitUUIDAggregateDryRunPlansSharedClassForSingleMember(t *testing.T) {
	target := testLimitTarget()
	service := &stubDiscoveryService{
		result: discovery.Result{
			Targets: []discovery.RuntimeTarget{target},
		},
	}
	inspector := &stubTCInspector{
		snapshot: tc.Snapshot{
			Device: "eth0",
		},
	}
	correlator := &stubUUIDCorrelator{
		result: testUUIDCorrelationResult(t, target, correlation.UUIDStatusSingleSession, testUUIDSession(t, target, "conn-1")),
	}
	app := NewApp(service)
	app.tcInspector = inspector
	app.uuidCorrelator = correlator

	var stdout bytes.Buffer
	var stderr bytes.Buffer

	exitCode := app.Run([]string{
		"limit",
		"--pid", "1001",
		"--uuid", "user-a",
		"--device", "eth0",
		"--direction", "upload",
		"--rate", "2048",
	}, &stdout, &stderr)

	if exitCode != 0 {
		t.Fatalf("expected exit code 0, got %d", exitCode)
	}

	output := stdout.String()
	for _, fragment := range []string{
		"UUID mode: aggregate_shared_pool",
		"UUID mode note: plain --uuid uses the shared UUID aggregate pool path; concrete execution is available when every live member is attachable by client IP, including native IPv6 and IPv4-mapped IPv6 after canonicalization, and the current non-ip extension now adds fresh RoutingService-backed socket-tuple mark classification in two safe scopes: upload by exact-user local socket tuple and download by exact-user client socket tuple, both without falling back to shared client IP. Stale, partial, or unsupported routing evidence remains blocked, and broader remote-target or metadata-only routing contexts still remain future backend work until a safe exact-user remote-socket classifier exists",
		"UUID aggregate mode: shared_class",
		"Aggregate membership: single_member (1 member(s))",
		"Aggregate shaping readiness: ready",
		"Aggregate attachment readiness: partial",
		"Aggregate attachment execution readiness: ready",
		"Aggregate attachment execution backend: client_ip_u32",
		"Aggregate attachment note: member attachment identities are derived from live sessions; concrete shared-class execution currently requires either attachable client-ip evidence for every live member or fresh exact-user RoutingService socket tuples in the current safe scope",
		"Aggregate attachment execution note: concrete client-ip attachment rules were derived for every live aggregate member; dynamic membership updates remain deferred",
		"Aggregate member attachments:",
		"conn-1 ->",
		"Aggregate attachment execution rules:",
		"client_ip 203.0.113.11/32",
		"Reconcile decision: apply",
		"Planned action: apply",
		"No system changes were made.",
	} {
		if !strings.Contains(output, fragment) {
			t.Fatalf("expected aggregate UUID dry-run output to contain %q, got %q", fragment, output)
		}
	}
	if strings.Contains(output, "Execution policy:") || strings.Contains(output, "Fan-out policy mode:") {
		t.Fatalf("expected aggregate UUID path to avoid execution-policy and fan-out reporting, got %q", output)
	}
	if stderr.Len() != 0 {
		t.Fatalf("expected no stderr output, got %q", stderr.String())
	}
}

func TestRunLimitUUIDAggregateDryRunSupportsNativeIPv6ClientIP(t *testing.T) {
	target := testLimitTarget()
	service := &stubDiscoveryService{
		result: discovery.Result{
			Targets: []discovery.RuntimeTarget{target},
		},
	}
	inspector := &stubTCInspector{
		snapshot: tc.Snapshot{
			Device: "eth0",
		},
	}
	session := testUUIDSession(t, target, "conn-1")
	session.Client.IP = "2001:db8::11"
	correlator := &stubUUIDCorrelator{
		result: testUUIDCorrelationResult(t, target, correlation.UUIDStatusSingleSession, session),
	}
	app := NewApp(service)
	app.tcInspector = inspector
	app.uuidCorrelator = correlator

	var stdout bytes.Buffer
	var stderr bytes.Buffer

	exitCode := app.Run([]string{
		"limit",
		"--pid", "1001",
		"--uuid", "user-a",
		"--device", "eth0",
		"--direction", "upload",
		"--rate", "2048",
	}, &stdout, &stderr)

	if exitCode != 0 {
		t.Fatalf("expected exit code 0, got %d", exitCode)
	}

	output := stdout.String()
	for _, fragment := range []string{
		"Aggregate attachment execution backend: client_ip_u32",
		"Aggregate attachment execution rules:",
		"client_ip 2001:db8::11/128",
		"Execution note: u32 ipv6 client-ip attachment rule targets the shared aggregate class for the current live membership and assumes no ipv6 extension headers",
		"Aggregate attachment execution note: concrete client-ip attachment rules were derived for every live aggregate member; ipv6 rules assume no ipv6 extension headers and dynamic membership updates remain deferred",
	} {
		if !strings.Contains(output, fragment) {
			t.Fatalf("expected native ipv6 aggregate dry-run output to contain %q, got %q", fragment, output)
		}
	}
	if stderr.Len() != 0 {
		t.Fatalf("expected no stderr output, got %q", stderr.String())
	}
}

func TestRunLimitUUIDAggregateDryRunUsesOneSharedClassForMultipleMembers(t *testing.T) {
	target := testLimitTarget()
	service := &stubDiscoveryService{
		result: discovery.Result{
			Targets: []discovery.RuntimeTarget{target},
		},
	}
	inspector := &stubTCInspector{
		snapshot: tc.Snapshot{
			Device: "eth0",
		},
	}
	correlator := &stubUUIDCorrelator{
		result: testUUIDCorrelationResult(
			t,
			target,
			correlation.UUIDStatusMultipleSessions,
			testUUIDSession(t, target, "conn-1"),
			testUUIDSession(t, target, "conn-2"),
		),
	}
	app := NewApp(service)
	app.tcInspector = inspector
	app.uuidCorrelator = correlator

	expectedPlan := testUUIDAggregatePlan(
		t,
		target,
		tc.UUIDAggregateOperationApply,
		"eth0",
		tc.DirectionUpload,
		2048,
		false,
		testUUIDSession(t, target, "conn-1"),
		testUUIDSession(t, target, "conn-2"),
	)

	var stdout bytes.Buffer
	var stderr bytes.Buffer

	exitCode := app.Run([]string{
		"limit",
		"--pid", "1001",
		"--uuid", "user-a",
		"--device", "eth0",
		"--direction", "upload",
		"--rate", "2048",
	}, &stdout, &stderr)

	if exitCode != 0 {
		t.Fatalf("expected exit code 0, got %d", exitCode)
	}

	output := stdout.String()
	if !strings.Contains(output, "Aggregate membership: multiple_members (2 member(s))") {
		t.Fatalf("expected multi-member aggregate output, got %q", output)
	}
	if !strings.Contains(output, "Aggregate class ID: "+expectedPlan.Handles.ClassID) {
		t.Fatalf("expected shared aggregate class id in output, got %q", output)
	}
	if !strings.Contains(output, "Aggregate member attachments:") ||
		!strings.Contains(output, "conn-1 -> "+expectedPlan.Handles.ClassID) ||
		!strings.Contains(output, "conn-2 -> "+expectedPlan.Handles.ClassID) {
		t.Fatalf("expected aggregate attachment output, got %q", output)
	}
	if !strings.Contains(output, "Aggregate attachment execution rules:") ||
		!strings.Contains(output, "client_ip 203.0.113.11/32 -> "+expectedPlan.Handles.ClassID) ||
		!strings.Contains(output, "client_ip 203.0.113.12/32 -> "+expectedPlan.Handles.ClassID) {
		t.Fatalf("expected concrete aggregate attachment execution output, got %q", output)
	}
	if strings.Contains(output, "Per-session fan-out plans:") {
		t.Fatalf("expected aggregate UUID path to avoid fan-out planning output, got %q", output)
	}
	if stderr.Len() != 0 {
		t.Fatalf("expected no stderr output, got %q", stderr.String())
	}
}

func TestRunLimitUUIDAggregateDryRunNoOpWhenObservedClassAndAttachmentRulesMatch(t *testing.T) {
	target := testLimitTarget()
	service := &stubDiscoveryService{
		result: discovery.Result{
			Targets: []discovery.RuntimeTarget{target},
		},
	}
	expectedPlan := testUUIDAggregatePlan(
		t,
		target,
		tc.UUIDAggregateOperationApply,
		"eth0",
		tc.DirectionUpload,
		2048,
		false,
		testUUIDSession(t, target, "conn-1"),
		testUUIDSession(t, target, "conn-2"),
	)
	snapshot := tc.Snapshot{
		Device: "eth0",
		Classes: []tc.ClassState{{
			Kind:               "htb",
			ClassID:            expectedPlan.Handles.ClassID,
			Parent:             expectedPlan.Handles.RootHandle,
			RateBytesPerSecond: 2048,
		}},
	}
	for _, rule := range expectedPlan.AttachmentExecution.Rules {
		snapshot.Filters = append(snapshot.Filters, tc.FilterState{
			Kind:       "u32",
			Parent:     expectedPlan.Handles.RootHandle,
			Protocol:   "ip",
			Preference: rule.Preference,
			FlowID:     expectedPlan.Handles.ClassID,
		})
	}
	inspector := &stubTCInspector{snapshot: snapshot}
	correlator := &stubUUIDCorrelator{
		result: testUUIDCorrelationResult(
			t,
			target,
			correlation.UUIDStatusMultipleSessions,
			testUUIDSession(t, target, "conn-1"),
			testUUIDSession(t, target, "conn-2"),
		),
	}
	app := NewApp(service)
	app.tcInspector = inspector
	app.uuidCorrelator = correlator

	var stdout bytes.Buffer
	var stderr bytes.Buffer

	exitCode := app.Run([]string{
		"limit",
		"--pid", "1001",
		"--uuid", "user-a",
		"--device", "eth0",
		"--direction", "upload",
		"--rate", "2048",
	}, &stdout, &stderr)

	if exitCode != 0 {
		t.Fatalf("expected exit code 0, got %d", exitCode)
	}

	output := stdout.String()
	for _, fragment := range []string{
		"Matching aggregate class: yes",
		"Matching attachment rules: yes",
		"Reconcile decision: no_op",
		"No tc changes are required.",
		"No system changes were made.",
	} {
		if !strings.Contains(output, fragment) {
			t.Fatalf("expected aggregate UUID no-op output to contain %q, got %q", fragment, output)
		}
	}
	if strings.Contains(output, "Planned commands:") {
		t.Fatalf("expected aggregate UUID no-op output to avoid tc commands, got %q", output)
	}
	if stderr.Len() != 0 {
		t.Fatalf("expected no stderr output, got %q", stderr.String())
	}
}

func TestRunLimitUUIDAggregateDryRunReconcilesAttachableMembershipDelta(t *testing.T) {
	target := testLimitTarget()
	service := &stubDiscoveryService{
		result: discovery.Result{
			Targets: []discovery.RuntimeTarget{target},
		},
	}
	currentPlan := testUUIDAggregatePlan(
		t,
		target,
		tc.UUIDAggregateOperationApply,
		"eth0",
		tc.DirectionUpload,
		2048,
		false,
		testUUIDSession(t, target, "conn-1"),
		testUUIDSession(t, target, "conn-3"),
	)
	stalePlan := testUUIDAggregatePlan(
		t,
		target,
		tc.UUIDAggregateOperationApply,
		"eth0",
		tc.DirectionUpload,
		2048,
		false,
		testUUIDSession(t, target, "conn-1"),
		testUUIDSession(t, target, "conn-2"),
	)
	snapshot := tc.Snapshot{
		Device: "eth0",
		QDiscs: []tc.QDiscState{
			testObservedRootQDisc(currentPlan.Handles.RootHandle),
		},
		Classes: []tc.ClassState{{
			Kind:               "htb",
			ClassID:            currentPlan.Handles.ClassID,
			Parent:             currentPlan.Handles.RootHandle,
			RateBytesPerSecond: 2048,
		}},
	}
	for _, rule := range stalePlan.AttachmentExecution.Rules {
		snapshot.Filters = append(snapshot.Filters, tc.FilterState{
			Kind:       "u32",
			Parent:     currentPlan.Handles.RootHandle,
			Protocol:   "ip",
			Preference: rule.Preference,
			FlowID:     currentPlan.Handles.ClassID,
		})
	}
	inspector := &stubTCInspector{snapshot: snapshot}
	correlator := &stubUUIDCorrelator{
		result: testUUIDCorrelationResult(
			t,
			target,
			correlation.UUIDStatusMultipleSessions,
			testUUIDSession(t, target, "conn-1"),
			testUUIDSession(t, target, "conn-3"),
		),
	}
	app := NewApp(service)
	app.tcInspector = inspector
	app.uuidCorrelator = correlator

	var stdout bytes.Buffer
	var stderr bytes.Buffer

	exitCode := app.Run([]string{
		"limit",
		"--pid", "1001",
		"--uuid", "user-a",
		"--device", "eth0",
		"--direction", "upload",
		"--rate", "2048",
	}, &stdout, &stderr)

	if exitCode != 0 {
		t.Fatalf("expected exit code 0, got %d", exitCode)
	}

	output := stdout.String()
	for _, fragment := range []string{
		"Matching aggregate class: yes",
		"Matching attachment rules: no",
		"Reconcile decision: apply",
		"Decision reason: matching shared aggregate class already satisfies the requested UUID rate, but concrete attachment rules did not fully match the current live membership; reconcile the concrete attachment delta",
		"Aggregate member attachability:",
		"conn-3 -> attachable",
		"tc filter del dev eth0 parent 1: protocol ip pref",
		"tc filter replace dev eth0 parent 1: protocol ip pref",
	} {
		if !strings.Contains(output, fragment) {
			t.Fatalf("expected aggregate UUID delta output to contain %q, got %q", fragment, output)
		}
	}
	if strings.Contains(output, "tc class replace dev eth0") || strings.Contains(output, "tc qdisc replace dev eth0") {
		t.Fatalf("expected aggregate UUID delta output to avoid class/qdisc replay when the shared class already matches, got %q", output)
	}
	if stderr.Len() != 0 {
		t.Fatalf("expected no stderr output, got %q", stderr.String())
	}
}

func TestRunLimitUUIDAggregateDryRunRemovesDuplicateAttachableRuleWithoutClassReplay(t *testing.T) {
	target := testLimitTarget()
	service := &stubDiscoveryService{
		result: discovery.Result{
			Targets: []discovery.RuntimeTarget{target},
		},
	}
	currentPlan := testUUIDAggregatePlan(
		t,
		target,
		tc.UUIDAggregateOperationApply,
		"eth0",
		tc.DirectionUpload,
		2048,
		false,
		testUUIDSession(t, target, "conn-1"),
		testUUIDSession(t, target, "conn-2"),
	)
	snapshot := tc.Snapshot{
		Device: "eth0",
		QDiscs: []tc.QDiscState{
			testObservedRootQDisc(currentPlan.Handles.RootHandle),
		},
		Classes: []tc.ClassState{{
			Kind:               "htb",
			ClassID:            currentPlan.Handles.ClassID,
			Parent:             currentPlan.Handles.RootHandle,
			RateBytesPerSecond: 2048,
		}},
	}
	for _, rule := range currentPlan.AttachmentExecution.Rules {
		snapshot.Filters = append(snapshot.Filters, tc.FilterState{
			Kind:       "u32",
			Parent:     currentPlan.Handles.RootHandle,
			Protocol:   "ip",
			Preference: rule.Preference,
			FlowID:     currentPlan.Handles.ClassID,
		})
	}
	snapshot.Filters = append(snapshot.Filters, tc.FilterState{
		Kind:       "u32",
		Parent:     currentPlan.Handles.RootHandle,
		Protocol:   "ip",
		Preference: currentPlan.AttachmentExecution.Rules[0].Preference,
		FlowID:     currentPlan.Handles.ClassID,
	})
	inspector := &stubTCInspector{snapshot: snapshot}
	correlator := &stubUUIDCorrelator{
		result: testUUIDCorrelationResult(
			t,
			target,
			correlation.UUIDStatusMultipleSessions,
			testUUIDSession(t, target, "conn-1"),
			testUUIDSession(t, target, "conn-2"),
		),
	}
	app := NewApp(service)
	app.tcInspector = inspector
	app.uuidCorrelator = correlator

	var stdout bytes.Buffer
	var stderr bytes.Buffer

	exitCode := app.Run([]string{
		"limit",
		"--pid", "1001",
		"--uuid", "user-a",
		"--device", "eth0",
		"--direction", "upload",
		"--rate", "2048",
	}, &stdout, &stderr)

	if exitCode != 0 {
		t.Fatalf("expected exit code 0, got %d", exitCode)
	}

	output := stdout.String()
	for _, fragment := range []string{
		"Matching aggregate class: yes",
		"Matching attachment rules: no",
		"Reconcile decision: apply",
		"tc filter del dev eth0 parent 1: protocol ip pref",
	} {
		if !strings.Contains(output, fragment) {
			t.Fatalf("expected duplicate aggregate rule cleanup output to contain %q, got %q", fragment, output)
		}
	}
	if strings.Contains(output, "tc filter replace dev eth0 parent 1: protocol ip pref") ||
		strings.Contains(output, "tc class replace dev eth0") ||
		strings.Contains(output, "tc qdisc replace dev eth0") {
		t.Fatalf("expected duplicate aggregate rule cleanup to avoid class, qdisc, and missing-rule replay, got %q", output)
	}
	if stderr.Len() != 0 {
		t.Fatalf("expected no stderr output, got %q", stderr.String())
	}
}

func TestRunLimitUUIDAggregateExecuteUsesOneRunnerPathForMultipleMembers(t *testing.T) {
	target := testLimitTarget()
	service := &stubDiscoveryService{
		result: discovery.Result{
			Targets: []discovery.RuntimeTarget{target},
		},
	}
	inspector := &stubTCInspector{
		snapshot: tc.Snapshot{
			Device: "eth0",
		},
	}
	correlator := &stubUUIDCorrelator{
		result: testUUIDCorrelationResult(
			t,
			target,
			correlation.UUIDStatusMultipleSessions,
			testUUIDSession(t, target, "conn-1"),
			testUUIDSession(t, target, "conn-2"),
		),
	}
	runner := &stubTCRunner{
		result: tc.Result{Stdout: "ok"},
	}
	app := NewApp(service)
	app.tcInspector = inspector
	app.nftInspector = &stubNftInspector{snapshot: tc.NftablesSnapshot{}}
	app.uuidCorrelator = correlator
	app.tcRunner = runner
	app.privilegeStatus = func() privilege.Status {
		return privilege.Status{EUID: 0, IsRoot: true}
	}

	var stdout bytes.Buffer
	var stderr bytes.Buffer

	exitCode := app.Run([]string{
		"limit",
		"--pid", "1001",
		"--uuid", "user-a",
		"--device", "eth0",
		"--direction", "upload",
		"--rate", "2048",
		"--execute",
	}, &stdout, &stderr)

	if exitCode != 0 {
		t.Fatalf("expected exit code 0, got %d", exitCode)
	}
	if len(runner.commands) != 4 {
		t.Fatalf("expected shared class execution plus concrete attachment rules, got %#v", runner.commands)
	}
	if runner.commands[2].Args[0] != "filter" || runner.commands[3].Args[0] != "filter" {
		t.Fatalf("expected aggregate execute path to include concrete filter rules, got %#v", runner.commands)
	}
	if !strings.Contains(stdout.String(), "Executed 4 command(s).") {
		t.Fatalf("expected aggregate execute summary, got %q", stdout.String())
	}
	if stderr.Len() != 0 {
		t.Fatalf("expected no stderr output, got %q", stderr.String())
	}
}

func TestRunLimitUUIDAggregateExecuteBlocksWhenCorrelationIsUnavailable(t *testing.T) {
	target := testLimitTarget()
	service := &stubDiscoveryService{
		result: discovery.Result{
			Targets: []discovery.RuntimeTarget{target},
		},
	}
	correlator := &stubUUIDCorrelator{
		result: correlation.UUIDResult{
			Request: correlation.UUIDRequest{
				UUID:    "user-a",
				Runtime: testLimitRuntime(t, target),
			},
			Provider: "xray_api",
			Scope:    correlation.UUIDScopeRuntime,
			Status:   correlation.UUIDStatusUnavailable,
			Note:     "API capability is unknown because no Xray configuration hint is available.",
		},
	}
	app := NewApp(service)
	app.uuidCorrelator = correlator

	var stdout bytes.Buffer
	var stderr bytes.Buffer

	exitCode := app.Run([]string{
		"limit",
		"--pid", "1001",
		"--uuid", "user-a",
		"--device", "eth0",
		"--direction", "upload",
		"--rate", "2048",
		"--execute",
	}, &stdout, &stderr)

	if exitCode != 1 {
		t.Fatalf("expected exit code 1, got %d", exitCode)
	}
	if !strings.Contains(stdout.String(), "UUID aggregate mode: shared_class") {
		t.Fatalf("expected aggregate UUID output, got %q", stdout.String())
	}
	if !strings.Contains(stdout.String(), "Execution status: blocked") {
		t.Fatalf("expected blocked aggregate execution output, got %q", stdout.String())
	}
	if !strings.Contains(stderr.String(), "API capability is unknown because no Xray configuration hint is available.") {
		t.Fatalf("expected aggregate unavailable-correlation error, got %q", stderr.String())
	}
}

func TestRunLimitUUIDAggregateRemoveUsesDeterministicFallbackWhenCorrelationIsUnavailable(t *testing.T) {
	target := testLimitTarget()
	removePlan := testUUIDAggregatePlan(
		t,
		target,
		tc.UUIDAggregateOperationRemove,
		"eth0",
		tc.DirectionUpload,
		0,
		false,
	)
	service := &stubDiscoveryService{
		result: discovery.Result{
			Targets: []discovery.RuntimeTarget{target},
		},
	}
	inspector := &stubTCInspector{
		snapshot: tc.Snapshot{
			Device: "eth0",
			QDiscs: []tc.QDiscState{
				testObservedRootQDisc(removePlan.Handles.RootHandle),
			},
			Classes: []tc.ClassState{
				{
					Kind:               "htb",
					ClassID:            removePlan.Handles.ClassID,
					Parent:             removePlan.Handles.RootHandle,
					RateBytesPerSecond: 2048,
				},
			},
		},
	}
	correlator := &stubUUIDCorrelator{
		result: correlation.UUIDResult{
			Request: correlation.UUIDRequest{
				UUID:    "user-a",
				Runtime: testLimitRuntime(t, target),
			},
			Scope:  correlation.UUIDScopeRuntime,
			Status: correlation.UUIDStatusUnavailable,
			Note:   "API capability is unknown because no Xray configuration hint is available.",
		},
	}
	app := NewApp(service)
	app.tcInspector = inspector
	app.uuidCorrelator = correlator

	var stdout bytes.Buffer
	var stderr bytes.Buffer

	exitCode := app.Run([]string{
		"limit",
		"--pid", "1001",
		"--uuid", "user-a",
		"--device", "eth0",
		"--direction", "upload",
		"--remove",
	}, &stdout, &stderr)

	if exitCode != 0 {
		t.Fatalf("expected exit code 0, got %d", exitCode)
	}

	output := stdout.String()
	for _, fragment := range []string{
		"Correlation status: unavailable",
		"Aggregate membership: unavailable",
		"Aggregate note: live aggregate membership is unavailable; remove planning falls back to the deterministic shared class identity and observed tc state only",
		"Aggregate attachment note: live aggregate membership is unavailable; current member attachments cannot be derived during remove fallback",
		"Aggregate attachment execution note: live aggregate membership is unavailable; concrete member attachment rules cannot be derived during remove fallback",
		"Reconcile decision: remove",
		"Cleanup scope: class plus root qdisc",
	} {
		if !strings.Contains(output, fragment) {
			t.Fatalf("expected unavailable-correlation aggregate remove output to contain %q, got %q", fragment, output)
		}
	}
	if stderr.Len() != 0 {
		t.Fatalf("expected no stderr output, got %q", stderr.String())
	}
}

func TestRunLimitUUIDAggregateExecuteBlocksWhenConcreteAttachmentExecutionIsUnavailable(t *testing.T) {
	target := testLimitTarget()
	service := &stubDiscoveryService{
		result: discovery.Result{
			Targets: []discovery.RuntimeTarget{target},
		},
	}
	session := testUUIDSession(t, target, "conn-1")
	session.Client.IP = ""
	correlator := &stubUUIDCorrelator{
		result: testUUIDCorrelationResult(t, target, correlation.UUIDStatusSingleSession, session),
	}
	backendDeriver := &stubUUIDNonIPBackendCandidateDeriver{
		result: discovery.UUIDNonIPBackendCandidate{
			Status:       discovery.UUIDNonIPBackendStatusCandidate,
			Kind:         discovery.UUIDNonIPBackendKindRoutingStatsPortClassifier,
			OutboundTags: []string{"proxy-out"},
			Reason:       `readable Xray config enables RoutingService and exact user routing for UUID "user-a"; live routing contexts can already drive the concrete local-socket and client-socket UUID backends, and the next broader exact-user-safe step is a remote-socket classifier that combines local and target tuple evidence without falling back to shared client IP`,
		},
	}
	app := NewApp(service)
	app.uuidCorrelator = correlator
	app.uuidNonIPBackend = backendDeriver
	app.tcRunner = &stubTCRunner{}
	app.privilegeStatus = func() privilege.Status {
		return privilege.Status{EUID: 0, IsRoot: true}
	}

	var stdout bytes.Buffer
	var stderr bytes.Buffer

	exitCode := app.Run([]string{
		"limit",
		"--pid", "1001",
		"--uuid", "user-a",
		"--device", "eth0",
		"--direction", "upload",
		"--rate", "2048",
		"--execute",
	}, &stdout, &stderr)

	if exitCode != 1 {
		t.Fatalf("expected exit code 1, got %d", exitCode)
	}
	if !strings.Contains(stdout.String(), "Execution status: blocked") {
		t.Fatalf("expected blocked aggregate execution output, got %q", stdout.String())
	}
	if !strings.Contains(stdout.String(), "Aggregate attachment execution readiness: unavailable") {
		t.Fatalf("expected aggregate attachment execution readiness output, got %q", stdout.String())
	}
	if !strings.Contains(stdout.String(), "Aggregate member attachability:") ||
		!strings.Contains(stdout.String(), "conn-1 -> missing_client_ip") ||
		!strings.Contains(stdout.String(), "Attachability note: live member has no client-ip evidence") {
		t.Fatalf("expected blocked aggregate execution output to expose member attachability, got %q", stdout.String())
	}
	if !strings.Contains(stdout.String(), "Aggregate non-IP backend status: candidate") ||
		!strings.Contains(stdout.String(), "Aggregate non-IP backend kind: routing_stats_port_classifier") ||
		!strings.Contains(stdout.String(), "Aggregate non-IP backend outbound tags: proxy-out") {
		t.Fatalf("expected blocked aggregate execution output to expose the next non-ip backend candidate, got %q", stdout.String())
	}
	if !strings.Contains(stdout.String(), "Decision reason: concrete aggregate attachment currently requires attachable client ip evidence for every live member; missing client ip evidence for: conn-1; no fresh RoutingService-backed UUID routing evidence was supplied for the non-ip backend; concrete uuid aggregate execution remains blocked until either every live member is attachable by client ip or fresh RoutingService-backed non-ip classifier evidence is concrete and safe to enforce") {
		t.Fatalf("expected blocked aggregate dry-run decision truth in execute output, got %q", stdout.String())
	}
	if !strings.Contains(stderr.String(), "real shared uuid aggregate execution remains blocked unless the aggregate has either concrete attachable client-ip evidence for every live member or fresh safe RoutingService-backed non-ip attachment evidence") ||
		!strings.Contains(stderr.String(), "stale, partial, missing, or unsupported non-ip evidence still remains blocked") {
		t.Fatalf("expected aggregate attachment-execution blocker, got %q", stderr.String())
	}
}

func TestRunLimitUUIDAggregateDryRunExplainsNonAttachableMembersAreBlockedByDesign(t *testing.T) {
	target := testLimitTarget()
	service := &stubDiscoveryService{
		result: discovery.Result{
			Targets: []discovery.RuntimeTarget{target},
		},
	}
	session := testUUIDSession(t, target, "conn-1")
	session.Client.IP = ""
	correlator := &stubUUIDCorrelator{
		result: testUUIDCorrelationResult(t, target, correlation.UUIDStatusSingleSession, session),
	}
	backendDeriver := &stubUUIDNonIPBackendCandidateDeriver{
		result: discovery.UUIDNonIPBackendCandidate{
			Status: discovery.UUIDNonIPBackendStatusCandidate,
			Kind:   discovery.UUIDNonIPBackendKindRoutingStatsPortClassifier,
			Reason: `readable Xray config enables RoutingService and exact user routing for UUID "user-a"; live routing contexts can already drive the concrete local-socket and client-socket UUID backends, and the next broader exact-user-safe step is a remote-socket classifier that combines local and target tuple evidence without falling back to shared client IP`,
		},
	}
	app := NewApp(service)
	app.uuidCorrelator = correlator
	app.uuidNonIPBackend = backendDeriver

	var stdout bytes.Buffer
	var stderr bytes.Buffer

	exitCode := app.Run([]string{
		"limit",
		"--pid", "1001",
		"--uuid", "user-a",
		"--device", "eth0",
		"--direction", "upload",
		"--rate", "2048",
	}, &stdout, &stderr)

	if exitCode != 0 {
		t.Fatalf("expected exit code 0, got %d", exitCode)
	}
	if !strings.Contains(stdout.String(), "Aggregate attachment execution readiness: unavailable") {
		t.Fatalf("expected unavailable aggregate attachment execution readiness, got %q", stdout.String())
	}
	if !strings.Contains(stdout.String(), "Decision reason: concrete aggregate attachment currently requires attachable client ip evidence for every live member; missing client ip evidence for: conn-1; no fresh RoutingService-backed UUID routing evidence was supplied for the non-ip backend; concrete uuid aggregate execution remains blocked until either every live member is attachable by client ip or fresh RoutingService-backed non-ip classifier evidence is concrete and safe to enforce") {
		t.Fatalf("expected non-attachable dry-run decision reason, got %q", stdout.String())
	}
	if !strings.Contains(stdout.String(), "Aggregate member attachability:") ||
		!strings.Contains(stdout.String(), "conn-1 -> missing_client_ip") {
		t.Fatalf("expected non-attachable dry-run output to expose member attachability, got %q", stdout.String())
	}
	if !strings.Contains(stdout.String(), "Aggregate non-IP backend status: candidate") ||
		!strings.Contains(stdout.String(), "Aggregate non-IP backend kind: routing_stats_port_classifier") ||
		!strings.Contains(stdout.String(), "Aggregate non-IP backend note: readable Xray config enables RoutingService and exact user routing") {
		t.Fatalf("expected non-attachable dry-run output to expose the next non-ip backend candidate, got %q", stdout.String())
	}
	if stderr.Len() != 0 {
		t.Fatalf("expected no stderr output, got %q", stderr.String())
	}
}

func TestRunLimitUUIDAggregateDryRunPlansConcreteRoutingMarkBackendWhenFreshEvidenceExists(t *testing.T) {
	target := testLimitTarget()
	service := &stubDiscoveryService{
		result: discovery.Result{
			Targets: []discovery.RuntimeTarget{target},
		},
	}
	session := testUUIDSession(t, target, "conn-1")
	session.Client.IP = ""
	correlator := &stubUUIDCorrelator{
		result: testUUIDCorrelationResult(t, target, correlation.UUIDStatusSingleSession, session),
	}
	routingProvider := &stubUUIDRoutingEvidenceProvider{
		result: testUUIDRoutingEvidenceResult(
			t,
			target,
			"user-a",
			testUUIDRoutingContext(t, target, "user-a", "tcp", "10.10.0.2", 8443),
		),
	}
	inspector := &stubTCInspector{
		snapshot: tc.Snapshot{
			Device: "eth0",
		},
	}
	nftInspector := &stubNftInspector{
		snapshot: tc.NftablesSnapshot{},
	}
	app := NewApp(service)
	app.tcInspector = inspector
	app.nftInspector = nftInspector
	app.uuidCorrelator = correlator
	app.uuidRoutingEvidence = routingProvider

	var stdout bytes.Buffer
	var stderr bytes.Buffer

	exitCode := app.Run([]string{
		"limit",
		"--pid", "1001",
		"--uuid", "user-a",
		"--device", "eth0",
		"--direction", "upload",
		"--rate", "2048",
	}, &stdout, &stderr)

	if exitCode != 0 {
		t.Fatalf("expected exit code 0, got %d", exitCode)
	}
	if len(routingProvider.requests) != 1 {
		t.Fatalf("expected one uuid routing evidence lookup, got %#v", routingProvider.requests)
	}
	if nftInspector.requests != 1 {
		t.Fatalf("expected one nftables inspection for the mark-backed UUID backend, got %d", nftInspector.requests)
	}

	output := stdout.String()
	for _, fragment := range []string{
		"Aggregate attachment execution readiness: ready",
		"Aggregate attachment execution backend: routing_local_socket_fw",
		"Aggregate routing evidence state: live",
		"Aggregate routing evidence freshness: fresh",
		"Aggregate mark-backed attachment execution rules:",
		"fresh RoutingService-derived TCP local socket 10.10.0.2:8443 selects the shared uuid class without falling back to shared client ip",
		"nft add table inet raylimit",
		"nft add chain inet raylimit raylimit_uuid_routing_context_upload",
		"nft add rule inet raylimit raylimit_uuid_routing_context_upload",
		"tc filter replace dev eth0 parent 1: protocol all",
	} {
		if !strings.Contains(output, fragment) {
			t.Fatalf("expected concrete non-ip UUID output to contain %q, got %q", fragment, output)
		}
	}
	if strings.Contains(output, "Aggregate attachment execution rules:\n") {
		t.Fatalf("expected concrete non-ip UUID output to use mark-backed aggregate execution reporting, got %q", output)
	}
	if stderr.Len() != 0 {
		t.Fatalf("expected no stderr output, got %q", stderr.String())
	}
}

func TestRunLimitUUIDAggregateDryRunPlansConcreteRoutingClientMarkBackendWhenFreshDownloadEvidenceExists(t *testing.T) {
	target := testLimitTarget()
	service := &stubDiscoveryService{
		result: discovery.Result{
			Targets: []discovery.RuntimeTarget{target},
		},
	}
	session := testUUIDSession(t, target, "conn-1")
	session.Client.IP = ""
	correlator := &stubUUIDCorrelator{
		result: testUUIDCorrelationResult(t, target, correlation.UUIDStatusSingleSession, session),
	}
	routingProvider := &stubUUIDRoutingEvidenceProvider{
		result: testUUIDRoutingEvidenceResult(
			t,
			target,
			"user-a",
			testUUIDClientRoutingContext(t, target, "user-a", "tcp", "198.51.100.44", 43120),
		),
	}
	inspector := &stubTCInspector{
		snapshot: tc.Snapshot{
			Device: "eth0",
		},
	}
	nftInspector := &stubNftInspector{
		snapshot: tc.NftablesSnapshot{},
	}
	app := NewApp(service)
	app.tcInspector = inspector
	app.nftInspector = nftInspector
	app.uuidCorrelator = correlator
	app.uuidRoutingEvidence = routingProvider

	var stdout bytes.Buffer
	var stderr bytes.Buffer

	exitCode := app.Run([]string{
		"limit",
		"--pid", "1001",
		"--uuid", "user-a",
		"--device", "eth0",
		"--direction", "download",
		"--rate", "2048",
	}, &stdout, &stderr)

	if exitCode != 0 {
		t.Fatalf("expected exit code 0, got %d", exitCode)
	}
	if len(routingProvider.requests) != 1 {
		t.Fatalf("expected one uuid routing evidence lookup, got %#v", routingProvider.requests)
	}
	if nftInspector.requests != 1 {
		t.Fatalf("expected one nftables inspection for the download mark-backed UUID backend, got %d", nftInspector.requests)
	}

	output := stdout.String()
	for _, fragment := range []string{
		"Aggregate attachment execution readiness: ready",
		"Aggregate attachment execution backend: routing_client_socket_fw",
		"Aggregate routing evidence state: live",
		"Aggregate routing evidence freshness: fresh",
		"Aggregate mark-backed attachment execution rules:",
		"fresh RoutingService-derived TCP client socket 198.51.100.44:43120 selects the shared uuid class without falling back to shared client ip",
		"nft add table inet raylimit",
		"nft add chain inet raylimit raylimit_uuid_routing_context_download",
		"nft add rule inet raylimit raylimit_uuid_routing_context_download",
		"tc filter replace dev eth0 parent 1: protocol all",
	} {
		if !strings.Contains(output, fragment) {
			t.Fatalf("expected concrete non-ip UUID download output to contain %q, got %q", fragment, output)
		}
	}
	if strings.Contains(output, "Aggregate attachment execution rules:\n") {
		t.Fatalf("expected concrete non-ip UUID download output to use mark-backed aggregate execution reporting, got %q", output)
	}
	if stderr.Len() != 0 {
		t.Fatalf("expected no stderr output, got %q", stderr.String())
	}
}

func TestRunLimitUUIDAggregateExecuteReportsUnavailableRoutingEvidenceClearly(t *testing.T) {
	target := testLimitTarget()
	service := &stubDiscoveryService{
		result: discovery.Result{
			Targets: []discovery.RuntimeTarget{target},
		},
	}
	session := testUUIDSession(t, target, "conn-1")
	session.Client.IP = ""
	correlator := &stubUUIDCorrelator{
		result: testUUIDCorrelationResult(t, target, correlation.UUIDStatusSingleSession, session),
	}
	result := testUUIDRoutingEvidenceResult(t, target, "user-a")
	result.Issues = []discovery.SessionEvidenceIssue{{
		Code:    discovery.SessionEvidenceIssueUnavailable,
		Message: "RoutingService endpoint is unavailable for live uuid routing evidence",
	}}
	if err := result.Validate(); err != nil {
		t.Fatalf("expected unavailable uuid routing evidence to validate, got %v", err)
	}
	routingProvider := &stubUUIDRoutingEvidenceProvider{result: result}
	app := NewApp(service)
	app.uuidCorrelator = correlator
	app.uuidRoutingEvidence = routingProvider
	app.tcRunner = &stubTCRunner{}
	app.privilegeStatus = func() privilege.Status {
		return privilege.Status{EUID: 0, IsRoot: true}
	}

	var stdout bytes.Buffer
	var stderr bytes.Buffer

	exitCode := app.Run([]string{
		"limit",
		"--pid", "1001",
		"--uuid", "user-a",
		"--device", "eth0",
		"--direction", "upload",
		"--rate", "2048",
		"--execute",
	}, &stdout, &stderr)

	if exitCode != 1 {
		t.Fatalf("expected exit code 1, got %d", exitCode)
	}
	output := stdout.String()
	for _, fragment := range []string{
		"Execution status: blocked",
		"Aggregate attachment execution readiness: unavailable",
		"Aggregate routing evidence state: unavailable",
		"Aggregate routing evidence freshness: unavailable",
		"Aggregate routing evidence note: uuid routing evidence is currently unavailable; RoutingService endpoint is unavailable for live uuid routing evidence",
	} {
		if !strings.Contains(output, fragment) {
			t.Fatalf("expected blocked weak-evidence output to contain %q, got %q", fragment, output)
		}
	}
	if !strings.Contains(stderr.String(), "real shared uuid aggregate execution remains blocked unless the aggregate has either concrete attachable client-ip evidence for every live member or fresh safe RoutingService-backed non-ip attachment evidence") {
		t.Fatalf("expected unavailable-evidence execute blocker, got %q", stderr.String())
	}
}

func TestRunLimitUUIDAggregateDryRunExplainsRemoteTargetOnlyEvidenceRemainsBlocked(t *testing.T) {
	target := testLimitTarget()
	service := &stubDiscoveryService{
		result: discovery.Result{
			Targets: []discovery.RuntimeTarget{target},
		},
	}
	session := testUUIDSession(t, target, "conn-1")
	session.Client.IP = ""
	correlator := &stubUUIDCorrelator{
		result: testUUIDCorrelationResult(t, target, correlation.UUIDStatusSingleSession, session),
	}
	routingProvider := &stubUUIDRoutingEvidenceProvider{
		result: testUUIDRoutingEvidenceResult(
			t,
			target,
			"user-a",
			testUUIDTargetRoutingContext(t, target, "user-a", "tcp", "203.0.113.200", 443),
		),
	}
	app := NewApp(service)
	app.tcInspector = &stubTCInspector{snapshot: tc.Snapshot{Device: "eth0"}}
	app.nftInspector = &stubNftInspector{snapshot: tc.NftablesSnapshot{}}
	app.uuidCorrelator = correlator
	app.uuidRoutingEvidence = routingProvider

	var stdout bytes.Buffer
	var stderr bytes.Buffer

	exitCode := app.Run([]string{
		"limit",
		"--pid", "1001",
		"--uuid", "user-a",
		"--device", "eth0",
		"--direction", "upload",
		"--rate", "2048",
	}, &stdout, &stderr)

	if exitCode != 0 {
		t.Fatalf("expected exit code 0, got %d", exitCode)
	}
	output := stdout.String()
	for _, fragment := range []string{
		"Aggregate attachment execution readiness: unavailable",
		"Aggregate routing evidence state: live",
		"Aggregate routing evidence freshness: fresh",
		"remote target ip and port can be shared across users and are not yet a safe uuid classifier on their own",
	} {
		if !strings.Contains(output, fragment) {
			t.Fatalf("expected blocked remote-target-only UUID output to contain %q, got %q", fragment, output)
		}
	}
	if stderr.Len() != 0 {
		t.Fatalf("expected no stderr output, got %q", stderr.String())
	}
}

func TestRunLimitUUIDAggregateBlockedJSONReportsNonIPBackendCandidate(t *testing.T) {
	target := testLimitTarget()
	service := &stubDiscoveryService{
		result: discovery.Result{
			Targets: []discovery.RuntimeTarget{target},
		},
	}
	session := testUUIDSession(t, target, "conn-1")
	session.Client.IP = ""
	correlator := &stubUUIDCorrelator{
		result: testUUIDCorrelationResult(t, target, correlation.UUIDStatusSingleSession, session),
	}
	app := NewApp(service)
	app.uuidCorrelator = correlator
	app.uuidNonIPBackend = &stubUUIDNonIPBackendCandidateDeriver{
		result: discovery.UUIDNonIPBackendCandidate{
			Status:       discovery.UUIDNonIPBackendStatusCandidate,
			Kind:         discovery.UUIDNonIPBackendKindRoutingStatsPortClassifier,
			OutboundTags: []string{"proxy-out"},
			Reason:       `readable Xray config enables RoutingService and exact user routing for UUID "user-a"; live routing contexts can already drive the concrete local-socket and client-socket UUID backends, and the next broader exact-user-safe step is a remote-socket classifier that combines local and target tuple evidence without falling back to shared client IP`,
		},
	}

	var stdout bytes.Buffer
	var stderr bytes.Buffer

	exitCode := app.Run([]string{
		"limit",
		"--pid", "1001",
		"--uuid", "user-a",
		"--device", "eth0",
		"--direction", "upload",
		"--rate", "2048",
		"--format", "json",
	}, &stdout, &stderr)

	if exitCode != 0 {
		t.Fatalf("expected exit code 0, got %d", exitCode)
	}

	var payload struct {
		UUIDAggregate struct {
			NonIPBackend struct {
				Status       string   `json:"status"`
				Kind         string   `json:"kind"`
				OutboundTags []string `json:"outbound_tags"`
				Reason       string   `json:"reason"`
			} `json:"non_ip_backend"`
		} `json:"uuid_aggregate"`
	}
	if err := json.Unmarshal(stdout.Bytes(), &payload); err != nil {
		t.Fatalf("expected valid JSON output, got %v", err)
	}

	if payload.UUIDAggregate.NonIPBackend.Status != string(discovery.UUIDNonIPBackendStatusCandidate) ||
		payload.UUIDAggregate.NonIPBackend.Kind != string(discovery.UUIDNonIPBackendKindRoutingStatsPortClassifier) ||
		len(payload.UUIDAggregate.NonIPBackend.OutboundTags) != 1 ||
		payload.UUIDAggregate.NonIPBackend.OutboundTags[0] != "proxy-out" ||
		!strings.Contains(payload.UUIDAggregate.NonIPBackend.Reason, "RoutingService") {
		t.Fatalf("expected non-ip backend candidate payload, got %#v", payload)
	}
	if stderr.Len() != 0 {
		t.Fatalf("expected no stderr output, got %q", stderr.String())
	}
}

func TestRunLimitUUIDAggregateRemoveReportsFullCleanupScope(t *testing.T) {
	target := testLimitTarget()
	service := &stubDiscoveryService{
		result: discovery.Result{
			Targets: []discovery.RuntimeTarget{target},
		},
	}
	removePlan := testUUIDAggregatePlan(
		t,
		target,
		tc.UUIDAggregateOperationRemove,
		"eth0",
		tc.DirectionUpload,
		0,
		false,
	)
	inspector := &stubTCInspector{
		snapshot: tc.Snapshot{
			Device: "eth0",
			QDiscs: []tc.QDiscState{
				testObservedRootQDisc(removePlan.Handles.RootHandle),
			},
			Classes: []tc.ClassState{
				{
					Kind:               "htb",
					ClassID:            removePlan.Handles.ClassID,
					Parent:             removePlan.Handles.RootHandle,
					RateBytesPerSecond: 2048,
				},
			},
		},
	}
	correlator := &stubUUIDCorrelator{
		result: testUUIDCorrelationResult(t, target, correlation.UUIDStatusZeroSessions),
	}
	app := NewApp(service)
	app.tcInspector = inspector
	app.uuidCorrelator = correlator

	var stdout bytes.Buffer
	var stderr bytes.Buffer

	exitCode := app.Run([]string{
		"limit",
		"--pid", "1001",
		"--uuid", "user-a",
		"--device", "eth0",
		"--direction", "upload",
		"--remove",
	}, &stdout, &stderr)

	if exitCode != 0 {
		t.Fatalf("expected exit code 0, got %d", exitCode)
	}
	if !strings.Contains(stdout.String(), "Cleanup scope: class plus root qdisc") {
		t.Fatalf("expected aggregate cleanup scope output, got %q", stdout.String())
	}
	if !strings.Contains(stdout.String(), "Planned action: remove") {
		t.Fatalf("expected aggregate remove planning output, got %q", stdout.String())
	}
	if stderr.Len() != 0 {
		t.Fatalf("expected no stderr output, got %q", stderr.String())
	}
}

func TestRunLimitUUIDAggregateRemoveExecuteUsesDeterministicFallbackWhenCorrelationIsUnavailable(t *testing.T) {
	target := testLimitTarget()
	removePlan := testUUIDAggregatePlan(
		t,
		target,
		tc.UUIDAggregateOperationRemove,
		"eth0",
		tc.DirectionUpload,
		0,
		false,
	)
	service := &stubDiscoveryService{
		result: discovery.Result{
			Targets: []discovery.RuntimeTarget{target},
		},
	}
	inspector := &stubTCInspector{
		snapshot: tc.Snapshot{
			Device: "eth0",
			QDiscs: []tc.QDiscState{
				testObservedRootQDisc(removePlan.Handles.RootHandle),
			},
			Classes: []tc.ClassState{
				{
					Kind:               "htb",
					ClassID:            removePlan.Handles.ClassID,
					Parent:             removePlan.Handles.RootHandle,
					RateBytesPerSecond: 2048,
				},
			},
			Filters: []tc.FilterState{
				{Kind: "u32", Parent: removePlan.Handles.RootHandle, Protocol: "ip", Preference: 180, FlowID: removePlan.Handles.ClassID},
				{Kind: "u32", Parent: removePlan.Handles.RootHandle, Protocol: "ip", Preference: 220, FlowID: removePlan.Handles.ClassID},
			},
		},
	}
	correlator := &stubUUIDCorrelator{
		result: correlation.UUIDResult{
			Request: correlation.UUIDRequest{
				UUID:    "user-a",
				Runtime: testLimitRuntime(t, target),
			},
			Scope:  correlation.UUIDScopeRuntime,
			Status: correlation.UUIDStatusUnavailable,
			Note:   "API capability is unknown because no Xray configuration hint is available.",
		},
	}
	runner := &stubTCRunner{
		result: tc.Result{Stdout: "ok"},
	}
	app := NewApp(service)
	app.tcInspector = inspector
	app.nftInspector = &stubNftInspector{snapshot: tc.NftablesSnapshot{}}
	app.uuidCorrelator = correlator
	app.tcRunner = runner
	app.privilegeStatus = func() privilege.Status {
		return privilege.Status{EUID: 0, IsRoot: true}
	}

	var stdout bytes.Buffer
	var stderr bytes.Buffer

	exitCode := app.Run([]string{
		"limit",
		"--pid", "1001",
		"--uuid", "user-a",
		"--device", "eth0",
		"--direction", "upload",
		"--remove",
		"--execute",
	}, &stdout, &stderr)

	if exitCode != 0 {
		t.Fatalf("expected exit code 0, got %d", exitCode)
	}
	if len(runner.commands) != 4 {
		t.Fatalf("expected observed aggregate filter cleanup, class delete, and root qdisc delete, got %#v", runner.commands)
	}
	if runner.commands[0].Args[0] != "filter" || runner.commands[1].Args[0] != "filter" || runner.commands[2].Args[0] != "class" || runner.commands[3].Args[0] != "qdisc" {
		t.Fatalf("expected aggregate fallback remove command ordering, got %#v", runner.commands)
	}
	if !strings.Contains(stdout.String(), "Executed 4 command(s).") {
		t.Fatalf("expected aggregate fallback remove execute summary, got %q", stdout.String())
	}
	if stderr.Len() != 0 {
		t.Fatalf("expected no stderr output, got %q", stderr.String())
	}
}

func TestRunLimitUUIDAggregateRemoveExecuteWithUnavailableCorrelationStillRequiresObservedTCState(t *testing.T) {
	target := testLimitTarget()
	service := &stubDiscoveryService{
		result: discovery.Result{
			Targets: []discovery.RuntimeTarget{target},
		},
	}
	inspector := &stubTCInspector{
		err: errors.New("permission denied"),
	}
	correlator := &stubUUIDCorrelator{
		result: correlation.UUIDResult{
			Request: correlation.UUIDRequest{
				UUID:    "user-a",
				Runtime: testLimitRuntime(t, target),
			},
			Scope:  correlation.UUIDScopeRuntime,
			Status: correlation.UUIDStatusUnavailable,
			Note:   "API capability is unknown because no Xray configuration hint is available.",
		},
	}
	app := NewApp(service)
	app.tcInspector = inspector
	app.uuidCorrelator = correlator
	app.tcRunner = &stubTCRunner{}
	app.privilegeStatus = func() privilege.Status {
		return privilege.Status{EUID: 0, IsRoot: true}
	}

	var stdout bytes.Buffer
	var stderr bytes.Buffer

	exitCode := app.Run([]string{
		"limit",
		"--pid", "1001",
		"--uuid", "user-a",
		"--device", "eth0",
		"--direction", "upload",
		"--remove",
		"--execute",
	}, &stdout, &stderr)

	if exitCode != 1 {
		t.Fatalf("expected exit code 1, got %d", exitCode)
	}
	if !strings.Contains(stdout.String(), "Execution status: blocked") {
		t.Fatalf("expected blocked aggregate remove output, got %q", stdout.String())
	}
	if !strings.Contains(stderr.String(), "real execution requires observed tc state") {
		t.Fatalf("expected observed-state blocker on aggregate fallback remove, got %q", stderr.String())
	}
}

func TestRunLimitUUIDAggregateRemoveExecuteUsesObservedAttachmentCleanupWhenLiveMembersAreGone(t *testing.T) {
	target := testLimitTarget()
	service := &stubDiscoveryService{
		result: discovery.Result{
			Targets: []discovery.RuntimeTarget{target},
		},
	}
	removePlan := testUUIDAggregatePlan(
		t,
		target,
		tc.UUIDAggregateOperationRemove,
		"eth0",
		tc.DirectionUpload,
		0,
		false,
	)
	inspector := &stubTCInspector{
		snapshot: tc.Snapshot{
			Device: "eth0",
			QDiscs: []tc.QDiscState{
				testObservedRootQDisc(removePlan.Handles.RootHandle),
			},
			Classes: []tc.ClassState{
				{
					Kind:               "htb",
					ClassID:            removePlan.Handles.ClassID,
					Parent:             removePlan.Handles.RootHandle,
					RateBytesPerSecond: 2048,
				},
			},
			Filters: []tc.FilterState{
				{Kind: "u32", Parent: removePlan.Handles.RootHandle, Protocol: "ip", Preference: 220, FlowID: removePlan.Handles.ClassID},
				{Kind: "u32", Parent: removePlan.Handles.RootHandle, Protocol: "ip", Preference: 180, FlowID: removePlan.Handles.ClassID},
			},
		},
	}
	correlator := &stubUUIDCorrelator{
		result: testUUIDCorrelationResult(t, target, correlation.UUIDStatusZeroSessions),
	}
	runner := &stubTCRunner{
		result: tc.Result{Stdout: "ok"},
	}
	app := NewApp(service)
	app.tcInspector = inspector
	app.nftInspector = &stubNftInspector{snapshot: tc.NftablesSnapshot{}}
	app.uuidCorrelator = correlator
	app.tcRunner = runner
	app.privilegeStatus = func() privilege.Status {
		return privilege.Status{EUID: 0, IsRoot: true}
	}

	var stdout bytes.Buffer
	var stderr bytes.Buffer

	exitCode := app.Run([]string{
		"limit",
		"--pid", "1001",
		"--uuid", "user-a",
		"--device", "eth0",
		"--direction", "upload",
		"--remove",
		"--execute",
	}, &stdout, &stderr)

	if exitCode != 0 {
		t.Fatalf("expected exit code 0, got %d", exitCode)
	}
	if len(runner.commands) != 4 {
		t.Fatalf("expected observed attachment cleanup, aggregate class removal, and root qdisc cleanup, got %#v", runner.commands)
	}
	if runner.commands[0].Args[0] != "filter" || runner.commands[1].Args[0] != "filter" || runner.commands[2].Args[0] != "class" || runner.commands[3].Args[0] != "qdisc" {
		t.Fatalf("expected two observed filter deletes followed by class and root qdisc delete, got %#v", runner.commands)
	}
	if runner.commands[0].Args[9] != "180" || runner.commands[1].Args[9] != "220" {
		t.Fatalf("expected observed filter cleanup to remain preference-ordered, got %#v", runner.commands)
	}
	if !strings.Contains(stdout.String(), "Executed 4 command(s).") {
		t.Fatalf("expected aggregate remove execute summary, got %q", stdout.String())
	}
	if stderr.Len() != 0 {
		t.Fatalf("expected no stderr output, got %q", stderr.String())
	}
}

func TestRunLimitUUIDAggregateRemoveExecuteUsesObservedRoutingRuleCleanupWhenLiveEvidenceIsWeak(t *testing.T) {
	target := testLimitTarget()
	service := &stubDiscoveryService{
		result: discovery.Result{
			Targets: []discovery.RuntimeTarget{target},
		},
	}
	_, snapshot, nftSnapshot := testObservedUUIDAggregateRoutingMarkState(t, target, "eth0", tc.DirectionUpload, 2048, "10.10.0.2", 8443)
	snapshot.Filters = nil
	inspector := &stubTCInspector{snapshot: snapshot}
	nftInspector := &stubNftInspector{snapshot: nftSnapshot}
	correlator := &stubUUIDCorrelator{
		result: testUUIDCorrelationResult(t, target, correlation.UUIDStatusZeroSessions),
	}
	runner := &stubTCRunner{result: tc.Result{Stdout: "ok"}}
	app := NewApp(service)
	app.tcInspector = inspector
	app.nftInspector = nftInspector
	app.uuidCorrelator = correlator
	app.tcRunner = runner
	app.privilegeStatus = func() privilege.Status {
		return privilege.Status{EUID: 0, IsRoot: true}
	}

	var stdout bytes.Buffer
	var stderr bytes.Buffer

	exitCode := app.Run([]string{
		"limit",
		"--pid", "1001",
		"--uuid", "user-a",
		"--device", "eth0",
		"--direction", "upload",
		"--remove",
		"--execute",
	}, &stdout, &stderr)

	if exitCode != 0 {
		t.Fatalf("expected exit code 0, got %d", exitCode)
	}
	if nftInspector.requests != 1 {
		t.Fatalf("expected weak-evidence remove to inspect nftables state, got %d", nftInspector.requests)
	}
	if len(runner.commands) != 3 {
		t.Fatalf("expected nft rule cleanup, class delete, and root qdisc cleanup for weak-evidence remove, got %#v", runner.commands)
	}
	if runner.commands[0].Path != "nft" || runner.commands[0].Args[0] != "delete" || runner.commands[0].Args[1] != "rule" {
		t.Fatalf("expected first weak-evidence remove command to delete the observed nft rule, got %#v", runner.commands)
	}
	if runner.commands[1].Args[0] != "class" || runner.commands[1].Args[1] != "del" {
		t.Fatalf("expected weak-evidence remove to delete the shared class after nft cleanup, got %#v", runner.commands)
	}
	if runner.commands[2].Args[0] != "qdisc" || runner.commands[2].Args[1] != "del" {
		t.Fatalf("expected weak-evidence remove to clean up the root qdisc after nft cleanup, got %#v", runner.commands)
	}
	if !strings.Contains(stdout.String(), "Executed 3 command(s).") {
		t.Fatalf("expected weak-evidence remove execute summary, got %q", stdout.String())
	}
	if stderr.Len() != 0 {
		t.Fatalf("expected no stderr output, got %q", stderr.String())
	}
}

func TestRunLimitUUIDAggregateRemoveExecuteBlocksWhenObservedRoutingMarkCleanupNeedsNFTState(t *testing.T) {
	target := testLimitTarget()
	service := &stubDiscoveryService{
		result: discovery.Result{
			Targets: []discovery.RuntimeTarget{target},
		},
	}
	_, snapshot, _ := testObservedUUIDAggregateRoutingMarkState(t, target, "eth0", tc.DirectionUpload, 2048, "10.10.0.2", 8443)
	inspector := &stubTCInspector{snapshot: snapshot}
	nftInspector := &stubNftInspector{err: errors.New("nft unavailable")}
	correlator := &stubUUIDCorrelator{
		result: testUUIDCorrelationResult(t, target, correlation.UUIDStatusZeroSessions),
	}
	runner := &stubTCRunner{result: tc.Result{Stdout: "ok"}}
	app := NewApp(service)
	app.tcInspector = inspector
	app.nftInspector = nftInspector
	app.uuidCorrelator = correlator
	app.tcRunner = runner
	app.privilegeStatus = func() privilege.Status {
		return privilege.Status{EUID: 0, IsRoot: true}
	}

	var stdout bytes.Buffer
	var stderr bytes.Buffer

	exitCode := app.Run([]string{
		"limit",
		"--pid", "1001",
		"--uuid", "user-a",
		"--device", "eth0",
		"--direction", "upload",
		"--remove",
		"--execute",
	}, &stdout, &stderr)

	if exitCode != 1 {
		t.Fatalf("expected exit code 1, got %d", exitCode)
	}
	if len(runner.commands) != 0 {
		t.Fatalf("expected blocked weak-evidence remove to avoid runner calls, got %#v", runner.commands)
	}
	if !strings.Contains(stdout.String(), "Execution status: blocked") {
		t.Fatalf("expected blocked weak-evidence remove output, got %q", stdout.String())
	}
	if !strings.Contains(stderr.String(), "concrete mark-backed execution requires observed tc and nftables state") ||
		!strings.Contains(stderr.String(), "nftables state inspection failed: nft unavailable") {
		t.Fatalf("expected mark-backed weak-evidence remove blocker, got %q", stderr.String())
	}
}

func TestRunLimitUUIDAggregateRemoveExecuteUsesObservedAttachmentCleanupWhenClassIsAlreadyGone(t *testing.T) {
	target := testLimitTarget()
	service := &stubDiscoveryService{
		result: discovery.Result{
			Targets: []discovery.RuntimeTarget{target},
		},
	}
	removePlan := testUUIDAggregatePlan(
		t,
		target,
		tc.UUIDAggregateOperationRemove,
		"eth0",
		tc.DirectionUpload,
		0,
		false,
	)
	inspector := &stubTCInspector{
		snapshot: tc.Snapshot{
			Device: "eth0",
			QDiscs: []tc.QDiscState{
				testObservedRootQDisc(removePlan.Handles.RootHandle),
			},
			Filters: []tc.FilterState{
				{Kind: "u32", Parent: removePlan.Handles.RootHandle, Protocol: "ip", Preference: 220, FlowID: removePlan.Handles.ClassID},
				{Kind: "u32", Parent: removePlan.Handles.RootHandle, Protocol: "ip", Preference: 180, FlowID: removePlan.Handles.ClassID},
			},
		},
	}
	correlator := &stubUUIDCorrelator{
		result: testUUIDCorrelationResult(t, target, correlation.UUIDStatusZeroSessions),
	}
	runner := &stubTCRunner{
		result: tc.Result{Stdout: "ok"},
	}
	app := NewApp(service)
	app.tcInspector = inspector
	app.nftInspector = &stubNftInspector{snapshot: tc.NftablesSnapshot{}}
	app.uuidCorrelator = correlator
	app.tcRunner = runner
	app.privilegeStatus = func() privilege.Status {
		return privilege.Status{EUID: 0, IsRoot: true}
	}

	var stdout bytes.Buffer
	var stderr bytes.Buffer

	exitCode := app.Run([]string{
		"limit",
		"--pid", "1001",
		"--uuid", "user-a",
		"--device", "eth0",
		"--direction", "upload",
		"--remove",
		"--execute",
	}, &stdout, &stderr)

	if exitCode != 0 {
		t.Fatalf("expected exit code 0, got %d", exitCode)
	}
	if len(runner.commands) != 3 {
		t.Fatalf("expected observed attachment cleanup plus root qdisc cleanup without a class delete, got %#v", runner.commands)
	}
	if runner.commands[0].Args[0] != "filter" || runner.commands[1].Args[0] != "filter" || runner.commands[2].Args[0] != "qdisc" {
		t.Fatalf("expected two observed filter deletes followed by root qdisc delete, got %#v", runner.commands)
	}
	if !strings.Contains(stdout.String(), "Cleanup scope: attachment rules plus root qdisc") {
		t.Fatalf("expected attachment-only cleanup scope output, got %q", stdout.String())
	}
	if !strings.Contains(stdout.String(), "Executed 3 command(s).") {
		t.Fatalf("expected aggregate attachment-only remove execute summary, got %q", stdout.String())
	}
	if stderr.Len() != 0 {
		t.Fatalf("expected no stderr output, got %q", stderr.String())
	}
}

func TestRunLimitUUIDAggregateRemoveWithUnavailableCorrelationShowsJSONOutput(t *testing.T) {
	target := testLimitTarget()
	removePlan := testUUIDAggregatePlan(
		t,
		target,
		tc.UUIDAggregateOperationRemove,
		"eth0",
		tc.DirectionUpload,
		0,
		false,
	)
	service := &stubDiscoveryService{
		result: discovery.Result{
			Targets: []discovery.RuntimeTarget{target},
		},
	}
	inspector := &stubTCInspector{
		snapshot: tc.Snapshot{
			Device: "eth0",
			Classes: []tc.ClassState{
				{
					Kind:               "htb",
					ClassID:            removePlan.Handles.ClassID,
					Parent:             removePlan.Handles.RootHandle,
					RateBytesPerSecond: 2048,
				},
			},
		},
	}
	correlator := &stubUUIDCorrelator{
		result: correlation.UUIDResult{
			Request: correlation.UUIDRequest{
				UUID:    "user-a",
				Runtime: testLimitRuntime(t, target),
			},
			Scope:  correlation.UUIDScopeRuntime,
			Status: correlation.UUIDStatusUnavailable,
			Note:   "API capability is unknown because no Xray configuration hint is available.",
		},
	}
	app := NewApp(service)
	app.tcInspector = inspector
	app.uuidCorrelator = correlator

	var stdout bytes.Buffer
	var stderr bytes.Buffer

	exitCode := app.Run([]string{
		"limit",
		"--pid", "1001",
		"--uuid", "user-a",
		"--device", "eth0",
		"--direction", "upload",
		"--remove",
		"--format", "json",
	}, &stdout, &stderr)

	if exitCode != 0 {
		t.Fatalf("expected exit code 0, got %d", exitCode)
	}

	var payload struct {
		Correlation struct {
			Status string `json:"status"`
		} `json:"correlation"`
		UUIDAggregate struct {
			MemberCount                  int    `json:"member_count"`
			Cardinality                  string `json:"membership_cardinality"`
			SharedClassID                string `json:"shared_class_id"`
			AttachmentReadiness          string `json:"attachment_readiness"`
			AttachmentExecutionReadiness string `json:"attachment_execution_readiness"`
			Note                         string `json:"note"`
			AttachmentNote               string `json:"attachment_note"`
			AttachmentExecutionNote      string `json:"attachment_execution_note"`
			Attachments                  []any  `json:"attachments"`
			AttachmentExecution          []any  `json:"attachment_execution"`
			Decision                     struct {
				Kind string `json:"kind"`
			} `json:"decision"`
			Plan struct {
				Operation string `json:"operation"`
			} `json:"plan"`
		} `json:"uuid_aggregate"`
	}
	if err := json.Unmarshal(stdout.Bytes(), &payload); err != nil {
		t.Fatalf("expected valid JSON output, got %v", err)
	}

	if payload.Correlation.Status != string(correlation.UUIDStatusUnavailable) {
		t.Fatalf("unexpected aggregate correlation payload, got %#v", payload)
	}
	if payload.UUIDAggregate.MemberCount != 0 || payload.UUIDAggregate.Cardinality != "" {
		t.Fatalf("expected unavailable aggregate membership reporting, got %#v", payload)
	}
	if payload.UUIDAggregate.SharedClassID == "" {
		t.Fatalf("expected deterministic shared class id in fallback remove JSON, got %#v", payload)
	}
	if payload.UUIDAggregate.AttachmentReadiness != string(tc.BindingReadinessUnavailable) ||
		payload.UUIDAggregate.AttachmentExecutionReadiness != string(tc.BindingReadinessUnavailable) {
		t.Fatalf("unexpected aggregate attachment readiness payload, got %#v", payload)
	}
	if !strings.Contains(payload.UUIDAggregate.Note, "remove planning falls back") ||
		!strings.Contains(payload.UUIDAggregate.AttachmentNote, "cannot be derived during remove fallback") ||
		!strings.Contains(payload.UUIDAggregate.AttachmentExecutionNote, "cannot be derived during remove fallback") {
		t.Fatalf("unexpected aggregate fallback notes, got %#v", payload)
	}
	if len(payload.UUIDAggregate.Attachments) != 0 || len(payload.UUIDAggregate.AttachmentExecution) != 0 {
		t.Fatalf("expected unavailable aggregate fallback to avoid attachment payloads, got %#v", payload)
	}
	if payload.UUIDAggregate.Decision.Kind != string(limiter.DecisionRemove) || payload.UUIDAggregate.Plan.Operation != string(tc.UUIDAggregateOperationRemove) {
		t.Fatalf("unexpected aggregate fallback remove plan payload, got %#v", payload)
	}
	if stderr.Len() != 0 {
		t.Fatalf("expected no stderr output, got %q", stderr.String())
	}
}

func TestRunLimitUUIDAggregateShowsJSONOutput(t *testing.T) {
	target := testLimitTarget()
	service := &stubDiscoveryService{
		result: discovery.Result{
			Targets: []discovery.RuntimeTarget{target},
		},
	}
	inspector := &stubTCInspector{
		snapshot: tc.Snapshot{
			Device: "eth0",
		},
	}
	correlator := &stubUUIDCorrelator{
		result: testUUIDCorrelationResult(
			t,
			target,
			correlation.UUIDStatusMultipleSessions,
			testUUIDSession(t, target, "conn-1"),
			testUUIDSession(t, target, "conn-2"),
		),
	}
	app := NewApp(service)
	app.tcInspector = inspector
	app.uuidCorrelator = correlator

	var stdout bytes.Buffer
	var stderr bytes.Buffer

	exitCode := app.Run([]string{
		"limit",
		"--pid", "1001",
		"--uuid", "user-a",
		"--device", "eth0",
		"--direction", "upload",
		"--rate", "2048",
		"--format", "json",
	}, &stdout, &stderr)

	if exitCode != 0 {
		t.Fatalf("expected exit code 0, got %d", exitCode)
	}

	var payload struct {
		TargetKind   string `json:"target_kind"`
		UUIDMode     string `json:"uuid_mode"`
		UUIDModeNote string `json:"uuid_mode_note"`
		Correlation  struct {
			Status              string `json:"status"`
			MatchedSessionCount int    `json:"matched_session_count"`
		} `json:"correlation"`
		UUIDAggregate struct {
			Mode                         string `json:"mode"`
			MemberCount                  int    `json:"member_count"`
			Cardinality                  string `json:"membership_cardinality"`
			SharedClassID                string `json:"shared_class_id"`
			AttachmentReadiness          string `json:"attachment_readiness"`
			AttachmentExecutionReadiness string `json:"attachment_execution_readiness"`
			AttachmentNote               string `json:"attachment_note"`
			AttachmentExecutionNote      string `json:"attachment_execution_note"`
			MemberAttachability          []struct {
				Status            string `json:"status"`
				RawClientIP       string `json:"raw_client_ip"`
				CanonicalClientIP string `json:"canonical_client_ip"`
				Reason            string `json:"reason"`
				Member            struct {
					Session struct {
						ID string `json:"id"`
					} `json:"session"`
				} `json:"member"`
			} `json:"member_attachability"`
			Attachments []struct {
				AggregateClassID string `json:"aggregate_class_id"`
				Identity         struct {
					Kind  string `json:"kind"`
					Value string `json:"value"`
				} `json:"identity"`
				Member struct {
					Session struct {
						ID string `json:"id"`
					} `json:"session"`
				} `json:"member"`
			} `json:"attachments"`
			AttachmentExecution []struct {
				AggregateClassID string   `json:"aggregate_class_id"`
				MatchField       string   `json:"match_field"`
				Preference       uint32   `json:"preference"`
				MemberSessionIDs []string `json:"member_session_ids"`
				Identity         struct {
					Kind  string `json:"kind"`
					Value string `json:"value"`
				} `json:"identity"`
			} `json:"attachment_execution"`
			Decision struct {
				Kind string `json:"kind"`
			} `json:"decision"`
			Plan struct {
				Operation string `json:"operation"`
			} `json:"plan"`
		} `json:"uuid_aggregate"`
	}
	if err := json.Unmarshal(stdout.Bytes(), &payload); err != nil {
		t.Fatalf("expected valid JSON output, got %v", err)
	}

	if payload.TargetKind != string(policy.TargetKindUUID) {
		t.Fatalf("unexpected aggregate target kind, got %#v", payload)
	}
	if payload.UUIDMode != string(limitUUIDModeAggregateSharedPool) {
		t.Fatalf("unexpected aggregate UUID mode, got %#v", payload)
	}
	if !strings.Contains(payload.UUIDModeNote, "plain --uuid uses the shared UUID aggregate pool path") {
		t.Fatalf("unexpected aggregate UUID mode note, got %#v", payload)
	}
	if payload.Correlation.Status != string(correlation.UUIDStatusMultipleSessions) || payload.Correlation.MatchedSessionCount != 2 {
		t.Fatalf("unexpected aggregate correlation payload, got %#v", payload)
	}
	if payload.UUIDAggregate.Mode != "shared_class" {
		t.Fatalf("unexpected aggregate mode, got %#v", payload)
	}
	if payload.UUIDAggregate.MemberCount != 2 || payload.UUIDAggregate.Cardinality != string(correlation.UUIDAggregateCardinalityMultiple) {
		t.Fatalf("unexpected aggregate membership payload, got %#v", payload)
	}
	if payload.UUIDAggregate.SharedClassID == "" || payload.UUIDAggregate.AttachmentReadiness != string(tc.BindingReadinessPartial) {
		t.Fatalf("unexpected aggregate binding payload, got %#v", payload)
	}
	if payload.UUIDAggregate.AttachmentExecutionReadiness != string(tc.BindingReadinessReady) {
		t.Fatalf("unexpected aggregate attachment execution readiness, got %#v", payload)
	}
	if payload.UUIDAggregate.AttachmentNote == "" || len(payload.UUIDAggregate.Attachments) != 2 {
		t.Fatalf("unexpected aggregate attachment payload, got %#v", payload)
	}
	if payload.UUIDAggregate.AttachmentExecutionNote == "" || len(payload.UUIDAggregate.AttachmentExecution) != 2 {
		t.Fatalf("unexpected aggregate attachment execution payload, got %#v", payload)
	}
	if len(payload.UUIDAggregate.MemberAttachability) != 2 ||
		payload.UUIDAggregate.MemberAttachability[0].Member.Session.ID != "conn-1" ||
		payload.UUIDAggregate.MemberAttachability[0].Status != string(tc.UUIDAggregateMemberAttachabilityAttachable) ||
		payload.UUIDAggregate.MemberAttachability[0].CanonicalClientIP != "203.0.113.11" ||
		payload.UUIDAggregate.MemberAttachability[1].Member.Session.ID != "conn-2" ||
		payload.UUIDAggregate.MemberAttachability[1].Status != string(tc.UUIDAggregateMemberAttachabilityAttachable) ||
		payload.UUIDAggregate.MemberAttachability[1].CanonicalClientIP != "203.0.113.12" {
		t.Fatalf("unexpected aggregate member attachability payload, got %#v", payload)
	}
	if payload.UUIDAggregate.Attachments[0].Member.Session.ID != "conn-1" ||
		payload.UUIDAggregate.Attachments[0].Identity.Kind != string(tc.IdentityKindSession) ||
		payload.UUIDAggregate.Attachments[0].AggregateClassID != payload.UUIDAggregate.SharedClassID {
		t.Fatalf("unexpected first aggregate attachment payload, got %#v", payload)
	}
	if payload.UUIDAggregate.Attachments[1].Member.Session.ID != "conn-2" ||
		payload.UUIDAggregate.Attachments[1].Identity.Value != "conn-2" ||
		payload.UUIDAggregate.Attachments[1].AggregateClassID != payload.UUIDAggregate.SharedClassID {
		t.Fatalf("unexpected second aggregate attachment payload, got %#v", payload)
	}
	if payload.UUIDAggregate.AttachmentExecution[0].Identity.Kind != string(tc.IdentityKindClientIP) ||
		payload.UUIDAggregate.AttachmentExecution[0].Identity.Value != "203.0.113.11" ||
		payload.UUIDAggregate.AttachmentExecution[0].MatchField != string(tc.UUIDAggregateAttachmentMatchSource) ||
		payload.UUIDAggregate.AttachmentExecution[0].AggregateClassID != payload.UUIDAggregate.SharedClassID ||
		len(payload.UUIDAggregate.AttachmentExecution[0].MemberSessionIDs) != 1 ||
		payload.UUIDAggregate.AttachmentExecution[0].MemberSessionIDs[0] != "conn-1" {
		t.Fatalf("unexpected first aggregate attachment execution payload, got %#v", payload)
	}
	if payload.UUIDAggregate.AttachmentExecution[1].Identity.Kind != string(tc.IdentityKindClientIP) ||
		payload.UUIDAggregate.AttachmentExecution[1].Identity.Value != "203.0.113.12" ||
		payload.UUIDAggregate.AttachmentExecution[1].Preference == 0 ||
		len(payload.UUIDAggregate.AttachmentExecution[1].MemberSessionIDs) != 1 ||
		payload.UUIDAggregate.AttachmentExecution[1].MemberSessionIDs[0] != "conn-2" {
		t.Fatalf("unexpected second aggregate attachment execution payload, got %#v", payload)
	}
	if payload.UUIDAggregate.Decision.Kind != string(limiter.DecisionApply) || payload.UUIDAggregate.Plan.Operation != string(tc.UUIDAggregateOperationApply) {
		t.Fatalf("unexpected aggregate plan payload, got %#v", payload)
	}
	if stderr.Len() != 0 {
		t.Fatalf("expected no stderr output, got %q", stderr.String())
	}
}

func TestRunLimitReportsRunnerFailureForConcreteExecutionPath(t *testing.T) {
	service := &stubDiscoveryService{
		result: discovery.Result{
			Targets: []discovery.RuntimeTarget{testLimitTarget()},
		},
	}
	inspector := &stubTCInspector{
		snapshot: tc.Snapshot{
			Device: "eth0",
		},
	}
	runner := &stubTCRunner{
		result: tc.Result{
			Stderr:   "failed",
			ExitCode: 1,
		},
		err: errors.New("command failed"),
	}
	app := NewApp(service)
	app.tcInspector = inspector
	app.tcRunner = runner
	app.privilegeStatus = func() privilege.Status {
		return privilege.Status{EUID: 0, IsRoot: true}
	}

	var stdout bytes.Buffer
	var stderr bytes.Buffer

	exitCode := app.Run([]string{
		"limit",
		"--pid", "1001",
		"--ip", "203.0.113.10",
		"--device", "eth0",
		"--direction", "upload",
		"--rate", "2048",
		"--execute",
	}, &stdout, &stderr)

	if exitCode != 1 {
		t.Fatalf("expected exit code 1, got %d", exitCode)
	}

	if !strings.Contains(stdout.String(), "Execution results:") {
		t.Fatalf("expected execution report, got %q", stdout.String())
	}
	if !strings.Contains(stderr.String(), "error execution: limit execution failed: command failed") {
		t.Fatalf("expected runner failure message, got %q", stderr.String())
	}
}
