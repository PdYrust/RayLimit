package tc

import (
	"sort"
	"strings"
	"testing"

	"github.com/PdYrust/RayLimit/internal/correlation"
	"github.com/PdYrust/RayLimit/internal/discovery"
	"github.com/PdYrust/RayLimit/internal/limiter"
	"github.com/PdYrust/RayLimit/internal/policy"
)

func testUUIDAggregateRuntime() discovery.SessionRuntime {
	return discovery.SessionRuntime{
		Source:  discovery.DiscoverySourceHostProcess,
		Name:    "edge-a",
		HostPID: 1001,
	}
}

func testUUIDAggregateSubject() correlation.UUIDAggregateSubject {
	return correlation.UUIDAggregateSubject{
		UUID:    "user-a",
		Runtime: testUUIDAggregateRuntime(),
	}
}

func testUUIDAggregateSession(id string) discovery.Session {
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
		Runtime: testUUIDAggregateRuntime(),
		Policy: discovery.SessionPolicyIdentity{
			UUID: "user-a",
		},
		Client: discovery.SessionClient{
			IP: ip,
		},
		Route: discovery.SessionRoute{
			InboundTag:  "api-in",
			OutboundTag: "direct",
		},
	}
}

func testUUIDAggregateMembership(t *testing.T, sessions ...discovery.Session) correlation.UUIDAggregateMembership {
	t.Helper()

	membership, err := correlation.NewUUIDAggregateMembership(testUUIDAggregateSubject(), sessions)
	if err != nil {
		t.Fatalf("expected aggregate membership construction to succeed, got %v", err)
	}

	return membership
}

func testUUIDAggregateRoutingContext(t *testing.T, network string, localIP string, localPort int) discovery.UUIDRoutingContext {
	t.Helper()

	context := discovery.UUIDRoutingContext{
		Runtime:    testUUIDAggregateRuntime(),
		UUID:       "user-a",
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

func testUUIDAggregateClientRoutingContext(t *testing.T, network string, clientIP string, clientPort int) discovery.UUIDRoutingContext {
	t.Helper()

	context := discovery.UUIDRoutingContext{
		Runtime:    testUUIDAggregateRuntime(),
		UUID:       "user-a",
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

func testUUIDAggregateTargetRoutingContext(t *testing.T, network string, targetIP string, targetPort int) discovery.UUIDRoutingContext {
	t.Helper()

	context := discovery.UUIDRoutingContext{
		Runtime:    testUUIDAggregateRuntime(),
		UUID:       "user-a",
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

func testUUIDAggregateRemoteRoutingContext(t *testing.T, network string, localIP string, localPort int, targetIP string, targetPort int) discovery.UUIDRoutingContext {
	t.Helper()

	context := discovery.UUIDRoutingContext{
		Runtime:    testUUIDAggregateRuntime(),
		UUID:       "user-a",
		Network:    network,
		LocalIPs:   []string{localIP},
		LocalPort:  localPort,
		TargetIPs:  []string{targetIP},
		TargetPort: targetPort,
		Confidence: discovery.SessionEvidenceConfidenceHigh,
		Note:       "fresh exact-user RoutingService local-plus-target socket tuple",
	}
	if err := context.Validate(); err != nil {
		t.Fatalf("expected uuid remote routing context validation to succeed, got %v", err)
	}

	return context
}

func testUUIDAggregateRoutingEvidenceResult(t *testing.T, contexts ...discovery.UUIDRoutingContext) discovery.UUIDRoutingEvidenceResult {
	t.Helper()

	result := discovery.UUIDRoutingEvidenceResult{
		Provider: "xray_routing_api",
		Runtime:  testUUIDAggregateRuntime(),
		UUID:     "user-a",
		Contexts: append([]discovery.UUIDRoutingContext(nil), contexts...),
	}
	if err := result.Validate(); err != nil {
		t.Fatalf("expected uuid routing evidence validation to succeed, got %v", err)
	}

	return result
}

func testUUIDAggregateRoutingAssessment(
	t *testing.T,
	freshness discovery.UUIDRoutingEvidenceFreshness,
	trusted bool,
	refreshNeeded bool,
	reason string,
) discovery.UUIDRoutingEvidenceAssessment {
	t.Helper()

	assessment := discovery.UUIDRoutingEvidenceAssessment{
		Freshness:     freshness,
		Trusted:       trusted,
		RefreshNeeded: refreshNeeded,
		Reason:        reason,
	}
	if err := assessment.Validate(); err != nil {
		t.Fatalf("expected uuid routing evidence assessment validation to succeed, got %v", err)
	}

	return assessment
}

func testUUIDAggregateRoutingPlan(
	t *testing.T,
	operation UUIDAggregateOperation,
	sessions []discovery.Session,
	contexts []discovery.UUIDRoutingContext,
	assessment discovery.UUIDRoutingEvidenceAssessment,
) UUIDAggregatePlan {
	t.Helper()

	return testUUIDAggregateRoutingPlanForDirection(t, operation, DirectionUpload, sessions, contexts, assessment)
}

func testUUIDAggregateRoutingPlanForDirection(
	t *testing.T,
	operation UUIDAggregateOperation,
	direction Direction,
	sessions []discovery.Session,
	contexts []discovery.UUIDRoutingContext,
	assessment discovery.UUIDRoutingEvidenceAssessment,
) UUIDAggregatePlan {
	t.Helper()

	membership := testUUIDAggregateMembership(t, sessions...)
	result := testUUIDAggregateRoutingEvidenceResult(t, contexts...)
	input := UUIDAggregatePlanInput{
		Operation:                 operation,
		Membership:                membership,
		Scope:                     Scope{Device: "eth0", Direction: direction},
		RoutingEvidence:           &result,
		RoutingEvidenceAssessment: &assessment,
	}
	if operation == UUIDAggregateOperationApply {
		input.Limits = policy.LimitPolicy{
			Upload:   &policy.RateLimit{BytesPerSecond: 2048},
			Download: &policy.RateLimit{BytesPerSecond: 2048},
		}
	}

	plan, err := (Planner{}).PlanUUIDAggregate(input)
	if err != nil {
		t.Fatalf("expected uuid aggregate routing plan construction to succeed, got %v", err)
	}

	return plan
}

func testUUIDAggregateObservedMarkAttachmentSnapshot(plan UUIDAggregatePlan, desiredRate int64) (Snapshot, NftablesSnapshot) {
	snapshot := Snapshot{
		Device: "eth0",
		QDiscs: []QDiscState{{
			Kind:   "htb",
			Handle: plan.Handles.RootHandle,
			Parent: "root",
		}},
		Classes: []ClassState{{
			Kind:               "htb",
			ClassID:            plan.Handles.ClassID,
			Parent:             plan.Handles.RootHandle,
			RateBytesPerSecond: desiredRate,
		}},
	}
	nftSnapshot := NftablesSnapshot{}
	if len(plan.AttachmentExecution.MarkAttachments) == 0 {
		return snapshot, nftSnapshot
	}

	shared := plan.AttachmentExecution.MarkAttachments[0]
	nftSnapshot.Tables = append(nftSnapshot.Tables, NftablesTableState{
		Family: shared.Table.Family,
		Name:   shared.Table.Name,
	})
	nftSnapshot.Chains = append(nftSnapshot.Chains, NftablesChainState{
		Family:   shared.Chain.Family,
		Table:    shared.Chain.Table,
		Name:     shared.Chain.Name,
		Type:     shared.Chain.Type,
		Hook:     shared.Chain.Hook,
		Priority: shared.Chain.Priority,
	})
	for index, attachment := range plan.AttachmentExecution.MarkAttachments {
		snapshot.Filters = append(snapshot.Filters, FilterState{
			Kind:       "fw",
			Parent:     plan.Handles.RootHandle,
			Protocol:   attachment.Filter.Protocol,
			Preference: attachment.Filter.Preference,
			Handle:     attachment.Filter.handleArg(),
			FlowID:     attachment.Filter.ClassID,
		})
		nftSnapshot.Rules = append(nftSnapshot.Rules, NftablesRuleState{
			Family:  attachment.Chain.Family,
			Table:   attachment.Chain.Table,
			Chain:   attachment.Chain.Name,
			Handle:  uint64(index + 11),
			Comment: attachment.Rule.Comment,
		})
	}

	return snapshot, nftSnapshot
}

func TestBindUUIDAggregateZeroMembers(t *testing.T) {
	binding, err := BindUUIDAggregate(testUUIDAggregateMembership(t))
	if err != nil {
		t.Fatalf("expected zero-member aggregate binding to succeed, got %v", err)
	}

	if binding.Identity.Kind != AggregateIdentityKindUUIDRuntimeGroup {
		t.Fatalf("expected uuid aggregate identity kind, got %#v", binding.Identity)
	}
	if binding.ShapingReadiness != BindingReadinessReady {
		t.Fatalf("expected ready aggregate shaping readiness, got %q", binding.ShapingReadiness)
	}
	if binding.AttachmentReadiness != BindingReadinessUnavailable {
		t.Fatalf("expected unavailable zero-member attachment readiness, got %q", binding.AttachmentReadiness)
	}
	if !strings.Contains(binding.Reason, "no live members") {
		t.Fatalf("unexpected zero-member aggregate binding reason: %#v", binding)
	}
}

func TestPlannerPlanUUIDAggregateZeroMembers(t *testing.T) {
	plan, err := (Planner{}).PlanUUIDAggregate(UUIDAggregatePlanInput{
		Membership: testUUIDAggregateMembership(t),
		Scope: Scope{
			Device:    "eth0",
			Direction: DirectionUpload,
		},
		Limits: policy.LimitPolicy{
			Upload: &policy.RateLimit{BytesPerSecond: 2048},
		},
	})
	if err != nil {
		t.Fatalf("expected zero-member aggregate plan to succeed, got %v", err)
	}

	if !plan.NoOp {
		t.Fatalf("expected zero-member aggregate plan to be a no-op, got %#v", plan)
	}
	if plan.Cardinality != correlation.UUIDAggregateCardinalityZero {
		t.Fatalf("expected zero-member cardinality, got %#v", plan)
	}
	if len(plan.Steps) != 0 {
		t.Fatalf("expected zero-member aggregate plan to avoid steps, got %#v", plan.Steps)
	}
	if strings.TrimSpace(plan.Handles.ClassID) == "" {
		t.Fatalf("expected aggregate handles to remain deterministic even for no-op plans, got %#v", plan)
	}
	if len(plan.Attachments.Members) != 0 {
		t.Fatalf("expected zero-member aggregate plan to avoid member attachments, got %#v", plan.Attachments)
	}
	if plan.Attachments.Readiness != BindingReadinessUnavailable {
		t.Fatalf("expected zero-member attachment readiness to be unavailable, got %#v", plan.Attachments)
	}
	if plan.AttachmentExecution.Readiness != BindingReadinessUnavailable {
		t.Fatalf("expected zero-member concrete attachment execution to be unavailable, got %#v", plan.AttachmentExecution)
	}
}

func TestPlannerPlanUUIDAggregateSingleMemberBuildsSharedClass(t *testing.T) {
	plan, err := (Planner{}).PlanUUIDAggregate(UUIDAggregatePlanInput{
		Membership: testUUIDAggregateMembership(t, testUUIDAggregateSession("conn-1")),
		Scope: Scope{
			Device:    "eth0",
			Direction: DirectionUpload,
		},
		Limits: policy.LimitPolicy{
			Upload: &policy.RateLimit{BytesPerSecond: 2048},
		},
	})
	if err != nil {
		t.Fatalf("expected single-member aggregate plan to succeed, got %v", err)
	}

	if plan.NoOp {
		t.Fatalf("expected single-member aggregate plan to require shaping steps, got %#v", plan)
	}
	if plan.Cardinality != correlation.UUIDAggregateCardinalitySingle {
		t.Fatalf("expected single-member cardinality, got %#v", plan)
	}
	if plan.Binding.AttachmentReadiness != BindingReadinessPartial {
		t.Fatalf("expected partial attachment readiness, got %#v", plan.Binding)
	}
	if len(plan.Attachments.Members) != 1 {
		t.Fatalf("expected single-member aggregate plan to include one member attachment, got %#v", plan.Attachments)
	}
	if plan.Attachments.Members[0].Identity.Kind != IdentityKindSession {
		t.Fatalf("expected single-member aggregate attachment to use session identity, got %#v", plan.Attachments.Members[0])
	}
	if plan.Attachments.Members[0].AggregateClassID != plan.Handles.ClassID {
		t.Fatalf("expected single-member aggregate attachment to target the shared class id, got %#v", plan.Attachments.Members[0])
	}
	if plan.AttachmentExecution.Readiness != BindingReadinessReady {
		t.Fatalf("expected single-member aggregate attachment execution to be ready, got %#v", plan.AttachmentExecution)
	}
	if len(plan.AttachmentExecution.Rules) != 1 {
		t.Fatalf("expected one concrete aggregate attachment rule, got %#v", plan.AttachmentExecution)
	}
	if plan.AttachmentExecution.Rules[0].Identity.Kind != IdentityKindClientIP ||
		plan.AttachmentExecution.Rules[0].Identity.Value != "203.0.113.11" {
		t.Fatalf("expected single-member aggregate rule to use the member client ip, got %#v", plan.AttachmentExecution.Rules[0])
	}
	if len(plan.Steps) != 3 {
		t.Fatalf("expected aggregate plan to include qdisc, shared class, and one attachment step, got %#v", plan.Steps)
	}
	if plan.Steps[1].Name != "upsert-aggregate-class" || plan.Steps[2].Name != "upsert-aggregate-attachment-1" {
		t.Fatalf("expected aggregate class plus concrete attachment step, got %#v", plan.Steps)
	}
	if !strings.Contains(plan.Reason, "concrete client-ip attachment rules") {
		t.Fatalf("unexpected aggregate plan reason: %#v", plan)
	}
}

func TestPlannerPlanUUIDAggregateRemoveCanCleanUpRootQDisc(t *testing.T) {
	plan, err := (Planner{}).PlanUUIDAggregate(UUIDAggregatePlanInput{
		Operation:  UUIDAggregateOperationRemove,
		Membership: testUUIDAggregateMembership(t, testUUIDAggregateSession("conn-1")),
		Scope: Scope{
			Device:    "eth0",
			Direction: DirectionUpload,
		},
		CleanupRootQDisc: true,
	})
	if err != nil {
		t.Fatalf("expected aggregate remove plan to succeed, got %v", err)
	}

	if plan.Operation != UUIDAggregateOperationRemove {
		t.Fatalf("expected aggregate remove operation, got %#v", plan)
	}
	if plan.NoOp {
		t.Fatalf("expected aggregate remove plan to be actionable, got %#v", plan)
	}
	if !plan.CleanupRootQDisc {
		t.Fatalf("expected aggregate remove plan to retain cleanup scope, got %#v", plan)
	}
	if len(plan.Steps) != 3 {
		t.Fatalf("expected aggregate remove plan to delete attachment rule, class, and root qdisc, got %#v", plan.Steps)
	}
	if plan.Steps[0].Name != "delete-aggregate-attachment-1" || plan.Steps[1].Name != "delete-aggregate-class" || plan.Steps[2].Name != "delete-root-qdisc" {
		t.Fatalf("unexpected aggregate remove steps, got %#v", plan.Steps)
	}
}

func TestPlannerPlanUUIDAggregateRemoveDeletesConcreteAttachmentRules(t *testing.T) {
	plan, err := (Planner{}).PlanUUIDAggregate(UUIDAggregatePlanInput{
		Operation:  UUIDAggregateOperationRemove,
		Membership: testUUIDAggregateMembership(t, testUUIDAggregateSession("conn-1"), testUUIDAggregateSession("conn-2")),
		Scope: Scope{
			Device:    "eth0",
			Direction: DirectionUpload,
		},
	})
	if err != nil {
		t.Fatalf("expected aggregate remove plan to succeed, got %v", err)
	}

	if len(plan.AttachmentExecution.Rules) != 2 {
		t.Fatalf("expected concrete attachment execution rules to remain available for remove planning, got %#v", plan.AttachmentExecution)
	}
	if len(plan.Steps) != 3 {
		t.Fatalf("expected aggregate remove plan to delete two attachment rules plus the shared class, got %#v", plan.Steps)
	}
	if plan.Steps[0].Name != "delete-aggregate-attachment-1" || plan.Steps[1].Name != "delete-aggregate-attachment-2" || plan.Steps[2].Name != "delete-aggregate-class" {
		t.Fatalf("unexpected aggregate remove plan step order, got %#v", plan.Steps)
	}
}

func TestAppendUUIDAggregateObservedAttachmentCleanupUsesObservedFiltersWhenMembershipIsNoLongerAttachable(t *testing.T) {
	plan, err := (Planner{}).PlanUUIDAggregate(UUIDAggregatePlanInput{
		Operation:  UUIDAggregateOperationRemove,
		Membership: testUUIDAggregateMembership(t),
		Scope: Scope{
			Device:    "eth0",
			Direction: DirectionUpload,
		},
	})
	if err != nil {
		t.Fatalf("expected aggregate remove plan to succeed, got %v", err)
	}
	if len(plan.Steps) != 1 || plan.Steps[0].Name != "delete-aggregate-class" {
		t.Fatalf("expected zero-member remove plan to start with class-only cleanup, got %#v", plan.Steps)
	}

	updated, err := AppendUUIDAggregateObservedAttachmentCleanup(plan, Snapshot{
		Device: "eth0",
		Filters: []FilterState{
			{Kind: "u32", Parent: plan.Handles.RootHandle, Protocol: "ip", Preference: 140, FlowID: plan.Handles.ClassID},
			{Kind: "u32", Parent: plan.Handles.RootHandle, Protocol: "ip", Preference: 120, FlowID: plan.Handles.ClassID},
			{Kind: "u32", Parent: plan.Handles.RootHandle, Protocol: "ip", Preference: 160, FlowID: "1:2b"},
		},
	}, nil)
	if err != nil {
		t.Fatalf("expected observed aggregate attachment cleanup to succeed, got %v", err)
	}

	if len(updated.Steps) != 2 {
		t.Fatalf("expected observed filter cleanup without a stale class delete, got %#v", updated.Steps)
	}
	if updated.Steps[0].Name != "delete-aggregate-attachment-1" || updated.Steps[1].Name != "delete-aggregate-attachment-2" {
		t.Fatalf("unexpected observed aggregate cleanup step order, got %#v", updated.Steps)
	}
	if updated.Steps[0].Command.Args[9] != "120" || updated.Steps[1].Command.Args[9] != "140" {
		t.Fatalf("expected observed cleanup to keep deterministic filter preference ordering, got %#v", updated.Steps)
	}
	if !strings.Contains(updated.Reason, "observed concrete attachment rules") {
		t.Fatalf("expected remove reason to mention observed attachment cleanup, got %#v", updated)
	}
	if strings.Contains(updated.Reason, "shared tc class") {
		t.Fatalf("expected observed attachment-only cleanup reason to avoid claiming class deletion, got %#v", updated)
	}
}

func TestAppendUUIDAggregateObservedAttachmentCleanupPreservesIPv6FilterProtocol(t *testing.T) {
	plan, err := (Planner{}).PlanUUIDAggregate(UUIDAggregatePlanInput{
		Operation:  UUIDAggregateOperationRemove,
		Membership: testUUIDAggregateMembership(t),
		Scope: Scope{
			Device:    "eth0",
			Direction: DirectionUpload,
		},
	})
	if err != nil {
		t.Fatalf("expected aggregate remove plan to succeed, got %v", err)
	}

	updated, err := AppendUUIDAggregateObservedAttachmentCleanup(plan, Snapshot{
		Device: "eth0",
		Filters: []FilterState{
			{Kind: "u32", Parent: plan.Handles.RootHandle, Protocol: "ipv6", Preference: 120, FlowID: plan.Handles.ClassID},
		},
	}, nil)
	if err != nil {
		t.Fatalf("expected observed ipv6 aggregate attachment cleanup to succeed, got %v", err)
	}

	if len(updated.Steps) != 1 {
		t.Fatalf("expected one observed ipv6 cleanup step, got %#v", updated.Steps)
	}
	if updated.Steps[0].Command.Args[7] != "ipv6" {
		t.Fatalf("expected observed ipv6 cleanup to preserve the ipv6 protocol, got %#v", updated.Steps[0])
	}
}

func TestAppendUUIDAggregateObservedAttachmentCleanupCanRestoreRootQDiscCleanup(t *testing.T) {
	plan, err := (Planner{}).PlanUUIDAggregate(UUIDAggregatePlanInput{
		Operation:  UUIDAggregateOperationRemove,
		Membership: testUUIDAggregateMembership(t),
		Scope: Scope{
			Device:    "eth0",
			Direction: DirectionUpload,
		},
	})
	if err != nil {
		t.Fatalf("expected aggregate remove plan to succeed, got %v", err)
	}

	updated, err := AppendUUIDAggregateObservedAttachmentCleanup(plan, Snapshot{
		Device: "eth0",
		QDiscs: []QDiscState{
			{Kind: "htb", Handle: plan.Handles.RootHandle, Parent: "root"},
		},
		Classes: []ClassState{
			{Kind: "htb", ClassID: plan.Handles.ClassID, Parent: plan.Handles.RootHandle},
		},
		Filters: []FilterState{
			{Kind: "u32", Parent: plan.Handles.RootHandle, Protocol: "ip", Preference: 120, FlowID: plan.Handles.ClassID},
			{Kind: "u32", Parent: plan.Handles.RootHandle, Protocol: "ip", Preference: 140, FlowID: plan.Handles.ClassID},
		},
	}, nil)
	if err != nil {
		t.Fatalf("expected observed aggregate attachment cleanup with root cleanup to succeed, got %v", err)
	}

	if !updated.CleanupRootQDisc {
		t.Fatalf("expected observed aggregate cleanup to restore root qdisc cleanup eligibility, got %#v", updated)
	}
	if len(updated.Steps) != 4 {
		t.Fatalf("expected observed filter cleanup, class delete, and root qdisc delete, got %#v", updated.Steps)
	}
	if updated.Steps[3].Name != "delete-root-qdisc" {
		t.Fatalf("expected root qdisc cleanup step, got %#v", updated.Steps)
	}
	if !strings.Contains(updated.Reason, "cleans up the root htb qdisc") {
		t.Fatalf("expected updated remove reason to mention root qdisc cleanup, got %#v", updated)
	}
}

func TestAppendUUIDAggregateObservedAttachmentCleanupDropsClassDeleteWhenObservedClassIsAlreadyGone(t *testing.T) {
	plan, err := (Planner{}).PlanUUIDAggregate(UUIDAggregatePlanInput{
		Operation:  UUIDAggregateOperationRemove,
		Membership: testUUIDAggregateMembership(t),
		Scope: Scope{
			Device:    "eth0",
			Direction: DirectionUpload,
		},
	})
	if err != nil {
		t.Fatalf("expected aggregate remove plan to succeed, got %v", err)
	}

	updated, err := AppendUUIDAggregateObservedAttachmentCleanup(plan, Snapshot{
		Device: "eth0",
		QDiscs: []QDiscState{
			{Kind: "htb", Handle: plan.Handles.RootHandle, Parent: "root"},
		},
		Filters: []FilterState{
			{Kind: "u32", Parent: plan.Handles.RootHandle, Protocol: "ip", Preference: 120, FlowID: plan.Handles.ClassID},
			{Kind: "u32", Parent: plan.Handles.RootHandle, Protocol: "ip", Preference: 140, FlowID: plan.Handles.ClassID},
		},
	}, nil)
	if err != nil {
		t.Fatalf("expected observed aggregate attachment cleanup without a class to succeed, got %v", err)
	}

	if len(updated.Steps) != 3 {
		t.Fatalf("expected observed filter cleanup and root qdisc cleanup without a class delete, got %#v", updated.Steps)
	}
	if updated.Steps[0].Name != "delete-aggregate-attachment-1" || updated.Steps[1].Name != "delete-aggregate-attachment-2" || updated.Steps[2].Name != "delete-root-qdisc" {
		t.Fatalf("unexpected observed aggregate attachment-only cleanup step order, got %#v", updated.Steps)
	}
	if strings.Contains(updated.Reason, "shared tc class") {
		t.Fatalf("expected attachment-only cleanup reason to avoid claiming class deletion, got %#v", updated)
	}
}

func TestPlannerPlanUUIDAggregateMultiMemberUsesSameSharedClassID(t *testing.T) {
	singlePlan, err := (Planner{}).PlanUUIDAggregate(UUIDAggregatePlanInput{
		Membership: testUUIDAggregateMembership(t, testUUIDAggregateSession("conn-1")),
		Scope: Scope{
			Device:    "eth0",
			Direction: DirectionUpload,
		},
		Limits: policy.LimitPolicy{
			Upload: &policy.RateLimit{BytesPerSecond: 2048},
		},
	})
	if err != nil {
		t.Fatalf("expected single-member aggregate plan to succeed, got %v", err)
	}

	multiPlan, err := (Planner{}).PlanUUIDAggregate(UUIDAggregatePlanInput{
		Membership: testUUIDAggregateMembership(t, testUUIDAggregateSession("conn-2"), testUUIDAggregateSession("conn-1")),
		Scope: Scope{
			Device:    "eth0",
			Direction: DirectionUpload,
		},
		Limits: policy.LimitPolicy{
			Upload: &policy.RateLimit{BytesPerSecond: 2048},
		},
	})
	if err != nil {
		t.Fatalf("expected multi-member aggregate plan to succeed, got %v", err)
	}

	if multiPlan.Cardinality != correlation.UUIDAggregateCardinalityMultiple {
		t.Fatalf("expected multiple-member cardinality, got %#v", multiPlan)
	}
	if singlePlan.Handles.ClassID != multiPlan.Handles.ClassID {
		t.Fatalf("expected one shared class identity per runtime-local uuid subject, got %q and %q", singlePlan.Handles.ClassID, multiPlan.Handles.ClassID)
	}
	if len(multiPlan.Attachments.Members) != 2 {
		t.Fatalf("expected two aggregate attachments, got %#v", multiPlan.Attachments)
	}
	if multiPlan.Attachments.Members[0].Member.Session.ID != "conn-1" || multiPlan.Attachments.Members[1].Member.Session.ID != "conn-2" {
		t.Fatalf("expected aggregate attachments to remain deterministic, got %#v", multiPlan.Attachments.Members)
	}
	if multiPlan.Attachments.Members[0].AggregateClassID != multiPlan.Handles.ClassID || multiPlan.Attachments.Members[1].AggregateClassID != multiPlan.Handles.ClassID {
		t.Fatalf("expected every aggregate attachment to target the shared class id, got %#v", multiPlan.Attachments.Members)
	}
	if multiPlan.AttachmentExecution.Readiness != BindingReadinessReady {
		t.Fatalf("expected multi-member concrete attachment execution to be ready, got %#v", multiPlan.AttachmentExecution)
	}
	if len(multiPlan.AttachmentExecution.Rules) != 2 {
		t.Fatalf("expected one concrete rule per unique member ip, got %#v", multiPlan.AttachmentExecution)
	}
	if multiPlan.AttachmentExecution.Rules[0].Identity.Value != "203.0.113.11" || multiPlan.AttachmentExecution.Rules[1].Identity.Value != "203.0.113.12" {
		t.Fatalf("expected deterministic concrete attachment-rule ordering, got %#v", multiPlan.AttachmentExecution.Rules)
	}
	if len(multiPlan.Steps) != 4 {
		t.Fatalf("expected qdisc, class, and two concrete attachment steps, got %#v", multiPlan.Steps)
	}
}

func TestBuildUUIDAggregateAttachmentSetRejectsInvalidClassID(t *testing.T) {
	_, err := BuildUUIDAggregateAttachmentSet(testUUIDAggregateMembership(t, testUUIDAggregateSession("conn-1")), "invalid")
	if err == nil {
		t.Fatal("expected invalid aggregate class id to fail attachment construction")
	}
}

func TestBuildUUIDAggregateAttachmentSetRejectsInvalidMemberSession(t *testing.T) {
	membership := testUUIDAggregateMembership(t, testUUIDAggregateSession("conn-1"))
	membership.Members[0].Session.ID = ""

	_, err := BuildUUIDAggregateAttachmentSet(membership, "1:2a")
	if err == nil {
		t.Fatal("expected invalid aggregate member session to fail attachment construction")
	}
}

func TestBuildUUIDAggregateAttachmentExecutionZeroMembers(t *testing.T) {
	execution, err := BuildUUIDAggregateAttachmentExecution(testUUIDAggregateMembership(t), Scope{
		Device:    "eth0",
		Direction: DirectionUpload,
	}, "1:2a")
	if err != nil {
		t.Fatalf("expected zero-member attachment execution construction to succeed, got %v", err)
	}
	if execution.Readiness != BindingReadinessUnavailable || len(execution.Rules) != 0 {
		t.Fatalf("expected unavailable zero-member attachment execution, got %#v", execution)
	}
}

func TestBuildUUIDAggregateAttachabilityMapClassifiesMemberEvidence(t *testing.T) {
	attachable := testUUIDAggregateSession("conn-1")
	mapped := testUUIDAggregateSession("conn-2")
	mapped.Client.IP = "::ffff:203.0.113.12"
	missing := testUUIDAggregateSession("conn-3")
	missing.Client.IP = ""
	ipv6 := testUUIDAggregateSession("conn-4")
	ipv6.Client.IP = "2001:db8::44"

	attachability, err := BuildUUIDAggregateAttachabilityMap(testUUIDAggregateMembership(t, attachable, mapped, missing, ipv6))
	if err != nil {
		t.Fatalf("expected aggregate attachability map construction to succeed, got %v", err)
	}
	if attachability.AttachableCount != 3 || attachability.BlockingCount != 1 {
		t.Fatalf("unexpected aggregate attachability counts, got %#v", attachability)
	}
	if !strings.Contains(attachability.Reason, "missing client ip evidence for: conn-3") {
		t.Fatalf("expected aggregate attachability reason to decompose blocking members, got %#v", attachability)
	}

	bySession := make(map[string]UUIDAggregateMemberAttachability, len(attachability.Members))
	for _, member := range attachability.Members {
		bySession[member.Member.Session.ID] = member
	}
	if bySession["conn-1"].Status != UUIDAggregateMemberAttachabilityAttachable ||
		bySession["conn-1"].CanonicalClientIP != "203.0.113.11" {
		t.Fatalf("expected conn-1 to stay attachable, got %#v", bySession["conn-1"])
	}
	if bySession["conn-2"].Status != UUIDAggregateMemberAttachabilityAttachable ||
		bySession["conn-2"].CanonicalClientIP != "203.0.113.12" {
		t.Fatalf("expected mapped conn-2 to canonicalize to attachable ipv4, got %#v", bySession["conn-2"])
	}
	if bySession["conn-3"].Status != UUIDAggregateMemberAttachabilityMissingClientIP {
		t.Fatalf("expected conn-3 to report missing client ip evidence, got %#v", bySession["conn-3"])
	}
	if bySession["conn-4"].Status != UUIDAggregateMemberAttachabilityAttachable ||
		bySession["conn-4"].CanonicalClientIP != "2001:db8::44" {
		t.Fatalf("expected conn-4 to report attachable native ipv6 client ip evidence, got %#v", bySession["conn-4"])
	}
}

func TestBuildUUIDAggregateAttachmentExecutionRejectsMissingClientIP(t *testing.T) {
	session := testUUIDAggregateSession("conn-1")
	session.Client.IP = ""

	execution, err := BuildUUIDAggregateAttachmentExecution(testUUIDAggregateMembership(t, session), Scope{
		Device:    "eth0",
		Direction: DirectionUpload,
	}, "1:2a")
	if err != nil {
		t.Fatalf("expected missing-ip aggregate attachment execution construction to succeed, got %v", err)
	}
	if execution.Readiness != BindingReadinessUnavailable {
		t.Fatalf("expected unavailable attachment execution when client ip is missing, got %#v", execution)
	}
	if len(execution.Rules) != 0 {
		t.Fatalf("expected missing-ip attachment execution to avoid concrete rules, got %#v", execution)
	}
}

func TestBuildUUIDAggregateAttachmentExecutionSupportsNativeIPv6ClientIP(t *testing.T) {
	session := testUUIDAggregateSession("conn-1")
	session.Client.IP = "2001:db8::11"

	execution, err := BuildUUIDAggregateAttachmentExecution(testUUIDAggregateMembership(t, session), Scope{
		Device:    "eth0",
		Direction: DirectionUpload,
	}, "1:2a")
	if err != nil {
		t.Fatalf("expected ipv6 aggregate attachment execution construction to succeed, got %v", err)
	}
	if execution.Readiness != BindingReadinessReady {
		t.Fatalf("expected ready attachment execution for native ipv6 client ip evidence, got %#v", execution)
	}
	if len(execution.Rules) != 1 {
		t.Fatalf("expected one concrete ipv6 attachment rule, got %#v", execution)
	}
	if execution.Rules[0].Identity.Value != "2001:db8::11" {
		t.Fatalf("expected canonical native ipv6 identity, got %#v", execution.Rules[0])
	}
	if !strings.Contains(execution.Rules[0].Reason, "assumes no ipv6 extension headers") {
		t.Fatalf("expected ipv6 attachment rule note, got %#v", execution.Rules[0])
	}
	if !strings.Contains(execution.Reason, "ipv6 rules assume no ipv6 extension headers") {
		t.Fatalf("expected ipv6 attachment execution reason to explain the current backend assumption, got %#v", execution)
	}
}

func TestPlannerPlanUUIDAggregateBuildsConcreteIPv6AttachmentApplyStep(t *testing.T) {
	session := testUUIDAggregateSession("conn-1")
	session.Client.IP = "2001:db8::11"

	plan, err := (Planner{}).PlanUUIDAggregate(UUIDAggregatePlanInput{
		Membership: testUUIDAggregateMembership(t, session),
		Scope: Scope{
			Device:    "eth0",
			Direction: DirectionUpload,
		},
		Limits: policy.LimitPolicy{
			Upload: &policy.RateLimit{BytesPerSecond: 2048},
		},
	})
	if err != nil {
		t.Fatalf("expected ipv6 aggregate apply plan construction to succeed, got %v", err)
	}

	if len(plan.AttachmentExecution.Rules) != 1 {
		t.Fatalf("expected one concrete ipv6 attachment rule, got %#v", plan.AttachmentExecution)
	}
	if len(plan.Steps) != 3 {
		t.Fatalf("expected root qdisc, class, and one ipv6 attachment step, got %#v", plan.Steps)
	}
	if plan.Steps[2].Command.Args[7] != "ipv6" ||
		plan.Steps[2].Command.Args[12] != "ip6" ||
		plan.Steps[2].Command.Args[14] != "2001:db8::11/128" {
		t.Fatalf("expected ipv6 aggregate apply step to use ipv6 protocol and ip6 match semantics, got %#v", plan.Steps[2])
	}
}

func TestBuildUUIDAggregateAttachmentExecutionIsPartialWhenOnlySomeMembersAreAttachable(t *testing.T) {
	attachable := testUUIDAggregateSession("conn-1")
	missing := testUUIDAggregateSession("conn-2")
	missing.Client.IP = ""

	execution, err := BuildUUIDAggregateAttachmentExecution(testUUIDAggregateMembership(t, attachable, missing), Scope{
		Device:    "eth0",
		Direction: DirectionUpload,
	}, "1:2a")
	if err != nil {
		t.Fatalf("expected mixed aggregate attachment execution construction to succeed, got %v", err)
	}
	if execution.Readiness != BindingReadinessPartial {
		t.Fatalf("expected partial attachment execution when one member is missing ip evidence, got %#v", execution)
	}
	if len(execution.Rules) != 0 {
		t.Fatalf("expected mixed aggregate attachment execution to avoid concrete rules, got %#v", execution)
	}
	if !strings.Contains(execution.Reason, "missing client ip evidence for: conn-2") {
		t.Fatalf("expected mixed aggregate attachment execution reason to explain missing client ip evidence, got %#v", execution)
	}
}

func TestBuildUUIDAggregateAttachmentExecutionAcceptsIPv4MappedIPv6(t *testing.T) {
	session := testUUIDAggregateSession("conn-1")
	session.Client.IP = "::ffff:203.0.113.11"

	execution, err := BuildUUIDAggregateAttachmentExecution(testUUIDAggregateMembership(t, session), Scope{
		Device:    "eth0",
		Direction: DirectionUpload,
	}, "1:2a")
	if err != nil {
		t.Fatalf("expected mapped-ip aggregate attachment execution construction to succeed, got %v", err)
	}
	if execution.Readiness != BindingReadinessReady {
		t.Fatalf("expected ready attachment execution for mapped ipv4 evidence, got %#v", execution)
	}
	if len(execution.Rules) != 1 {
		t.Fatalf("expected one concrete attachment rule, got %#v", execution)
	}
	if execution.Rules[0].Identity.Value != "203.0.113.11" {
		t.Fatalf("expected mapped ipv6 client ip to normalize to ipv4 rule identity, got %#v", execution.Rules[0])
	}
}

func TestPlannerPlanUUIDAggregateUsesRoutingLocalSocketMarkBackendWhenFreshEvidenceIsConcrete(t *testing.T) {
	session := testUUIDAggregateSession("conn-1")
	session.Client.IP = ""
	plan := testUUIDAggregateRoutingPlan(
		t,
		UUIDAggregateOperationApply,
		[]discovery.Session{session},
		[]discovery.UUIDRoutingContext{
			testUUIDAggregateRoutingContext(t, "tcp", "10.10.0.2", 8443),
		},
		testUUIDAggregateRoutingAssessment(
			t,
			discovery.UUIDRoutingEvidenceFreshnessFresh,
			true,
			false,
			"uuid routing evidence is fresh enough to reuse without a refresh",
		),
	)

	if plan.AttachmentExecution.Backend != UUIDAggregateAttachmentBackendRoutingLocalSocketFW {
		t.Fatalf("expected routing-local-socket mark backend, got %#v", plan.AttachmentExecution)
	}
	if len(plan.AttachmentExecution.Rules) != 0 {
		t.Fatalf("expected fresh routing evidence to avoid direct client-ip rules, got %#v", plan.AttachmentExecution)
	}
	if len(plan.AttachmentExecution.MarkAttachments) != 1 {
		t.Fatalf("expected one concrete mark-backed attachment for one local socket tuple, got %#v", plan.AttachmentExecution)
	}
	if plan.AttachmentExecution.MarkAttachments[0].Identity.Kind != IdentityKindUUIDRouting {
		t.Fatalf("expected routing-local-socket mark attachment identity, got %#v", plan.AttachmentExecution.MarkAttachments[0])
	}
	if len(plan.Steps) != 6 {
		t.Fatalf("expected qdisc, class, nft table, nft chain, nft rule, and tc fw filter steps, got %#v", plan.Steps)
	}
	if !strings.Contains(plan.AttachmentExecution.Reason, "RoutingService-backed local socket tuples") {
		t.Fatalf("expected routing-local-socket backend reason, got %#v", plan.AttachmentExecution)
	}
}

func TestPlannerPlanUUIDAggregateRoutingBackendPreservesIPv6LocalSocketSelectors(t *testing.T) {
	session := testUUIDAggregateSession("conn-1")
	session.Client.IP = ""
	plan := testUUIDAggregateRoutingPlan(
		t,
		UUIDAggregateOperationApply,
		[]discovery.Session{session},
		[]discovery.UUIDRoutingContext{
			testUUIDAggregateRoutingContext(t, "tcp", "2001:db8::25", 9443),
		},
		testUUIDAggregateRoutingAssessment(
			t,
			discovery.UUIDRoutingEvidenceFreshnessFresh,
			true,
			false,
			"uuid routing evidence is fresh enough to reuse without a refresh",
		),
	)

	if len(plan.AttachmentExecution.MarkAttachments) != 1 {
		t.Fatalf("expected one ipv6-aware mark attachment, got %#v", plan.AttachmentExecution)
	}
	expression := strings.Join(plan.AttachmentExecution.MarkAttachments[0].Rule.Selector.Expression, " ")
	if !strings.Contains(expression, "ip6 saddr 2001:db8::25") || !strings.Contains(expression, "tcp sport 9443") {
		t.Fatalf("expected ipv6-aware local socket selector expression, got %q", expression)
	}
}

func TestPlannerPlanUUIDAggregateUsesRoutingClientSocketMarkBackendForFreshDownloadEvidence(t *testing.T) {
	session := testUUIDAggregateSession("conn-1")
	session.Client.IP = ""
	plan := testUUIDAggregateRoutingPlanForDirection(
		t,
		UUIDAggregateOperationApply,
		DirectionDownload,
		[]discovery.Session{session},
		[]discovery.UUIDRoutingContext{
			testUUIDAggregateClientRoutingContext(t, "tcp", "198.51.100.44", 43120),
		},
		testUUIDAggregateRoutingAssessment(
			t,
			discovery.UUIDRoutingEvidenceFreshnessFresh,
			true,
			false,
			"uuid routing evidence is fresh enough to reuse without a refresh",
		),
	)

	if plan.AttachmentExecution.Backend != UUIDAggregateAttachmentBackendRoutingClientSocketFW {
		t.Fatalf("expected routing-client-socket mark backend, got %#v", plan.AttachmentExecution)
	}
	if len(plan.AttachmentExecution.MarkAttachments) != 1 {
		t.Fatalf("expected one concrete client-socket mark attachment, got %#v", plan.AttachmentExecution)
	}
	if len(plan.Steps) != 6 {
		t.Fatalf("expected qdisc, class, nft table, nft chain, nft rule, and tc fw filter steps, got %#v", plan.Steps)
	}
	if !strings.Contains(plan.AttachmentExecution.Reason, "client socket tuples") {
		t.Fatalf("expected routing-client backend reason, got %#v", plan.AttachmentExecution)
	}
	expression := strings.Join(plan.AttachmentExecution.MarkAttachments[0].Rule.Selector.Expression, " ")
	if !strings.Contains(expression, "ip daddr 198.51.100.44") || !strings.Contains(expression, "tcp dport 43120") {
		t.Fatalf("expected download client-socket selector expression, got %q", expression)
	}
}

func TestPlannerPlanUUIDAggregateRoutingClientBackendKeepsSharedClientIPTuplesSeparate(t *testing.T) {
	sessionA := testUUIDAggregateSession("conn-1")
	sessionA.Client.IP = ""
	sessionB := testUUIDAggregateSession("conn-2")
	sessionB.Client.IP = ""
	plan := testUUIDAggregateRoutingPlanForDirection(
		t,
		UUIDAggregateOperationApply,
		DirectionDownload,
		[]discovery.Session{sessionA, sessionB},
		[]discovery.UUIDRoutingContext{
			testUUIDAggregateClientRoutingContext(t, "tcp", "198.51.100.44", 43120),
			testUUIDAggregateClientRoutingContext(t, "tcp", "198.51.100.44", 43121),
		},
		testUUIDAggregateRoutingAssessment(
			t,
			discovery.UUIDRoutingEvidenceFreshnessFresh,
			true,
			false,
			"uuid routing evidence is fresh enough to reuse without a refresh",
		),
	)

	if plan.AttachmentExecution.Backend != UUIDAggregateAttachmentBackendRoutingClientSocketFW {
		t.Fatalf("expected routing-client-socket mark backend, got %#v", plan.AttachmentExecution)
	}
	if len(plan.AttachmentExecution.MarkAttachments) != 2 {
		t.Fatalf("expected one attachment per concrete client socket tuple, got %#v", plan.AttachmentExecution)
	}
	expressions := make([]string, 0, len(plan.AttachmentExecution.MarkAttachments))
	for _, attachment := range plan.AttachmentExecution.MarkAttachments {
		expressions = append(expressions, strings.Join(attachment.Rule.Selector.Expression, " "))
	}
	sort.Strings(expressions)
	if !strings.Contains(expressions[0], "ip daddr 198.51.100.44") || !strings.Contains(expressions[0], "tcp dport 43120") {
		t.Fatalf("expected first shared-ip client socket selector to preserve the concrete port tuple, got %#v", expressions)
	}
	if !strings.Contains(expressions[1], "ip daddr 198.51.100.44") || !strings.Contains(expressions[1], "tcp dport 43121") {
		t.Fatalf("expected second shared-ip client socket selector to preserve the concrete port tuple, got %#v", expressions)
	}
}

func TestPlannerPlanUUIDAggregateRoutingClientBackendPreservesIPv6ClientSocketSelectors(t *testing.T) {
	session := testUUIDAggregateSession("conn-1")
	session.Client.IP = ""
	plan := testUUIDAggregateRoutingPlanForDirection(
		t,
		UUIDAggregateOperationApply,
		DirectionDownload,
		[]discovery.Session{session},
		[]discovery.UUIDRoutingContext{
			testUUIDAggregateClientRoutingContext(t, "udp", "2001:db8::25", 5353),
		},
		testUUIDAggregateRoutingAssessment(
			t,
			discovery.UUIDRoutingEvidenceFreshnessFresh,
			true,
			false,
			"uuid routing evidence is fresh enough to reuse without a refresh",
		),
	)

	if len(plan.AttachmentExecution.MarkAttachments) != 1 {
		t.Fatalf("expected one ipv6-aware client mark attachment, got %#v", plan.AttachmentExecution)
	}
	expression := strings.Join(plan.AttachmentExecution.MarkAttachments[0].Rule.Selector.Expression, " ")
	if !strings.Contains(expression, "ip6 daddr 2001:db8::25") || !strings.Contains(expression, "udp dport 5353") {
		t.Fatalf("expected ipv6-aware client socket selector expression, got %q", expression)
	}
}

func TestBuildUUIDAggregateAttachmentExecutionWithRoutingEvidenceBlocksMissingLocalSocketTuple(t *testing.T) {
	session := testUUIDAggregateSession("conn-1")
	session.Client.IP = ""
	result := testUUIDAggregateRoutingEvidenceResult(t)
	assessment := testUUIDAggregateRoutingAssessment(
		t,
		discovery.UUIDRoutingEvidenceFreshnessFresh,
		true,
		false,
		"uuid routing evidence is fresh enough to reuse without a refresh",
	)

	execution, err := BuildUUIDAggregateAttachmentExecutionWithRoutingEvidence(
		testUUIDAggregateMembership(t, session),
		Scope{Device: "eth0", Direction: DirectionUpload},
		"1:2a",
		&result,
		&assessment,
	)
	if err != nil {
		t.Fatalf("expected missing local socket tuple execution construction to succeed, got %v", err)
	}
	if execution.Readiness != BindingReadinessUnavailable {
		t.Fatalf("expected missing local socket tuple to keep execution unavailable, got %#v", execution)
	}
	if !strings.Contains(execution.Reason, "local socket tuple") {
		t.Fatalf("expected missing tuple reason to mention local socket tuple, got %#v", execution)
	}
}

func TestBuildUUIDAggregateAttachmentExecutionWithRoutingEvidenceBlocksMissingClientSocketTupleForDownload(t *testing.T) {
	session := testUUIDAggregateSession("conn-1")
	session.Client.IP = ""
	result := testUUIDAggregateRoutingEvidenceResult(t)
	assessment := testUUIDAggregateRoutingAssessment(
		t,
		discovery.UUIDRoutingEvidenceFreshnessFresh,
		true,
		false,
		"uuid routing evidence is fresh enough to reuse without a refresh",
	)

	execution, err := BuildUUIDAggregateAttachmentExecutionWithRoutingEvidence(
		testUUIDAggregateMembership(t, session),
		Scope{Device: "eth0", Direction: DirectionDownload},
		"1:2a",
		&result,
		&assessment,
	)
	if err != nil {
		t.Fatalf("expected missing client socket tuple execution construction to succeed, got %v", err)
	}
	if execution.Readiness != BindingReadinessUnavailable {
		t.Fatalf("expected missing client socket tuple to keep download execution unavailable, got %#v", execution)
	}
	if !strings.Contains(execution.Reason, "client socket tuple") {
		t.Fatalf("expected missing client tuple reason to mention client socket tuple, got %#v", execution)
	}
}

func TestBuildUUIDAggregateAttachmentExecutionWithRoutingEvidenceExplainsClientSocketIsDownloadOnlyForUpload(t *testing.T) {
	session := testUUIDAggregateSession("conn-1")
	session.Client.IP = ""
	result := testUUIDAggregateRoutingEvidenceResult(
		t,
		testUUIDAggregateClientRoutingContext(t, "tcp", "198.51.100.44", 43120),
	)
	assessment := testUUIDAggregateRoutingAssessment(
		t,
		discovery.UUIDRoutingEvidenceFreshnessFresh,
		true,
		false,
		"uuid routing evidence is fresh enough to reuse without a refresh",
	)

	execution, err := BuildUUIDAggregateAttachmentExecutionWithRoutingEvidence(
		testUUIDAggregateMembership(t, session),
		Scope{Device: "eth0", Direction: DirectionUpload},
		"1:2a",
		&result,
		&assessment,
	)
	if err != nil {
		t.Fatalf("expected upload blocker construction to succeed, got %v", err)
	}
	if execution.Readiness != BindingReadinessUnavailable {
		t.Fatalf("expected client-only routing evidence to keep upload execution unavailable, got %#v", execution)
	}
	if !strings.Contains(execution.Reason, "current download backend") || !strings.Contains(execution.Reason, "upload execution still requires a concrete local socket tuple") {
		t.Fatalf("expected upload blocker to explain client tuple scope, got %#v", execution)
	}
}

func TestBuildUUIDAggregateAttachmentExecutionWithRoutingEvidenceExplainsRemoteTargetTupleOnlyBlocked(t *testing.T) {
	session := testUUIDAggregateSession("conn-1")
	session.Client.IP = ""
	result := testUUIDAggregateRoutingEvidenceResult(
		t,
		testUUIDAggregateTargetRoutingContext(t, "tcp", "203.0.113.200", 443),
	)
	assessment := testUUIDAggregateRoutingAssessment(
		t,
		discovery.UUIDRoutingEvidenceFreshnessFresh,
		true,
		false,
		"uuid routing evidence is fresh enough to reuse without a refresh",
	)

	execution, err := BuildUUIDAggregateAttachmentExecutionWithRoutingEvidence(
		testUUIDAggregateMembership(t, session),
		Scope{Device: "eth0", Direction: DirectionUpload},
		"1:2a",
		&result,
		&assessment,
	)
	if err != nil {
		t.Fatalf("expected remote-target blocker construction to succeed, got %v", err)
	}
	if execution.Readiness != BindingReadinessUnavailable {
		t.Fatalf("expected target-only routing evidence to remain unavailable, got %#v", execution)
	}
	if !strings.Contains(execution.Reason, "remote target ip and port can be shared across users") {
		t.Fatalf("expected target-only blocker reason, got %#v", execution)
	}
}

func TestBuildUUIDAggregateAttachmentExecutionWithRoutingEvidenceExplainsRemoteSocketFutureStepForDownload(t *testing.T) {
	session := testUUIDAggregateSession("conn-1")
	session.Client.IP = ""
	result := testUUIDAggregateRoutingEvidenceResult(
		t,
		testUUIDAggregateRemoteRoutingContext(t, "tcp", "10.10.0.2", 8443, "203.0.113.200", 443),
	)
	assessment := testUUIDAggregateRoutingAssessment(
		t,
		discovery.UUIDRoutingEvidenceFreshnessFresh,
		true,
		false,
		"uuid routing evidence is fresh enough to reuse without a refresh",
	)

	execution, err := BuildUUIDAggregateAttachmentExecutionWithRoutingEvidence(
		testUUIDAggregateMembership(t, session),
		Scope{Device: "eth0", Direction: DirectionDownload},
		"1:2a",
		&result,
		&assessment,
	)
	if err != nil {
		t.Fatalf("expected remote-socket future-step blocker construction to succeed, got %v", err)
	}
	if execution.Readiness != BindingReadinessUnavailable {
		t.Fatalf("expected local-plus-target evidence without client tuple to remain unavailable, got %#v", execution)
	}
	if !strings.Contains(execution.Reason, "broader exact-user remote socket classifier remains future work") {
		t.Fatalf("expected remote-socket future-step blocker reason, got %#v", execution)
	}
}

func TestBuildUUIDAggregateAttachmentExecutionWithRoutingEvidenceExplainsMetadataOnlyBlocked(t *testing.T) {
	session := testUUIDAggregateSession("conn-1")
	session.Client.IP = ""
	result := testUUIDAggregateRoutingEvidenceResult(t, discovery.UUIDRoutingContext{
		Runtime:      testUUIDAggregateRuntime(),
		UUID:         "user-a",
		Network:      "tcp",
		OutboundTag:  "proxy-out",
		InboundTag:   "socks-in",
		Protocol:     "tls",
		TargetDomain: "example.com",
		Confidence:   discovery.SessionEvidenceConfidenceHigh,
		Note:         "fresh exact-user routing metadata without concrete socket tuple",
	})
	assessment := testUUIDAggregateRoutingAssessment(
		t,
		discovery.UUIDRoutingEvidenceFreshnessFresh,
		true,
		false,
		"uuid routing evidence is fresh enough to reuse without a refresh",
	)

	execution, err := BuildUUIDAggregateAttachmentExecutionWithRoutingEvidence(
		testUUIDAggregateMembership(t, session),
		Scope{Device: "eth0", Direction: DirectionUpload},
		"1:2a",
		&result,
		&assessment,
	)
	if err != nil {
		t.Fatalf("expected metadata-only blocker construction to succeed, got %v", err)
	}
	if execution.Readiness != BindingReadinessUnavailable {
		t.Fatalf("expected metadata-only routing evidence to remain unavailable, got %#v", execution)
	}
	if !strings.Contains(execution.Reason, "not yet a kernel-visible exact-user-safe uuid classifier") {
		t.Fatalf("expected metadata-only blocker reason, got %#v", execution)
	}
}

func TestBuildUUIDAggregateAttachmentExecutionWithRoutingEvidenceBlocksStaleEvidence(t *testing.T) {
	session := testUUIDAggregateSession("conn-1")
	session.Client.IP = ""
	result := testUUIDAggregateRoutingEvidenceResult(
		t,
		testUUIDAggregateRoutingContext(t, "tcp", "10.10.0.2", 8443),
	)
	assessment := testUUIDAggregateRoutingAssessment(
		t,
		discovery.UUIDRoutingEvidenceFreshnessStale,
		false,
		true,
		"uuid routing evidence is stale and should be refreshed before reuse",
	)
	execution, err := BuildUUIDAggregateAttachmentExecutionWithRoutingEvidence(
		testUUIDAggregateMembership(t, session),
		Scope{Device: "eth0", Direction: DirectionUpload},
		"1:2a",
		&result,
		&assessment,
	)
	if err != nil {
		t.Fatalf("expected stale routing evidence execution construction to succeed, got %v", err)
	}
	if execution.Readiness != BindingReadinessUnavailable {
		t.Fatalf("expected stale routing evidence to keep concrete execution unavailable, got %#v", execution)
	}
	if len(execution.MarkAttachments) != 0 {
		t.Fatalf("expected stale routing evidence to avoid concrete mark attachments, got %#v", execution)
	}
	if !strings.Contains(execution.Reason, "stale") {
		t.Fatalf("expected stale routing evidence reason, got %#v", execution)
	}
}

func TestBuildUUIDAggregateAttachmentExecutionWithRoutingEvidenceBlocksPartialEvidence(t *testing.T) {
	attachable := testUUIDAggregateSession("conn-1")
	missing := testUUIDAggregateSession("conn-2")
	missing.Client.IP = ""
	result := testUUIDAggregateRoutingEvidenceResult(t)
	result.Issues = []discovery.SessionEvidenceIssue{{
		Code:    discovery.SessionEvidenceIssueInsufficient,
		Message: "RoutingService returned only partial uuid routing evidence",
	}}
	if err := result.Validate(); err != nil {
		t.Fatalf("expected partial routing evidence to validate, got %v", err)
	}
	assessment := testUUIDAggregateRoutingAssessment(
		t,
		discovery.UUIDRoutingEvidenceFreshnessPartial,
		false,
		true,
		"uuid routing evidence is only partially trustworthy",
	)

	execution, err := BuildUUIDAggregateAttachmentExecutionWithRoutingEvidence(
		testUUIDAggregateMembership(t, attachable, missing),
		Scope{Device: "eth0", Direction: DirectionUpload},
		"1:2a",
		&result,
		&assessment,
	)
	if err != nil {
		t.Fatalf("expected partial routing evidence execution construction to succeed, got %v", err)
	}
	if execution.Readiness != BindingReadinessPartial {
		t.Fatalf("expected partial routing evidence to keep mixed attachability in partial state, got %#v", execution)
	}
	if len(execution.MarkAttachments) != 0 {
		t.Fatalf("expected partial routing evidence to avoid concrete mark attachments, got %#v", execution)
	}
	if !strings.Contains(execution.Reason, "partially trustworthy") {
		t.Fatalf("expected partial routing evidence reason, got %#v", execution)
	}
}

func TestBuildUUIDAggregateAttachmentExecutionWithRoutingEvidenceBlocksUnavailableEvidence(t *testing.T) {
	session := testUUIDAggregateSession("conn-1")
	session.Client.IP = ""
	result := testUUIDAggregateRoutingEvidenceResult(t)
	result.Issues = []discovery.SessionEvidenceIssue{{
		Code:    discovery.SessionEvidenceIssueUnavailable,
		Message: "RoutingService endpoint is unavailable for live uuid routing evidence",
	}}
	if err := result.Validate(); err != nil {
		t.Fatalf("expected unavailable routing evidence to validate, got %v", err)
	}
	assessment := testUUIDAggregateRoutingAssessment(
		t,
		discovery.UUIDRoutingEvidenceFreshnessUnavailable,
		false,
		true,
		"uuid routing evidence is currently unavailable",
	)

	execution, err := BuildUUIDAggregateAttachmentExecutionWithRoutingEvidence(
		testUUIDAggregateMembership(t, session),
		Scope{Device: "eth0", Direction: DirectionUpload},
		"1:2a",
		&result,
		&assessment,
	)
	if err != nil {
		t.Fatalf("expected unavailable routing evidence execution construction to succeed, got %v", err)
	}
	if execution.Readiness != BindingReadinessUnavailable {
		t.Fatalf("expected unavailable routing evidence to keep concrete execution unavailable, got %#v", execution)
	}
	if len(execution.MarkAttachments) != 0 {
		t.Fatalf("expected unavailable routing evidence to avoid concrete mark attachments, got %#v", execution)
	}
	if !strings.Contains(execution.Reason, "currently unavailable") {
		t.Fatalf("expected unavailable routing evidence reason, got %#v", execution)
	}
}

func TestDecideUUIDAggregateApplyZeroMembersNoOp(t *testing.T) {
	plan, err := (Planner{}).PlanUUIDAggregate(UUIDAggregatePlanInput{
		Membership: testUUIDAggregateMembership(t),
		Scope: Scope{
			Device:    "eth0",
			Direction: DirectionUpload,
		},
		Limits: policy.LimitPolicy{
			Upload: &policy.RateLimit{BytesPerSecond: 2048},
		},
	})
	if err != nil {
		t.Fatalf("expected zero-member aggregate plan to succeed, got %v", err)
	}

	decision, err := DecideUUIDAggregate(plan, UUIDAggregateObservation{
		Available:       true,
		Reconcilable:    true,
		ExpectedClassID: plan.Handles.ClassID,
	}, 2048)
	if err != nil {
		t.Fatalf("expected zero-member aggregate decision to succeed, got %v", err)
	}

	if decision.Kind != limiter.DecisionNoOp {
		t.Fatalf("expected zero-member aggregate no-op, got %#v", decision)
	}
}

func TestDecideUUIDAggregateApplySingleMemberNoOpWhenRateAndAttachmentRulesMatch(t *testing.T) {
	plan, err := (Planner{}).PlanUUIDAggregate(UUIDAggregatePlanInput{
		Membership: testUUIDAggregateMembership(t, testUUIDAggregateSession("conn-1")),
		Scope: Scope{
			Device:    "eth0",
			Direction: DirectionUpload,
		},
		Limits: policy.LimitPolicy{
			Upload: &policy.RateLimit{BytesPerSecond: 2048},
		},
	})
	if err != nil {
		t.Fatalf("expected single-member aggregate plan to succeed, got %v", err)
	}

	decision, err := DecideUUIDAggregate(plan, UUIDAggregateObservation{
		Available:                  true,
		Reconcilable:               true,
		Matched:                    true,
		AttachmentComparable:       true,
		AttachmentMatched:          true,
		ExpectedClassID:            plan.Handles.ClassID,
		ObservedClassID:            plan.Handles.ClassID,
		ObservedRateBytesPerSecond: 2048,
	}, 2048)
	if err != nil {
		t.Fatalf("expected aggregate decision to succeed, got %v", err)
	}

	if decision.Kind != limiter.DecisionNoOp {
		t.Fatalf("expected matching aggregate class and attachment rules to become a no-op, got %#v", decision)
	}
}

func TestDecideUUIDAggregateApplySingleMemberReappliesWhenAttachmentRulesDoNotMatch(t *testing.T) {
	plan, err := (Planner{}).PlanUUIDAggregate(UUIDAggregatePlanInput{
		Membership: testUUIDAggregateMembership(t, testUUIDAggregateSession("conn-1")),
		Scope: Scope{
			Device:    "eth0",
			Direction: DirectionUpload,
		},
		Limits: policy.LimitPolicy{
			Upload: &policy.RateLimit{BytesPerSecond: 2048},
		},
	})
	if err != nil {
		t.Fatalf("expected single-member aggregate plan to succeed, got %v", err)
	}

	decision, err := DecideUUIDAggregate(plan, UUIDAggregateObservation{
		Available:                  true,
		Reconcilable:               true,
		Matched:                    true,
		AttachmentComparable:       true,
		AttachmentMatched:          false,
		ExpectedClassID:            plan.Handles.ClassID,
		ObservedClassID:            plan.Handles.ClassID,
		ObservedRateBytesPerSecond: 2048,
	}, 2048)
	if err != nil {
		t.Fatalf("expected aggregate decision to succeed, got %v", err)
	}

	if decision.Kind != limiter.DecisionApply {
		t.Fatalf("expected missing aggregate attachment rules to require reapply, got %#v", decision)
	}
}

func TestDecideUUIDAggregateApplyMultiMemberReplacesDifferingRate(t *testing.T) {
	plan, err := (Planner{}).PlanUUIDAggregate(UUIDAggregatePlanInput{
		Membership: testUUIDAggregateMembership(t, testUUIDAggregateSession("conn-1"), testUUIDAggregateSession("conn-2")),
		Scope: Scope{
			Device:    "eth0",
			Direction: DirectionUpload,
		},
		Limits: policy.LimitPolicy{
			Upload: &policy.RateLimit{BytesPerSecond: 4096},
		},
	})
	if err != nil {
		t.Fatalf("expected multi-member aggregate plan to succeed, got %v", err)
	}

	decision, err := DecideUUIDAggregate(plan, UUIDAggregateObservation{
		Available:                  true,
		Reconcilable:               true,
		Matched:                    true,
		ExpectedClassID:            plan.Handles.ClassID,
		ObservedClassID:            plan.Handles.ClassID,
		ObservedRateBytesPerSecond: 2048,
	}, 4096)
	if err != nil {
		t.Fatalf("expected aggregate decision to succeed, got %v", err)
	}

	if decision.Kind != limiter.DecisionApply {
		t.Fatalf("expected differing aggregate rate to require apply, got %#v", decision)
	}
}

func TestObserveUUIDAggregateRemoveMarksRootCleanupEligibility(t *testing.T) {
	plan, err := (Planner{}).PlanUUIDAggregate(UUIDAggregatePlanInput{
		Operation:  UUIDAggregateOperationRemove,
		Membership: testUUIDAggregateMembership(t, testUUIDAggregateSession("conn-1")),
		Scope: Scope{
			Device:    "eth0",
			Direction: DirectionUpload,
		},
	})
	if err != nil {
		t.Fatalf("expected aggregate remove plan to succeed, got %v", err)
	}

	observation, err := ObserveUUIDAggregate(Snapshot{
		Device: "eth0",
		QDiscs: []QDiscState{
			{
				Kind:   "htb",
				Handle: plan.Handles.RootHandle,
				Parent: "root",
			},
		},
		Classes: []ClassState{
			{
				Kind:               "htb",
				ClassID:            plan.Handles.ClassID,
				Parent:             plan.Handles.RootHandle,
				RateBytesPerSecond: 2048,
			},
		},
	}, nil, plan)
	if err != nil {
		t.Fatalf("expected aggregate observation to succeed, got %v", err)
	}

	if !observation.Matched {
		t.Fatalf("expected aggregate observation to match the shared class, got %#v", observation)
	}
	if !observation.CleanupRootQDisc {
		t.Fatalf("expected aggregate observation to mark root cleanup eligibility, got %#v", observation)
	}
}

func TestObserveUUIDAggregateRemoveDoesNotCleanRootQDiscWhenFiltersRemain(t *testing.T) {
	plan, err := (Planner{}).PlanUUIDAggregate(UUIDAggregatePlanInput{
		Operation:  UUIDAggregateOperationRemove,
		Membership: testUUIDAggregateMembership(t, testUUIDAggregateSession("conn-1")),
		Scope: Scope{
			Device:    "eth0",
			Direction: DirectionUpload,
		},
	})
	if err != nil {
		t.Fatalf("expected aggregate remove plan to succeed, got %v", err)
	}

	observation, err := ObserveUUIDAggregate(Snapshot{
		Device: "eth0",
		QDiscs: []QDiscState{
			{
				Kind:   "htb",
				Handle: plan.Handles.RootHandle,
				Parent: "root",
			},
		},
		Classes: []ClassState{
			{
				Kind:               "htb",
				ClassID:            plan.Handles.ClassID,
				Parent:             plan.Handles.RootHandle,
				RateBytesPerSecond: 2048,
			},
		},
		Filters: []FilterState{
			{Kind: "u32", Parent: plan.Handles.RootHandle, Protocol: "ip"},
		},
	}, nil, plan)
	if err != nil {
		t.Fatalf("expected aggregate observation with filters to succeed, got %v", err)
	}

	if observation.CleanupRootQDisc {
		t.Fatalf("expected observed filters to block root qdisc cleanup, got %#v", observation)
	}
}

func TestObserveUUIDAggregateApplyMatchesConcreteAttachmentRules(t *testing.T) {
	plan, err := (Planner{}).PlanUUIDAggregate(UUIDAggregatePlanInput{
		Membership: testUUIDAggregateMembership(t, testUUIDAggregateSession("conn-1"), testUUIDAggregateSession("conn-2")),
		Scope: Scope{
			Device:    "eth0",
			Direction: DirectionUpload,
		},
		Limits: policy.LimitPolicy{
			Upload: &policy.RateLimit{BytesPerSecond: 2048},
		},
	})
	if err != nil {
		t.Fatalf("expected aggregate apply plan to succeed, got %v", err)
	}

	snapshot := Snapshot{
		Device: "eth0",
		Classes: []ClassState{
			{
				Kind:               "htb",
				ClassID:            plan.Handles.ClassID,
				Parent:             plan.Handles.RootHandle,
				RateBytesPerSecond: 2048,
			},
		},
	}
	for _, rule := range plan.AttachmentExecution.Rules {
		snapshot.Filters = append(snapshot.Filters, FilterState{
			Kind:       "u32",
			Parent:     plan.Handles.RootHandle,
			Protocol:   "ip",
			Preference: rule.Preference,
			FlowID:     plan.Handles.ClassID,
		})
	}

	observation, err := ObserveUUIDAggregate(snapshot, nil, plan)
	if err != nil {
		t.Fatalf("expected aggregate observation to succeed, got %v", err)
	}

	if !observation.AttachmentComparable || !observation.AttachmentMatched {
		t.Fatalf("expected aggregate observation to match concrete attachment rules, got %#v", observation)
	}
}

func TestObserveUUIDAggregateApplyMatchesConcreteIPv6AttachmentRules(t *testing.T) {
	session := testUUIDAggregateSession("conn-1")
	session.Client.IP = "2001:db8::11"
	plan, err := (Planner{}).PlanUUIDAggregate(UUIDAggregatePlanInput{
		Membership: testUUIDAggregateMembership(t, session),
		Scope: Scope{
			Device:    "eth0",
			Direction: DirectionUpload,
		},
		Limits: policy.LimitPolicy{
			Upload: &policy.RateLimit{BytesPerSecond: 2048},
		},
	})
	if err != nil {
		t.Fatalf("expected ipv6 aggregate apply plan to succeed, got %v", err)
	}

	snapshot := Snapshot{
		Device: "eth0",
		Classes: []ClassState{
			{
				Kind:               "htb",
				ClassID:            plan.Handles.ClassID,
				Parent:             plan.Handles.RootHandle,
				RateBytesPerSecond: 2048,
			},
		},
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

	observation, err := ObserveUUIDAggregate(snapshot, nil, plan)
	if err != nil {
		t.Fatalf("expected ipv6 aggregate observation to succeed, got %v", err)
	}

	if !observation.AttachmentComparable || !observation.AttachmentMatched {
		t.Fatalf("expected ipv6 aggregate observation to match concrete attachment rules, got %#v", observation)
	}

	decision, err := DecideUUIDAggregate(plan, observation, 2048)
	if err != nil {
		t.Fatalf("expected ipv6 aggregate decision to succeed, got %v", err)
	}
	if decision.Kind != limiter.DecisionNoOp {
		t.Fatalf("expected matching ipv6 aggregate state to become a no-op, got %#v", decision)
	}
}

func TestObserveUUIDAggregateApplyMatchesRoutingMarkAttachments(t *testing.T) {
	session := testUUIDAggregateSession("conn-1")
	session.Client.IP = ""
	plan := testUUIDAggregateRoutingPlan(
		t,
		UUIDAggregateOperationApply,
		[]discovery.Session{session},
		[]discovery.UUIDRoutingContext{
			testUUIDAggregateRoutingContext(t, "tcp", "10.10.0.2", 8443),
			testUUIDAggregateRoutingContext(t, "udp", "2001:db8::25", 5353),
		},
		testUUIDAggregateRoutingAssessment(
			t,
			discovery.UUIDRoutingEvidenceFreshnessFresh,
			true,
			false,
			"uuid routing evidence is fresh enough to reuse without a refresh",
		),
	)
	snapshot, nftSnapshot := testUUIDAggregateObservedMarkAttachmentSnapshot(plan, 2048)

	observation, err := ObserveUUIDAggregate(snapshot, &nftSnapshot, plan)
	if err != nil {
		t.Fatalf("expected routing mark-backed aggregate observation to succeed, got %v", err)
	}
	if !observation.AttachmentComparable || !observation.AttachmentMatched {
		t.Fatalf("expected routing mark-backed aggregate observation to match concrete attachment state, got %#v", observation)
	}

	decision, err := DecideUUIDAggregate(plan, observation, 2048)
	if err != nil {
		t.Fatalf("expected routing mark-backed aggregate decision to succeed, got %v", err)
	}
	if decision.Kind != limiter.DecisionNoOp {
		t.Fatalf("expected matching routing mark-backed aggregate state to become a no-op, got %#v", decision)
	}
}

func TestObserveUUIDAggregateApplyMatchesRoutingClientMarkAttachments(t *testing.T) {
	session := testUUIDAggregateSession("conn-1")
	session.Client.IP = ""
	plan := testUUIDAggregateRoutingPlanForDirection(
		t,
		UUIDAggregateOperationApply,
		DirectionDownload,
		[]discovery.Session{session},
		[]discovery.UUIDRoutingContext{
			testUUIDAggregateClientRoutingContext(t, "tcp", "198.51.100.44", 43120),
			testUUIDAggregateClientRoutingContext(t, "udp", "2001:db8::25", 5353),
		},
		testUUIDAggregateRoutingAssessment(
			t,
			discovery.UUIDRoutingEvidenceFreshnessFresh,
			true,
			false,
			"uuid routing evidence is fresh enough to reuse without a refresh",
		),
	)
	snapshot, nftSnapshot := testUUIDAggregateObservedMarkAttachmentSnapshot(plan, 2048)

	observation, err := ObserveUUIDAggregate(snapshot, &nftSnapshot, plan)
	if err != nil {
		t.Fatalf("expected routing client mark-backed aggregate observation to succeed, got %v", err)
	}
	if !observation.AttachmentComparable || !observation.AttachmentMatched {
		t.Fatalf("expected routing client mark-backed aggregate observation to match concrete attachment state, got %#v", observation)
	}

	decision, err := DecideUUIDAggregate(plan, observation, 2048)
	if err != nil {
		t.Fatalf("expected routing client mark-backed aggregate decision to succeed, got %v", err)
	}
	if decision.Kind != limiter.DecisionNoOp {
		t.Fatalf("expected matching routing client mark-backed aggregate state to become a no-op, got %#v", decision)
	}
}

func TestAppendUUIDAggregateObservedApplyDeltaReconcilesAttachableMembershipChanges(t *testing.T) {
	currentPlan, err := (Planner{}).PlanUUIDAggregate(UUIDAggregatePlanInput{
		Membership: testUUIDAggregateMembership(t, testUUIDAggregateSession("conn-1"), testUUIDAggregateSession("conn-3")),
		Scope: Scope{
			Device:    "eth0",
			Direction: DirectionUpload,
		},
		Limits: policy.LimitPolicy{
			Upload: &policy.RateLimit{BytesPerSecond: 2048},
		},
	})
	if err != nil {
		t.Fatalf("expected current aggregate plan to succeed, got %v", err)
	}
	stalePlan, err := (Planner{}).PlanUUIDAggregate(UUIDAggregatePlanInput{
		Membership: testUUIDAggregateMembership(t, testUUIDAggregateSession("conn-1"), testUUIDAggregateSession("conn-2")),
		Scope: Scope{
			Device:    "eth0",
			Direction: DirectionUpload,
		},
		Limits: policy.LimitPolicy{
			Upload: &policy.RateLimit{BytesPerSecond: 2048},
		},
	})
	if err != nil {
		t.Fatalf("expected stale aggregate plan to succeed, got %v", err)
	}

	snapshot := Snapshot{
		Device: "eth0",
		QDiscs: []QDiscState{{
			Kind:   "htb",
			Handle: currentPlan.Handles.RootHandle,
			Parent: "root",
		}},
		Classes: []ClassState{{
			Kind:               "htb",
			ClassID:            currentPlan.Handles.ClassID,
			Parent:             currentPlan.Handles.RootHandle,
			RateBytesPerSecond: 2048,
		}},
	}
	for _, rule := range stalePlan.AttachmentExecution.Rules {
		snapshot.Filters = append(snapshot.Filters, FilterState{
			Kind:       "u32",
			Parent:     currentPlan.Handles.RootHandle,
			Protocol:   "ip",
			Preference: rule.Preference,
			FlowID:     currentPlan.Handles.ClassID,
		})
	}

	updated, err := AppendUUIDAggregateObservedApplyDelta(currentPlan, snapshot, nil, 2048)
	if err != nil {
		t.Fatalf("expected aggregate apply delta narrowing to succeed, got %v", err)
	}
	if len(updated.Steps) != 2 {
		t.Fatalf("expected one stale delete plus one missing-member upsert, got %#v", updated.Steps)
	}
	if updated.Steps[0].Name != "delete-stale-aggregate-attachment-1" ||
		updated.Steps[1].Name != "upsert-aggregate-attachment-2" {
		t.Fatalf("unexpected aggregate delta steps, got %#v", updated.Steps)
	}
	for _, step := range updated.Steps {
		if len(step.Command.Args) >= 2 && step.Command.Args[0] == "class" && step.Command.Args[1] == "replace" {
			t.Fatalf("expected aggregate delta plan to avoid class replacement when the shared class already matches, got %#v", updated.Steps)
		}
	}
	if !strings.Contains(updated.Reason, "removing stale or duplicate member rules and adding missing current rules") {
		t.Fatalf("expected aggregate delta reason to explain stale-plus-missing reconcile, got %#v", updated)
	}
}

func TestAppendUUIDAggregateObservedApplyDeltaDeletesDuplicateExpectedAttachmentRule(t *testing.T) {
	currentPlan, err := (Planner{}).PlanUUIDAggregate(UUIDAggregatePlanInput{
		Membership: testUUIDAggregateMembership(t, testUUIDAggregateSession("conn-1"), testUUIDAggregateSession("conn-2")),
		Scope: Scope{
			Device:    "eth0",
			Direction: DirectionUpload,
		},
		Limits: policy.LimitPolicy{
			Upload: &policy.RateLimit{BytesPerSecond: 2048},
		},
	})
	if err != nil {
		t.Fatalf("expected current aggregate plan to succeed, got %v", err)
	}

	snapshot := Snapshot{
		Device: "eth0",
		QDiscs: []QDiscState{{
			Kind:   "htb",
			Handle: currentPlan.Handles.RootHandle,
			Parent: "root",
		}},
		Classes: []ClassState{{
			Kind:               "htb",
			ClassID:            currentPlan.Handles.ClassID,
			Parent:             currentPlan.Handles.RootHandle,
			RateBytesPerSecond: 2048,
		}},
	}
	for _, rule := range currentPlan.AttachmentExecution.Rules {
		snapshot.Filters = append(snapshot.Filters, FilterState{
			Kind:       "u32",
			Parent:     currentPlan.Handles.RootHandle,
			Protocol:   "ip",
			Preference: rule.Preference,
			FlowID:     currentPlan.Handles.ClassID,
		})
	}
	snapshot.Filters = append(snapshot.Filters, FilterState{
		Kind:       "u32",
		Parent:     currentPlan.Handles.RootHandle,
		Protocol:   "ip",
		Preference: currentPlan.AttachmentExecution.Rules[0].Preference,
		FlowID:     currentPlan.Handles.ClassID,
	})

	updated, err := AppendUUIDAggregateObservedApplyDelta(currentPlan, snapshot, nil, 2048)
	if err != nil {
		t.Fatalf("expected aggregate apply delta narrowing to succeed, got %v", err)
	}
	if len(updated.Steps) != 1 {
		t.Fatalf("expected one duplicate-rule delete without class or qdisc replay, got %#v", updated.Steps)
	}
	if updated.Steps[0].Name != "delete-stale-aggregate-attachment-1" {
		t.Fatalf("expected duplicate-rule cleanup step, got %#v", updated.Steps)
	}
	if updated.Steps[0].Command.Args[0] != "filter" || updated.Steps[0].Command.Args[1] != "del" {
		t.Fatalf("expected duplicate-rule cleanup to use tc filter del, got %#v", updated.Steps[0])
	}
	if strings.Contains(updated.Reason, "adding missing current rules") {
		t.Fatalf("expected duplicate-rule cleanup to avoid missing-rule wording, got %#v", updated)
	}
	if !strings.Contains(updated.Reason, "stale or duplicate concrete attachment rules") {
		t.Fatalf("expected duplicate-rule cleanup reason to explain duplicate stale state, got %#v", updated)
	}
}

func TestAppendUUIDAggregateObservedApplyDeltaReconcilesIPv6AttachmentChanges(t *testing.T) {
	current := testUUIDAggregateSession("conn-1")
	current.Client.IP = "2001:db8::11"
	stale := testUUIDAggregateSession("conn-1")
	stale.Client.IP = "2001:db8::22"

	currentPlan, err := (Planner{}).PlanUUIDAggregate(UUIDAggregatePlanInput{
		Membership: testUUIDAggregateMembership(t, current),
		Scope: Scope{
			Device:    "eth0",
			Direction: DirectionUpload,
		},
		Limits: policy.LimitPolicy{
			Upload: &policy.RateLimit{BytesPerSecond: 2048},
		},
	})
	if err != nil {
		t.Fatalf("expected current ipv6 aggregate plan to succeed, got %v", err)
	}
	stalePlan, err := (Planner{}).PlanUUIDAggregate(UUIDAggregatePlanInput{
		Membership: testUUIDAggregateMembership(t, stale),
		Scope: Scope{
			Device:    "eth0",
			Direction: DirectionUpload,
		},
		Limits: policy.LimitPolicy{
			Upload: &policy.RateLimit{BytesPerSecond: 2048},
		},
	})
	if err != nil {
		t.Fatalf("expected stale ipv6 aggregate plan to succeed, got %v", err)
	}

	snapshot := Snapshot{
		Device: "eth0",
		QDiscs: []QDiscState{{
			Kind:   "htb",
			Handle: currentPlan.Handles.RootHandle,
			Parent: "root",
		}},
		Classes: []ClassState{{
			Kind:               "htb",
			ClassID:            currentPlan.Handles.ClassID,
			Parent:             currentPlan.Handles.RootHandle,
			RateBytesPerSecond: 2048,
		}},
		Filters: []FilterState{{
			Kind:       "u32",
			Parent:     currentPlan.Handles.RootHandle,
			Protocol:   "ipv6",
			Preference: stalePlan.AttachmentExecution.Rules[0].Preference,
			FlowID:     currentPlan.Handles.ClassID,
		}},
	}

	updated, err := AppendUUIDAggregateObservedApplyDelta(currentPlan, snapshot, nil, 2048)
	if err != nil {
		t.Fatalf("expected ipv6 aggregate apply delta narrowing to succeed, got %v", err)
	}
	if len(updated.Steps) != 2 {
		t.Fatalf("expected one stale delete plus one ipv6 upsert, got %#v", updated.Steps)
	}
	if updated.Steps[0].Command.Args[7] != "ipv6" {
		t.Fatalf("expected stale ipv6 delete to preserve the ipv6 protocol, got %#v", updated.Steps[0])
	}
	if updated.Steps[1].Command.Args[7] != "ipv6" ||
		updated.Steps[1].Command.Args[12] != "ip6" ||
		updated.Steps[1].Command.Args[14] != "2001:db8::11/128" {
		t.Fatalf("expected ipv6 upsert to use ipv6 protocol and ip6 match semantics, got %#v", updated.Steps[1])
	}
}

func TestAppendUUIDAggregateObservedApplyDeltaReconcilesRoutingSocketChanges(t *testing.T) {
	session := testUUIDAggregateSession("conn-1")
	session.Client.IP = ""
	currentPlan := testUUIDAggregateRoutingPlan(
		t,
		UUIDAggregateOperationApply,
		[]discovery.Session{session},
		[]discovery.UUIDRoutingContext{
			testUUIDAggregateRoutingContext(t, "tcp", "10.10.0.2", 8443),
		},
		testUUIDAggregateRoutingAssessment(
			t,
			discovery.UUIDRoutingEvidenceFreshnessFresh,
			true,
			false,
			"uuid routing evidence is fresh enough to reuse without a refresh",
		),
	)
	stalePlan := testUUIDAggregateRoutingPlan(
		t,
		UUIDAggregateOperationApply,
		[]discovery.Session{session},
		[]discovery.UUIDRoutingContext{
			testUUIDAggregateRoutingContext(t, "tcp", "10.10.0.9", 9443),
		},
		testUUIDAggregateRoutingAssessment(
			t,
			discovery.UUIDRoutingEvidenceFreshnessFresh,
			true,
			false,
			"uuid routing evidence is fresh enough to reuse without a refresh",
		),
	)
	snapshot, nftSnapshot := testUUIDAggregateObservedMarkAttachmentSnapshot(stalePlan, 2048)
	if len(currentPlan.AttachmentExecution.MarkAttachments) != 1 || len(stalePlan.AttachmentExecution.MarkAttachments) != 1 {
		t.Fatalf("expected one current and one stale mark attachment, got current=%#v stale=%#v", currentPlan.AttachmentExecution, stalePlan.AttachmentExecution)
	}
	nftSnapshot.Tables = []NftablesTableState{{
		Family: currentPlan.AttachmentExecution.MarkAttachments[0].Table.Family,
		Name:   currentPlan.AttachmentExecution.MarkAttachments[0].Table.Name,
	}}
	nftSnapshot.Chains = []NftablesChainState{{
		Family:   currentPlan.AttachmentExecution.MarkAttachments[0].Chain.Family,
		Table:    currentPlan.AttachmentExecution.MarkAttachments[0].Chain.Table,
		Name:     currentPlan.AttachmentExecution.MarkAttachments[0].Chain.Name,
		Type:     currentPlan.AttachmentExecution.MarkAttachments[0].Chain.Type,
		Hook:     currentPlan.AttachmentExecution.MarkAttachments[0].Chain.Hook,
		Priority: currentPlan.AttachmentExecution.MarkAttachments[0].Chain.Priority,
	}}

	updated, err := AppendUUIDAggregateObservedApplyDelta(currentPlan, snapshot, &nftSnapshot, 2048)
	if err != nil {
		t.Fatalf("expected routing mark-backed aggregate delta narrowing to succeed, got %v", err)
	}
	if len(updated.Steps) != 4 {
		t.Fatalf("expected stale filter and rule cleanup plus one missing rule/filter upsert, got %#v", updated.Steps)
	}
	if updated.Steps[0].Name != "delete-stale-aggregate-attachment-1" ||
		updated.Steps[1].Name != "delete-stale-aggregate-attachment-2" ||
		updated.Steps[2].Name != "upsert-aggregate-mark-attachment-rule-1" ||
		updated.Steps[3].Name != "upsert-aggregate-mark-attachment-filter-1" {
		t.Fatalf("unexpected routing mark-backed aggregate delta steps, got %#v", updated.Steps)
	}
	if updated.Steps[0].Command.Path != defaultBinary || updated.Steps[1].Command.Path != defaultNftBinary {
		t.Fatalf("expected tc fw filter cleanup before nft rule cleanup for deterministic stale-state ordering, got %#v", updated.Steps)
	}
	if !strings.Contains(updated.Reason, "removing stale or duplicate member rules and adding missing current rules") {
		t.Fatalf("expected routing mark-backed delta reason to explain stale-plus-missing reconcile, got %#v", updated)
	}
}

func TestAppendUUIDAggregateObservedApplyDeltaReconcilesRoutingClientSocketChanges(t *testing.T) {
	session := testUUIDAggregateSession("conn-1")
	session.Client.IP = ""
	currentPlan := testUUIDAggregateRoutingPlanForDirection(
		t,
		UUIDAggregateOperationApply,
		DirectionDownload,
		[]discovery.Session{session},
		[]discovery.UUIDRoutingContext{
			testUUIDAggregateClientRoutingContext(t, "tcp", "198.51.100.44", 43120),
		},
		testUUIDAggregateRoutingAssessment(
			t,
			discovery.UUIDRoutingEvidenceFreshnessFresh,
			true,
			false,
			"uuid routing evidence is fresh enough to reuse without a refresh",
		),
	)
	stalePlan := testUUIDAggregateRoutingPlanForDirection(
		t,
		UUIDAggregateOperationApply,
		DirectionDownload,
		[]discovery.Session{session},
		[]discovery.UUIDRoutingContext{
			testUUIDAggregateClientRoutingContext(t, "tcp", "198.51.100.44", 43121),
		},
		testUUIDAggregateRoutingAssessment(
			t,
			discovery.UUIDRoutingEvidenceFreshnessFresh,
			true,
			false,
			"uuid routing evidence is fresh enough to reuse without a refresh",
		),
	)
	snapshot, nftSnapshot := testUUIDAggregateObservedMarkAttachmentSnapshot(stalePlan, 2048)

	updated, err := AppendUUIDAggregateObservedApplyDelta(currentPlan, snapshot, &nftSnapshot, 2048)
	if err != nil {
		t.Fatalf("expected routing client mark-backed aggregate delta narrowing to succeed, got %v", err)
	}
	if len(updated.Steps) != 4 {
		t.Fatalf("expected stale filter and rule cleanup plus one missing rule/filter upsert for client-socket changes, got %#v", updated.Steps)
	}
	if updated.Steps[0].Name != "delete-stale-aggregate-attachment-1" ||
		updated.Steps[1].Name != "delete-stale-aggregate-attachment-2" ||
		updated.Steps[2].Name != "upsert-aggregate-mark-attachment-rule-1" ||
		updated.Steps[3].Name != "upsert-aggregate-mark-attachment-filter-1" {
		t.Fatalf("unexpected routing client mark-backed aggregate delta steps, got %#v", updated.Steps)
	}
	if updated.Steps[0].Command.Path != defaultBinary || updated.Steps[1].Command.Path != defaultNftBinary {
		t.Fatalf("expected tc fw filter cleanup before nft rule cleanup for routing client stale-state ordering, got %#v", updated.Steps)
	}
	if !strings.Contains(updated.Reason, "removing stale or duplicate member rules and adding missing current rules") {
		t.Fatalf("expected routing client mark-backed delta reason to explain stale-plus-missing reconcile, got %#v", updated)
	}
}

func TestAppendUUIDAggregateObservedAttachmentCleanupRemovesObservedRoutingMarkAttachments(t *testing.T) {
	session := testUUIDAggregateSession("conn-1")
	session.Client.IP = ""
	staleApplyPlan := testUUIDAggregateRoutingPlan(
		t,
		UUIDAggregateOperationApply,
		[]discovery.Session{session},
		[]discovery.UUIDRoutingContext{
			testUUIDAggregateRoutingContext(t, "tcp", "10.10.0.2", 8443),
		},
		testUUIDAggregateRoutingAssessment(
			t,
			discovery.UUIDRoutingEvidenceFreshnessFresh,
			true,
			false,
			"uuid routing evidence is fresh enough to reuse without a refresh",
		),
	)
	removePlan, err := (Planner{}).PlanUUIDAggregate(UUIDAggregatePlanInput{
		Operation:  UUIDAggregateOperationRemove,
		Membership: testUUIDAggregateMembership(t),
		Scope: Scope{
			Device:    "eth0",
			Direction: DirectionUpload,
		},
	})
	if err != nil {
		t.Fatalf("expected zero-member aggregate remove plan to succeed, got %v", err)
	}

	snapshot, nftSnapshot := testUUIDAggregateObservedMarkAttachmentSnapshot(staleApplyPlan, 2048)
	updated, err := AppendUUIDAggregateObservedAttachmentCleanup(removePlan, snapshot, &nftSnapshot)
	if err != nil {
		t.Fatalf("expected routing mark-backed aggregate cleanup to succeed, got %v", err)
	}
	if len(updated.Steps) != 4 {
		t.Fatalf("expected mark-backed filter cleanup, nft rule cleanup, class delete, and root qdisc delete, got %#v", updated.Steps)
	}
	if updated.Steps[0].Name != "delete-aggregate-attachment-1" ||
		updated.Steps[1].Name != "delete-aggregate-attachment-2" ||
		updated.Steps[2].Name != "delete-aggregate-class" ||
		updated.Steps[3].Name != "delete-root-qdisc" {
		t.Fatalf("unexpected routing mark-backed cleanup steps, got %#v", updated.Steps)
	}
	if !strings.Contains(updated.Reason, "removes observed concrete attachment rules") {
		t.Fatalf("expected routing mark-backed cleanup reason to mention observed attachment cleanup, got %#v", updated)
	}
}

func TestAppendUUIDAggregateObservedAttachmentCleanupRemovesObservedRoutingClientMarkAttachments(t *testing.T) {
	session := testUUIDAggregateSession("conn-1")
	session.Client.IP = ""
	staleApplyPlan := testUUIDAggregateRoutingPlanForDirection(
		t,
		UUIDAggregateOperationApply,
		DirectionDownload,
		[]discovery.Session{session},
		[]discovery.UUIDRoutingContext{
			testUUIDAggregateClientRoutingContext(t, "tcp", "198.51.100.44", 43120),
		},
		testUUIDAggregateRoutingAssessment(
			t,
			discovery.UUIDRoutingEvidenceFreshnessFresh,
			true,
			false,
			"uuid routing evidence is fresh enough to reuse without a refresh",
		),
	)
	removePlan, err := (Planner{}).PlanUUIDAggregate(UUIDAggregatePlanInput{
		Operation:  UUIDAggregateOperationRemove,
		Membership: testUUIDAggregateMembership(t),
		Scope: Scope{
			Device:    "eth0",
			Direction: DirectionDownload,
		},
	})
	if err != nil {
		t.Fatalf("expected zero-member aggregate remove plan to succeed, got %v", err)
	}

	snapshot, nftSnapshot := testUUIDAggregateObservedMarkAttachmentSnapshot(staleApplyPlan, 2048)
	updated, err := AppendUUIDAggregateObservedAttachmentCleanup(removePlan, snapshot, &nftSnapshot)
	if err != nil {
		t.Fatalf("expected routing client mark-backed aggregate cleanup to succeed, got %v", err)
	}
	if len(updated.Steps) != 4 {
		t.Fatalf("expected mark-backed filter cleanup, nft rule cleanup, class delete, and root qdisc delete for routing client cleanup, got %#v", updated.Steps)
	}
	if updated.Steps[0].Name != "delete-aggregate-attachment-1" ||
		updated.Steps[1].Name != "delete-aggregate-attachment-2" ||
		updated.Steps[2].Name != "delete-aggregate-class" ||
		updated.Steps[3].Name != "delete-root-qdisc" {
		t.Fatalf("unexpected routing client mark-backed cleanup steps, got %#v", updated.Steps)
	}
	if !strings.Contains(updated.Reason, "removes observed concrete attachment rules") {
		t.Fatalf("expected routing client mark-backed cleanup reason to mention observed attachment cleanup, got %#v", updated)
	}
}

func TestAppendUUIDAggregateObservedAttachmentCleanupRemovesObservedRoutingMarkRulesWithoutFilters(t *testing.T) {
	session := testUUIDAggregateSession("conn-1")
	session.Client.IP = ""
	staleApplyPlan := testUUIDAggregateRoutingPlan(
		t,
		UUIDAggregateOperationApply,
		[]discovery.Session{session},
		[]discovery.UUIDRoutingContext{
			testUUIDAggregateRoutingContext(t, "tcp", "10.10.0.2", 8443),
		},
		testUUIDAggregateRoutingAssessment(
			t,
			discovery.UUIDRoutingEvidenceFreshnessFresh,
			true,
			false,
			"uuid routing evidence is fresh enough to reuse without a refresh",
		),
	)
	removePlan, err := (Planner{}).PlanUUIDAggregate(UUIDAggregatePlanInput{
		Operation:  UUIDAggregateOperationRemove,
		Membership: testUUIDAggregateMembership(t),
		Scope: Scope{
			Device:    "eth0",
			Direction: DirectionUpload,
		},
	})
	if err != nil {
		t.Fatalf("expected zero-member aggregate remove plan to succeed, got %v", err)
	}

	snapshot, nftSnapshot := testUUIDAggregateObservedMarkAttachmentSnapshot(staleApplyPlan, 2048)
	snapshot.Filters = nil
	updated, err := AppendUUIDAggregateObservedAttachmentCleanup(removePlan, snapshot, &nftSnapshot)
	if err != nil {
		t.Fatalf("expected routing mark-rule cleanup without filters to succeed, got %v", err)
	}
	if len(updated.Steps) != 2 {
		t.Fatalf("expected nft rule cleanup plus class delete without stale tc filters, got %#v", updated.Steps)
	}
	if updated.Steps[0].Command.Path != defaultNftBinary || updated.Steps[1].Name != "delete-aggregate-class" {
		t.Fatalf("unexpected routing mark-rule cleanup steps, got %#v", updated.Steps)
	}
	if strings.Contains(updated.Reason, "root htb qdisc") {
		t.Fatalf("expected routing mark-rule cleanup without filters to avoid root qdisc cleanup claims, got %#v", updated)
	}
}

func TestObserveUUIDAggregateRemoveKeepsObservedAttachmentStateWhenClassIsGone(t *testing.T) {
	plan, err := (Planner{}).PlanUUIDAggregate(UUIDAggregatePlanInput{
		Operation:  UUIDAggregateOperationRemove,
		Membership: testUUIDAggregateMembership(t),
		Scope: Scope{
			Device:    "eth0",
			Direction: DirectionUpload,
		},
	})
	if err != nil {
		t.Fatalf("expected aggregate remove plan to succeed, got %v", err)
	}

	observation, err := ObserveUUIDAggregate(Snapshot{
		Device: "eth0",
		QDiscs: []QDiscState{
			{Kind: "htb", Handle: plan.Handles.RootHandle, Parent: "root"},
		},
		Filters: []FilterState{
			{Kind: "u32", Parent: plan.Handles.RootHandle, Protocol: "ip", Preference: 120, FlowID: plan.Handles.ClassID},
		},
	}, nil, plan)
	if err != nil {
		t.Fatalf("expected aggregate observation with attachment-only state to succeed, got %v", err)
	}

	if observation.Matched {
		t.Fatalf("expected aggregate observation to keep the missing class unmatched, got %#v", observation)
	}
	if !observation.ObservedAttachmentPresent {
		t.Fatalf("expected aggregate observation to retain observed attachment-only state, got %#v", observation)
	}
	if !observation.CleanupRootQDisc {
		t.Fatalf("expected aggregate observation to restore root qdisc cleanup eligibility after attachment-only cleanup, got %#v", observation)
	}
}

func TestDecideUUIDAggregateRemoveNoOpWhenSharedClassIsAbsent(t *testing.T) {
	plan, err := (Planner{}).PlanUUIDAggregate(UUIDAggregatePlanInput{
		Operation:  UUIDAggregateOperationRemove,
		Membership: testUUIDAggregateMembership(t),
		Scope: Scope{
			Device:    "eth0",
			Direction: DirectionUpload,
		},
	})
	if err != nil {
		t.Fatalf("expected aggregate remove plan to succeed, got %v", err)
	}

	decision, err := DecideUUIDAggregate(plan, UUIDAggregateObservation{
		Available:       true,
		Reconcilable:    true,
		ExpectedClassID: plan.Handles.ClassID,
	}, 0)
	if err != nil {
		t.Fatalf("expected aggregate remove decision to succeed, got %v", err)
	}

	if decision.Kind != limiter.DecisionNoOp {
		t.Fatalf("expected aggregate remove no-op when class is absent, got %#v", decision)
	}
}

func TestDecideUUIDAggregateRemoveWhenObservedAttachmentsRemainAfterClassIsGone(t *testing.T) {
	plan, err := (Planner{}).PlanUUIDAggregate(UUIDAggregatePlanInput{
		Operation:  UUIDAggregateOperationRemove,
		Membership: testUUIDAggregateMembership(t),
		Scope: Scope{
			Device:    "eth0",
			Direction: DirectionUpload,
		},
	})
	if err != nil {
		t.Fatalf("expected aggregate remove plan to succeed, got %v", err)
	}

	decision, err := DecideUUIDAggregate(plan, UUIDAggregateObservation{
		Available:                 true,
		Reconcilable:              true,
		ExpectedClassID:           plan.Handles.ClassID,
		ObservedAttachmentPresent: true,
		CleanupRootQDisc:          true,
	}, 0)
	if err != nil {
		t.Fatalf("expected aggregate remove decision to succeed, got %v", err)
	}

	if decision.Kind != limiter.DecisionRemove {
		t.Fatalf("expected aggregate remove when observed attachments remain after the class is gone, got %#v", decision)
	}
}

func TestPlannerPlanUUIDAggregateRejectsInvalidInput(t *testing.T) {
	_, err := (Planner{}).PlanUUIDAggregate(UUIDAggregatePlanInput{
		Membership: correlation.UUIDAggregateMembership{
			Subject: correlation.UUIDAggregateSubject{
				UUID:    "",
				Runtime: testUUIDAggregateRuntime(),
			},
		},
		Scope: Scope{
			Device:    "eth0",
			Direction: DirectionUpload,
		},
		Limits: policy.LimitPolicy{
			Upload: &policy.RateLimit{BytesPerSecond: 2048},
		},
	})
	if err == nil {
		t.Fatal("expected invalid aggregate subject to fail planning")
	}

	_, err = (Planner{}).PlanUUIDAggregate(UUIDAggregatePlanInput{
		Membership: testUUIDAggregateMembership(t, testUUIDAggregateSession("conn-1")),
		Scope: Scope{
			Device:    "eth0",
			Direction: DirectionDownload,
		},
		Limits: policy.LimitPolicy{
			Upload: &policy.RateLimit{BytesPerSecond: 2048},
		},
	})
	if err == nil {
		t.Fatal("expected missing directional aggregate limit to fail planning")
	}

	_, err = (Planner{}).PlanUUIDAggregate(UUIDAggregatePlanInput{
		Operation:  UUIDAggregateOperationRemove,
		Membership: testUUIDAggregateMembership(t, testUUIDAggregateSession("conn-1")),
		Scope: Scope{
			Device:    "eth0",
			Direction: DirectionUpload,
		},
		Limits: policy.LimitPolicy{
			Upload: &policy.RateLimit{BytesPerSecond: 2048},
		},
	})
	if err == nil {
		t.Fatal("expected aggregate remove planning with limits to fail")
	}
}
