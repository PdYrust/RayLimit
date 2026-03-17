package tc

import (
	"strings"
	"testing"

	"github.com/PdYrust/RayLimit/internal/policy"
)

func testCleanupStaleReconcileResult(t *testing.T, observed ManagedStateSet) PeriodicReconcileResult {
	t.Helper()

	result, err := (PeriodicReconciler{}).Decide(PeriodicReconcileInput{
		Desired:  ManagedStateSet{OwnerKey: observed.OwnerKey},
		Observed: observed,
	})
	if err != nil {
		t.Fatalf("expected stale reconcile result to succeed, got %v", err)
	}

	return result
}

func TestGarbageCollectorPlansDirectAttachmentCleanupDelta(t *testing.T) {
	plan := testManagedPlan(t, policy.TargetKindIP, DirectionUpload, 2048)
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

	observed, err := ObservedManagedState(snapshot, NftablesSnapshot{}, plan)
	if err != nil {
		t.Fatalf("expected observed managed state to succeed, got %v", err)
	}
	reconcile := testCleanupStaleReconcileResult(t, observed)

	gcPlan, err := (GarbageCollector{}).Plan(GarbageCollectionInput{
		Reconcile:        reconcile,
		Snapshot:         snapshot,
		NftablesSnapshot: NftablesSnapshot{},
	})
	if err != nil {
		t.Fatalf("expected direct stale GC plan to succeed, got %v", err)
	}

	if gcPlan.Kind != GarbageCollectionOutcomeCleanupDelta {
		t.Fatalf("expected cleanup_delta GC outcome, got %#v", gcPlan)
	}
	if len(gcPlan.Steps) != 3 {
		t.Fatalf("expected direct stale cleanup to remove filter, class, and root qdisc, got %#v", gcPlan.Steps)
	}
	if gcPlan.Steps[0].Name != "delete-stale-direct-attachment-1" ||
		gcPlan.Steps[1].Name != "delete-stale-class-1" ||
		gcPlan.Steps[2].Name != "delete-stale-root-qdisc-1" {
		t.Fatalf("unexpected direct stale cleanup step order, got %#v", gcPlan.Steps)
	}
}

func TestGarbageCollectorDefersCleanupWhileDesiredDeltaStillNeedsApply(t *testing.T) {
	reconcile, err := (PeriodicReconciler{}).Decide(PeriodicReconcileInput{
		Desired: ManagedStateSet{
			OwnerKey: "host_process|xray|xray|1234|container-1|ip|203.0.113.10",
			Objects: []ManagedObject{
				testPeriodicReconcileObject(ManagedObjectRootQDisc, "1:", false, false, true),
				testPeriodicReconcileObject(ManagedObjectClass, "1:1001", false, false, false),
			},
		},
		Observed: ManagedStateSet{
			OwnerKey: "host_process|xray|xray|1234|container-1|ip|203.0.113.10",
			Objects: []ManagedObject{
				testPeriodicReconcileObject(ManagedObjectRootQDisc, "1:", false, false, true),
				testPeriodicReconcileObject(ManagedObjectClass, "1:2002", false, false, false),
			},
		},
	})
	if err != nil {
		t.Fatalf("expected mixed stale/delta reconcile result to succeed, got %v", err)
	}

	gcPlan, err := (GarbageCollector{}).Plan(GarbageCollectionInput{
		Reconcile: reconcile,
		Snapshot: Snapshot{
			Device: "eth0",
		},
		NftablesSnapshot: NftablesSnapshot{},
	})
	if err != nil {
		t.Fatalf("expected deferred GC plan to succeed, got %v", err)
	}

	if gcPlan.Kind != GarbageCollectionOutcomeDefer {
		t.Fatalf("expected defer GC outcome while desired delta remains, got %#v", gcPlan)
	}
	if len(gcPlan.Steps) != 0 {
		t.Fatalf("expected no cleanup steps while desired delta remains, got %#v", gcPlan.Steps)
	}
	if len(gcPlan.Deferred) == 0 {
		t.Fatalf("expected deferred stale objects, got %#v", gcPlan)
	}
}

func TestGarbageCollectorPlansMarkBackedCleanupIncludingTable(t *testing.T) {
	plan := testManagedPlan(t, policy.TargetKindInbound, DirectionUpload, 2048)
	execution := testInboundMarkAttachmentExecution(t, plan)
	plan.MarkAttachment = &execution
	tcSnapshot, nftSnapshot := testObservedMarkManagedState(plan.Scope, plan.Handles.ClassID, execution)

	observed, err := ObservedManagedState(tcSnapshot, nftSnapshot, plan)
	if err != nil {
		t.Fatalf("expected observed mark-backed managed state to succeed, got %v", err)
	}
	reconcile := testCleanupStaleReconcileResult(t, observed)

	gcPlan, err := (GarbageCollector{}).Plan(GarbageCollectionInput{
		Reconcile:        reconcile,
		Snapshot:         tcSnapshot,
		NftablesSnapshot: nftSnapshot,
	})
	if err != nil {
		t.Fatalf("expected mark-backed stale GC plan to succeed, got %v", err)
	}

	if gcPlan.Kind != GarbageCollectionOutcomeCleanupDelta {
		t.Fatalf("expected cleanup_delta GC outcome, got %#v", gcPlan)
	}
	names := make([]string, 0, len(gcPlan.Steps))
	for _, step := range gcPlan.Steps {
		names = append(names, step.Name)
	}
	for _, expected := range []string{
		"delete-stale-mark-attachment-filter-1",
		"delete-stale-class-1",
		"delete-stale-mark-attachment-rule-1",
		"delete-stale-mark-attachment-rule-2",
		"delete-stale-mark-attachment-chain-1",
		"delete-stale-mark-attachment-chain-2",
		"delete-stale-mark-attachment-table-1",
		"delete-stale-root-qdisc-1",
	} {
		if !containsString(names, expected) {
			t.Fatalf("expected mark-backed stale cleanup step %q, got %#v", expected, gcPlan.Steps)
		}
	}
	if last := gcPlan.Steps[len(gcPlan.Steps)-1].Name; last != "delete-stale-root-qdisc-1" {
		t.Fatalf("expected root qdisc cleanup to stay last, got %#v", gcPlan.Steps)
	}
}

func TestGarbageCollectorPlansUUIDAggregateCleanupDelta(t *testing.T) {
	plan, err := (Planner{}).PlanUUIDAggregate(UUIDAggregatePlanInput{
		Operation: UUIDAggregateOperationApply,
		Membership: testUUIDAggregateMembership(
			t,
			testUUIDAggregateSession("conn-1"),
			testUUIDAggregateSession("conn-2"),
		),
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
		QDiscs: []QDiscState{{Kind: "htb", Handle: plan.Handles.RootHandle, Parent: "root"}},
		Classes: []ClassState{{
			Kind:    "htb",
			ClassID: plan.Handles.ClassID,
			Parent:  plan.Handles.RootHandle,
		}},
		Filters: []FilterState{
			{Kind: "u32", Parent: plan.Handles.RootHandle, Protocol: "ip", Preference: 120, FlowID: plan.Handles.ClassID},
			{Kind: "u32", Parent: plan.Handles.RootHandle, Protocol: "ip", Preference: 140, FlowID: plan.Handles.ClassID},
		},
	}

	observed, err := ObservedUUIDAggregateManagedState(snapshot, NftablesSnapshot{}, plan)
	if err != nil {
		t.Fatalf("expected observed aggregate managed state to succeed, got %v", err)
	}
	reconcile := testCleanupStaleReconcileResult(t, observed)

	gcPlan, err := (GarbageCollector{}).Plan(GarbageCollectionInput{
		Reconcile:        reconcile,
		Snapshot:         snapshot,
		NftablesSnapshot: NftablesSnapshot{},
	})
	if err != nil {
		t.Fatalf("expected aggregate stale GC plan to succeed, got %v", err)
	}

	if gcPlan.Kind != GarbageCollectionOutcomeCleanupDelta {
		t.Fatalf("expected cleanup_delta aggregate GC outcome, got %#v", gcPlan)
	}
	if len(gcPlan.Steps) != 4 {
		t.Fatalf("expected aggregate stale cleanup to remove two filters, class, and root qdisc, got %#v", gcPlan.Steps)
	}
	if gcPlan.Steps[0].Name != "delete-stale-aggregate-attachment-1" ||
		gcPlan.Steps[1].Name != "delete-stale-aggregate-attachment-2" ||
		gcPlan.Steps[2].Name != "delete-stale-class-1" ||
		gcPlan.Steps[3].Name != "delete-stale-root-qdisc-1" {
		t.Fatalf("unexpected aggregate stale cleanup step order, got %#v", gcPlan.Steps)
	}
}

func TestGarbageCollectorDefersWhenObservedStaleObjectsRemainEvidenceGated(t *testing.T) {
	observed := ManagedStateSet{
		OwnerKey: "host_process|xray|xray|1234|container-1|inbound|api-in",
		Objects: []ManagedObject{
			testPeriodicReconcileObject(ManagedObjectMarkAttachmentTable, "inet|raylimit", true, false, false),
		},
	}
	reconcile := testCleanupStaleReconcileResult(t, observed)

	gcPlan, err := (GarbageCollector{}).Plan(GarbageCollectionInput{
		Reconcile: reconcile,
		Snapshot: Snapshot{
			Device: "eth0",
		},
		NftablesSnapshot: NftablesSnapshot{},
	})
	if err != nil {
		t.Fatalf("expected deferred stale GC plan to succeed, got %v", err)
	}

	if gcPlan.Kind != GarbageCollectionOutcomeDefer {
		t.Fatalf("expected deferred stale GC outcome, got %#v", gcPlan)
	}
	if len(gcPlan.Deferred) != 1 || gcPlan.Deferred[0].Object.Kind != ManagedObjectMarkAttachmentTable {
		t.Fatalf("expected deferred mark attachment table ownership, got %#v", gcPlan)
	}
	if len(gcPlan.Steps) != 0 {
		t.Fatalf("expected no cleanup steps for deferred GC plan, got %#v", gcPlan.Steps)
	}
}

func containsString(values []string, want string) bool {
	for _, value := range values {
		if strings.TrimSpace(value) == strings.TrimSpace(want) {
			return true
		}
	}

	return false
}
