package tc

import (
	"errors"
	"strings"

	"github.com/PdYrust/RayLimit/internal/limiter"
	"github.com/PdYrust/RayLimit/internal/policy"
)

const (
	stepEnsureRootQDisc          = "ensure-root-qdisc"
	stepReplaceForeignRootQDisc  = "replace-foreign-root-qdisc"
	stepUpsertClass              = "upsert-class"
	stepUpsertDirectAttachPrefix = "upsert-direct-attachment-"
)

// AppendIdempotentApply rewrites an apply or reconcile plan's tc steps so they
// are safe to run against the observed device snapshot. It is the snapshot-aware
// counterpart to AppendMarkAttachmentApply for the htb root qdisc, class, and
// direct-attachment filters:
//
//   - ensure-root-qdisc is dropped when the managed htb root qdisc already
//     exists, so existing sibling classes and filters (for example the upload
//     class while the download apply runs) are preserved;
//   - ensure-root-qdisc is rewritten to an explicit delete followed by add when
//     a foreign (non-managed) qdisc occupies the root, rather than relying on a
//     destructive blind replace;
//   - upsert-class is dropped when the observed class already matches the
//     desired rate and ceil;
//   - upsert-direct-attachment-N is dropped when a matching filter is already
//     observed.
//
// When the snapshot carries no device (a zero snapshot) the plan is returned
// unchanged so callers without observed state keep the from-scratch plan. The
// executor applies the same guarantees at execution time through its
// already-exists recovery, so this rewriting is a plan-time optimisation that
// also keeps dry-run previews accurate.
//
// Deferred: not wired into production; the mark-attachment path
// (AppendMarkAttachmentApply at limit.go:1616) is the live idempotency
// mechanism for the production flow, and the executor's execution-time
// already-exists recovery (recoverExistingObject in runner.go) is the
// correctness backstop that covers these same cases by re-inspecting the
// device. This function and its tests are retained, correct and unwired, for
// the direct-attachment dry-run preview accuracy optimisation if it is later
// prioritised; it currently has no production caller.
func AppendIdempotentApply(plan Plan, snapshot Snapshot) (Plan, error) {
	if err := plan.Validate(); err != nil {
		return Plan{}, err
	}
	if plan.Action.Kind != limiter.ActionApply && plan.Action.Kind != limiter.ActionReconcile {
		return Plan{}, errors.New("idempotent apply rewriting requires an apply or reconcile plan")
	}
	if isAllIPPerIPSubject(plan.Action.Subject) {
		return plan, nil
	}
	if strings.TrimSpace(snapshot.Device) == "" {
		// No observed state to reconcile against; keep the from-scratch plan.
		return plan, nil
	}
	if err := snapshot.Validate(); err != nil {
		return Plan{}, err
	}

	rootHandle := plan.Handles.RootHandle
	hasManagedRoot := snapshotHasManagedRootQDisc(snapshot, rootHandle)
	_, hasForeignRoot := snapshotForeignRootQDisc(snapshot, rootHandle)

	desiredRate, hasDesiredRate := int64(0), false
	if plan.Action.Desired != nil && plan.Action.Desired.Mode == limiter.DesiredModeLimit {
		desiredRate, hasDesiredRate = directionRateBytes(plan.Action.Desired.Limits, plan.Scope.Direction)
	}

	next := plan
	rewritten := make([]Step, 0, len(plan.Steps)+1)
	for _, step := range plan.Steps {
		name := strings.TrimSpace(step.Name)
		switch {
		case name == stepEnsureRootQDisc:
			if hasManagedRoot {
				// Managed htb root already present; skip to preserve children.
				continue
			}
			if hasForeignRoot {
				// A different qdisc owns the root; delete it before adding ours
				// instead of issuing a destructive blind replace.
				rewritten = append(rewritten, tcStep(plan, stepReplaceForeignRootQDisc,
					"qdisc", "del", "dev", plan.Scope.Device, "root"))
			}
			rewritten = append(rewritten, step)
		case name == stepUpsertClass:
			if hasDesiredRate && snapshotClassMatchesDesiredRate(snapshot, plan.Handles.ClassID, desiredRate) {
				continue
			}
			rewritten = append(rewritten, step)
		case strings.HasPrefix(name, stepUpsertDirectAttachPrefix):
			if snapshotHasDirectAttachmentFilter(snapshot, rootHandle, plan.Handles.ClassID, plan.AttachmentExecution) {
				continue
			}
			rewritten = append(rewritten, step)
		default:
			rewritten = append(rewritten, step)
		}
	}

	next.Steps = rewritten
	next.NoOp = len(rewritten) == 0
	if err := next.Validate(); err != nil {
		return Plan{}, err
	}

	return next, nil
}

// tcStep builds a tc step that reuses the plan's resolved tc binary path.
func tcStep(plan Plan, name string, args ...string) Step {
	return Step{
		Name: name,
		Command: Command{
			Path: tcCommandPath(plan),
			Args: args,
		},
	}
}

// snapshotForeignRootQDisc returns the first observed root qdisc that is not the
// RayLimit-managed htb root at the expected handle.
func snapshotForeignRootQDisc(snapshot Snapshot, rootHandle string) (QDiscState, bool) {
	for _, qdisc := range snapshot.QDiscs {
		if strings.TrimSpace(qdisc.Parent) != "root" {
			continue
		}
		if strings.TrimSpace(qdisc.Kind) == "htb" &&
			strings.TrimSpace(qdisc.Handle) == strings.TrimSpace(rootHandle) {
			continue
		}

		return qdisc, true
	}

	return QDiscState{}, false
}

// snapshotClassMatchesDesiredRate reports whether the observed class already
// carries the desired rate and ceil in bytes per second.
func snapshotClassMatchesDesiredRate(snapshot Snapshot, classID string, rateBytesPerSecond int64) bool {
	class, ok := snapshot.Class(classID)
	if !ok {
		return false
	}

	return class.RateBytesPerSecond == rateBytesPerSecond &&
		class.CeilBytesPerSecond == rateBytesPerSecond
}

// snapshotHasDirectAttachmentFilter reports whether the observed snapshot
// already carries a filter matching the planned direct attachment execution.
func snapshotHasDirectAttachmentFilter(snapshot Snapshot, rootHandle string, classID string, execution DirectAttachmentExecution) bool {
	if execution.Readiness != BindingReadinessReady {
		return false
	}

	return len(snapshot.DirectAttachmentFilters(rootHandle, classID, execution)) > 0
}

// directionRateBytes returns the desired rate in bytes per second for a scope
// direction.
func directionRateBytes(limits policy.LimitPolicy, direction Direction) (int64, bool) {
	switch direction {
	case DirectionUpload:
		if limits.Upload != nil {
			return limits.Upload.BytesPerSecond, true
		}
	case DirectionDownload:
		if limits.Download != nil {
			return limits.Download.BytesPerSecond, true
		}
	}

	return 0, false
}
