package tc

import (
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/PdYrust/RayLimit/internal/discovery"
)

// RestartRecoveryOutcomeKind describes the first safe post-restart treatment
// for previously managed observed state.
type RestartRecoveryOutcomeKind string

const (
	RestartRecoveryRecoverableObservedState RestartRecoveryOutcomeKind = "recoverable_observed_state"
	RestartRecoveryRefreshRequired          RestartRecoveryOutcomeKind = "restart_refresh_required"
	RestartRecoveryGraceRetained            RestartRecoveryOutcomeKind = "restart_grace_retained"
	RestartRecoveryCleanupSafe              RestartRecoveryOutcomeKind = "restart_cleanup_safe"
	RestartRecoveryDefer                    RestartRecoveryOutcomeKind = "restart_defer"
)

func (k RestartRecoveryOutcomeKind) Valid() bool {
	switch k {
	case RestartRecoveryRecoverableObservedState,
		RestartRecoveryRefreshRequired,
		RestartRecoveryGraceRetained,
		RestartRecoveryCleanupSafe,
		RestartRecoveryDefer:
		return true
	default:
		return false
	}
}

// RestartRecoveryInput carries the minimal owner-aware, evidence-aware inputs
// needed to classify previously managed observed state after process restart.
type RestartRecoveryInput struct {
	Inventory       ManagedStateInventory                   `json:"inventory"`
	RuntimeEvidence *discovery.RuntimeEvidenceChurnDecision `json:"runtime_evidence,omitempty"`
}

func (i RestartRecoveryInput) Validate() error {
	if err := i.Inventory.Validate(); err != nil {
		return fmt.Errorf("invalid managed-state inventory: %w", err)
	}
	if i.RuntimeEvidence != nil {
		if err := i.RuntimeEvidence.Validate(); err != nil {
			return fmt.Errorf("invalid restart runtime evidence decision: %w", err)
		}
	}

	return nil
}

// RestartRecoveryResult captures whether observed managed state can be adopted,
// must refresh runtime proof, may survive briefly under grace, can be cleaned
// safely, or still needs to defer mutation after restart.
type RestartRecoveryResult struct {
	Kind                RestartRecoveryOutcomeKind `json:"kind"`
	OwnerKey            string                     `json:"owner_key,omitempty"`
	Inventory           ManagedStateInventory      `json:"inventory"`
	RecoverableObserved []ManagedObject            `json:"recoverable_observed,omitempty"`
	CleanupCandidates   []StaleManagedObject       `json:"cleanup_candidates,omitempty"`
	GraceUntil          *time.Time                 `json:"grace_until,omitempty"`
	Reason              string                     `json:"reason"`
}

func (r RestartRecoveryResult) Validate() error {
	if !r.Kind.Valid() {
		return fmt.Errorf("invalid restart recovery outcome kind %q", r.Kind)
	}
	if err := r.Inventory.Validate(); err != nil {
		return fmt.Errorf("invalid restart recovery inventory: %w", err)
	}
	for index, object := range r.RecoverableObserved {
		if err := object.Validate(); err != nil {
			return fmt.Errorf("invalid recoverable observed object at index %d: %w", index, err)
		}
	}
	for index, object := range r.CleanupCandidates {
		if err := object.Validate(); err != nil {
			return fmt.Errorf("invalid restart cleanup candidate at index %d: %w", index, err)
		}
	}
	if strings.TrimSpace(r.Reason) == "" {
		return errors.New("restart recovery reason is required")
	}

	switch r.Kind {
	case RestartRecoveryRecoverableObservedState:
		if len(r.RecoverableObserved) == 0 {
			return errors.New("recoverable_observed_state requires recoverable observed objects")
		}
		if len(r.CleanupCandidates) != 0 {
			return errors.New("recoverable_observed_state cannot include cleanup candidates")
		}
		if r.GraceUntil != nil {
			return errors.New("recoverable_observed_state cannot include a grace deadline")
		}
	case RestartRecoveryGraceRetained:
		if len(r.RecoverableObserved) == 0 {
			return errors.New("restart_grace_retained requires recoverable observed objects")
		}
		if r.GraceUntil == nil || r.GraceUntil.IsZero() {
			return errors.New("restart_grace_retained requires a grace deadline")
		}
		if len(r.CleanupCandidates) != 0 {
			return errors.New("restart_grace_retained cannot include cleanup candidates")
		}
	case RestartRecoveryCleanupSafe:
		if len(r.CleanupCandidates) == 0 {
			return errors.New("restart_cleanup_safe requires cleanup candidates")
		}
		if len(r.RecoverableObserved) != 0 {
			return errors.New("restart_cleanup_safe cannot include recoverable observed objects")
		}
		if r.GraceUntil != nil {
			return errors.New("restart_cleanup_safe cannot include a grace deadline")
		}
	case RestartRecoveryRefreshRequired, RestartRecoveryDefer:
		if len(r.RecoverableObserved) != 0 {
			return errors.New("restart_refresh_required and restart_defer cannot include recoverable observed objects")
		}
		if len(r.CleanupCandidates) != 0 {
			return errors.New("restart_refresh_required and restart_defer cannot include cleanup candidates")
		}
		if r.GraceUntil != nil {
			return errors.New("restart_refresh_required and restart_defer cannot include a grace deadline")
		}
	}

	return nil
}

// RestartRecoverer classifies previously managed observed state after restart
// without building a full daemon loop.
type RestartRecoverer struct{}

func (RestartRecoverer) Decide(input RestartRecoveryInput) (RestartRecoveryResult, error) {
	if err := input.Validate(); err != nil {
		return RestartRecoveryResult{}, err
	}

	result := RestartRecoveryResult{
		OwnerKey:  input.Inventory.OwnerKey,
		Inventory: input.Inventory,
	}

	if len(input.Inventory.Observed) == 0 {
		result.Kind = RestartRecoveryDefer
		result.Reason = "no previously managed observed state is present to recover after restart"
		if err := result.Validate(); err != nil {
			return RestartRecoveryResult{}, err
		}
		return result, nil
	}

	if !inventoryRequiresRuntimeEvidence(input.Inventory) {
		result.Kind = RestartRecoveryRecoverableObservedState
		result.RecoverableObserved = append([]ManagedObject(nil), input.Inventory.Observed...)
		result.Reason = "observed managed state belongs to a concrete owner and can be recovered after restart without fresh runtime proof"
		if err := result.Validate(); err != nil {
			return RestartRecoveryResult{}, err
		}
		return result, nil
	}

	if input.RuntimeEvidence == nil {
		result.Kind = RestartRecoveryRefreshRequired
		result.Reason = "observed managed state belongs to a runtime-derived owner, but cached runtime evidence is missing after restart and must be refreshed before retain or recreate decisions"
		if err := result.Validate(); err != nil {
			return RestartRecoveryResult{}, err
		}
		return result, nil
	}

	switch input.RuntimeEvidence.Action {
	case discovery.RuntimeEvidenceChurnActionStable:
		result.Kind = RestartRecoveryRecoverableObservedState
		result.RecoverableObserved = append([]ManagedObject(nil), input.Inventory.Observed...)
		result.Reason = restartRecoveryReason(
			"fresh trusted runtime evidence still supports this runtime-derived owner, so observed managed state can be adopted cheaply after restart",
			input.RuntimeEvidence,
		)
	case discovery.RuntimeEvidenceChurnActionGraceRetained:
		result.Kind = RestartRecoveryGraceRetained
		result.RecoverableObserved = append([]ManagedObject(nil), input.Inventory.Observed...)
		if input.RuntimeEvidence.GraceUntil != nil {
			copy := *input.RuntimeEvidence.GraceUntil
			result.GraceUntil = &copy
		}
		result.Reason = restartRecoveryReason(
			"runtime-derived owner evidence is briefly absent after restart, but observed managed state remains grace-retained to avoid reconnect flap churn",
			input.RuntimeEvidence,
		)
	case discovery.RuntimeEvidenceChurnActionRefreshRequired:
		result.Kind = RestartRecoveryRefreshRequired
		result.Reason = restartRecoveryReason(
			"runtime-derived owner evidence is stale after restart and still requires a fresher refresh before retain or recreate decisions",
			input.RuntimeEvidence,
		)
	case discovery.RuntimeEvidenceChurnActionImmediatelyRemovable:
		cleanupCandidates := cleanupEligibleStaleObjects(input.Inventory.Stale)
		if len(cleanupCandidates) == 0 {
			result.Kind = RestartRecoveryDefer
			result.Reason = restartRecoveryReason(
				"runtime-derived owner absence is confirmed after restart, but no cleanup-eligible observed managed state is available yet",
				input.RuntimeEvidence,
			)
			break
		}
		result.Kind = RestartRecoveryCleanupSafe
		result.CleanupCandidates = cleanupCandidates
		result.Reason = restartRecoveryReason(
			"runtime-derived owner absence is confirmed after restart and the remaining observed managed state is cleanup-safe",
			input.RuntimeEvidence,
		)
	case discovery.RuntimeEvidenceChurnActionDefer:
		result.Kind = RestartRecoveryDefer
		result.Reason = restartRecoveryReason(
			"runtime-derived owner evidence remains too weak after restart, so recovery still defers mutation",
			input.RuntimeEvidence,
		)
	default:
		return RestartRecoveryResult{}, fmt.Errorf("unsupported restart runtime evidence action %q", input.RuntimeEvidence.Action)
	}

	if err := result.Validate(); err != nil {
		return RestartRecoveryResult{}, err
	}

	return result, nil
}

func inventoryRequiresRuntimeEvidence(inventory ManagedStateInventory) bool {
	objects := make([]ManagedObject, 0, len(inventory.Desired)+len(inventory.Observed)+len(inventory.Stale))
	objects = append(objects, inventory.Desired...)
	objects = append(objects, inventory.Observed...)
	for _, stale := range inventory.Stale {
		objects = append(objects, stale.Object)
	}

	return managedObjectsRequireRuntimeEvidence(objects)
}

func restartRecoveryReason(base string, evidence *discovery.RuntimeEvidenceChurnDecision) string {
	reason := strings.TrimSpace(base)
	if evidence == nil {
		return reason
	}
	if note := strings.TrimSpace(evidence.Reason); note != "" {
		return reason + "; " + note
	}

	return reason
}
