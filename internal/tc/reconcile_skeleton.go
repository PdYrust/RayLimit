package tc

import (
	"errors"
	"fmt"
	"sort"
	"strings"
)

// ReconcileOutcomeKind identifies the next cheap-first control-plane outcome
// for one managed owner.
type ReconcileOutcomeKind string

const (
	ReconcileOutcomeNoChange               ReconcileOutcomeKind = "no_change"
	ReconcileOutcomeApplyDelta             ReconcileOutcomeKind = "apply_delta"
	ReconcileOutcomeCleanupStale           ReconcileOutcomeKind = "cleanup_stale"
	ReconcileOutcomeBlockedMissingEvidence ReconcileOutcomeKind = "blocked_missing_evidence"
	ReconcileOutcomeDefer                  ReconcileOutcomeKind = "defer"
)

func (k ReconcileOutcomeKind) Valid() bool {
	switch k {
	case ReconcileOutcomeNoChange,
		ReconcileOutcomeApplyDelta,
		ReconcileOutcomeCleanupStale,
		ReconcileOutcomeBlockedMissingEvidence,
		ReconcileOutcomeDefer:
		return true
	default:
		return false
	}
}

// ReconcileRetainEvidence captures the current runtime-derived proof gates that
// allow an owner to remain valid or be recreated cheaply.
type ReconcileRetainEvidence struct {
	AllowsRetain   bool   `json:"allows_retain,omitempty"`
	AllowsRecreate bool   `json:"allows_recreate,omitempty"`
	Reason         string `json:"reason,omitempty"`
}

func (e ReconcileRetainEvidence) Validate() error {
	return nil
}

// PeriodicReconcileInput is the owner-aware managed-state delta contract later
// periodic loops can build on.
type PeriodicReconcileInput struct {
	Desired        ManagedStateSet         `json:"desired"`
	Observed       ManagedStateSet         `json:"observed"`
	RetainEvidence ReconcileRetainEvidence `json:"retain_evidence,omitempty"`
}

func (i PeriodicReconcileInput) Validate() error {
	if err := i.Desired.Validate(); err != nil {
		return fmt.Errorf("invalid desired managed state: %w", err)
	}
	if err := i.Observed.Validate(); err != nil {
		return fmt.Errorf("invalid observed managed state: %w", err)
	}
	if strings.TrimSpace(i.Desired.OwnerKey) != "" &&
		strings.TrimSpace(i.Observed.OwnerKey) != "" &&
		strings.TrimSpace(i.Desired.OwnerKey) != strings.TrimSpace(i.Observed.OwnerKey) {
		return errors.New("desired and observed managed state do not describe the same owner")
	}
	if err := i.RetainEvidence.Validate(); err != nil {
		return fmt.Errorf("invalid retain evidence: %w", err)
	}

	return nil
}

// PeriodicReconcileResult captures the minimal delta-oriented outcome for one
// managed owner.
type PeriodicReconcileResult struct {
	Kind              ReconcileOutcomeKind  `json:"kind"`
	OwnerKey          string                `json:"owner_key,omitempty"`
	Inventory         ManagedStateInventory `json:"inventory"`
	MissingDesired    []ManagedObject       `json:"missing_desired,omitempty"`
	CleanupCandidates []StaleManagedObject  `json:"cleanup_candidates,omitempty"`
	Reason            string                `json:"reason"`
}

func (r PeriodicReconcileResult) Validate() error {
	if !r.Kind.Valid() {
		return fmt.Errorf("invalid reconcile outcome kind %q", r.Kind)
	}
	if err := r.Inventory.Validate(); err != nil {
		return fmt.Errorf("invalid reconcile inventory: %w", err)
	}
	for index, object := range r.MissingDesired {
		if err := object.Validate(); err != nil {
			return fmt.Errorf("invalid missing desired object at index %d: %w", index, err)
		}
	}
	for index, object := range r.CleanupCandidates {
		if err := object.Validate(); err != nil {
			return fmt.Errorf("invalid cleanup candidate at index %d: %w", index, err)
		}
	}
	if strings.TrimSpace(r.Reason) == "" {
		return errors.New("reconcile result reason is required")
	}

	switch r.Kind {
	case ReconcileOutcomeNoChange:
		if len(r.MissingDesired) != 0 || len(r.CleanupCandidates) != 0 {
			return errors.New("no_change result cannot include missing desired objects or cleanup candidates")
		}
	case ReconcileOutcomeApplyDelta, ReconcileOutcomeBlockedMissingEvidence:
		if len(r.MissingDesired) == 0 {
			return errors.New("apply_delta and blocked_missing_evidence results require missing desired objects")
		}
	case ReconcileOutcomeCleanupStale:
		if len(r.CleanupCandidates) == 0 {
			return errors.New("cleanup_stale result requires cleanup candidates")
		}
		if len(r.MissingDesired) != 0 {
			return errors.New("cleanup_stale result cannot include missing desired objects")
		}
	case ReconcileOutcomeDefer:
	}

	return nil
}

// PeriodicReconciler decides the next cheap-first delta action without building
// a full daemon loop.
type PeriodicReconciler struct{}

// Decide compares desired and observed owned state plus current retain/recreate
// proof and returns the smallest safe next outcome.
func (PeriodicReconciler) Decide(input PeriodicReconcileInput) (PeriodicReconcileResult, error) {
	if err := input.Validate(); err != nil {
		return PeriodicReconcileResult{}, err
	}

	inventory, err := ClassifyManagedState(input.Desired, input.Observed)
	if err != nil {
		return PeriodicReconcileResult{}, err
	}
	result := PeriodicReconcileResult{
		OwnerKey:  inventory.OwnerKey,
		Inventory: inventory,
	}

	missing := missingManagedObjects(input.Desired.Objects, input.Observed.Objects)
	cleanupCandidates := cleanupEligibleStaleObjects(inventory.Stale)
	desiredNeedsRetainEvidence := managedObjectsRequireRuntimeEvidence(input.Desired.Objects)
	missingNeedsRecreateEvidence := managedObjectsRequireRuntimeEvidence(missing)

	switch {
	case len(missing) == 0 && len(inventory.Stale) == 0:
		if desiredNeedsRetainEvidence && !input.RetainEvidence.AllowsRetain {
			result.Kind = ReconcileOutcomeDefer
			result.Reason = reconcileEvidenceReason(
				"desired and observed managed state already match, but runtime-derived retain evidence is not currently strong enough to keep refreshing this owner cheaply",
				input.RetainEvidence,
			)
			break
		}
		result.Kind = ReconcileOutcomeNoChange
		result.Reason = "desired and observed managed state already match; no mutation is required"
	case len(missing) != 0:
		result.MissingDesired = missing
		result.CleanupCandidates = cleanupCandidates
		if missingNeedsRecreateEvidence && !input.RetainEvidence.AllowsRecreate {
			result.Kind = ReconcileOutcomeBlockedMissingEvidence
			result.Reason = reconcileEvidenceReason(
				"desired managed state is missing observed owned objects, but safe recreation currently lacks the required runtime-derived evidence",
				input.RetainEvidence,
			)
			break
		}
		result.Kind = ReconcileOutcomeApplyDelta
		result.Reason = "desired managed state differs from observed state; apply only the missing managed objects"
	case len(cleanupCandidates) != 0:
		result.Kind = ReconcileOutcomeCleanupStale
		result.CleanupCandidates = cleanupCandidates
		result.Reason = "observed stale managed objects are cleanup-eligible and no desired delta remains"
	default:
		result.Kind = ReconcileOutcomeDefer
		result.Reason = "observed stale managed objects remain, but none are cleanup-eligible yet"
	}

	sortManagedObjects(result.MissingDesired)
	sort.Slice(result.CleanupCandidates, func(i, j int) bool {
		return result.CleanupCandidates[i].Object.fingerprint() < result.CleanupCandidates[j].Object.fingerprint()
	})
	if err := result.Validate(); err != nil {
		return PeriodicReconcileResult{}, err
	}

	return result, nil
}

func missingManagedObjects(desired []ManagedObject, observed []ManagedObject) []ManagedObject {
	if len(desired) == 0 {
		return nil
	}

	observedKeys := make(map[string]struct{}, len(observed))
	for _, object := range observed {
		observedKeys[object.fingerprint()] = struct{}{}
	}

	missing := make([]ManagedObject, 0, len(desired))
	for _, object := range desired {
		if _, ok := observedKeys[object.fingerprint()]; ok {
			continue
		}
		missing = append(missing, object)
	}

	return missing
}

func cleanupEligibleStaleObjects(stale []StaleManagedObject) []StaleManagedObject {
	candidates := make([]StaleManagedObject, 0, len(stale))
	for _, object := range stale {
		if object.CleanupEligible {
			candidates = append(candidates, object)
		}
	}

	return candidates
}

func managedObjectsRequireRuntimeEvidence(objects []ManagedObject) bool {
	for _, object := range objects {
		if object.RetainRequiresRuntimeEvidence {
			return true
		}
	}

	return false
}

func reconcileEvidenceReason(base string, evidence ReconcileRetainEvidence) string {
	reason := strings.TrimSpace(base)
	if note := strings.TrimSpace(evidence.Reason); note != "" {
		return reason + "; " + note
	}

	return reason
}
