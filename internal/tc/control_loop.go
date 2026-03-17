package tc

import (
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/PdYrust/RayLimit/internal/correlation"
	"github.com/PdYrust/RayLimit/internal/discovery"
)

// ControlLoopOutcomeKind identifies the integrated cheap-first control-loop
// outcome after combining runtime evidence, restart recovery, reconcile, and GC.
type ControlLoopOutcomeKind string

const (
	ControlLoopOutcomeNoChange               ControlLoopOutcomeKind = "no_change"
	ControlLoopOutcomeRestartRecovery        ControlLoopOutcomeKind = "restart_recovery"
	ControlLoopOutcomeApplyDelta             ControlLoopOutcomeKind = "apply_delta"
	ControlLoopOutcomeCleanupDelta           ControlLoopOutcomeKind = "cleanup_delta"
	ControlLoopOutcomeBlockedMissingEvidence ControlLoopOutcomeKind = "blocked_missing_evidence"
	ControlLoopOutcomeRefreshRequired        ControlLoopOutcomeKind = "refresh_required"
	ControlLoopOutcomeGraceRetained          ControlLoopOutcomeKind = "grace_retained"
	ControlLoopOutcomeDefer                  ControlLoopOutcomeKind = "defer"
)

func (k ControlLoopOutcomeKind) Valid() bool {
	switch k {
	case ControlLoopOutcomeNoChange,
		ControlLoopOutcomeRestartRecovery,
		ControlLoopOutcomeApplyDelta,
		ControlLoopOutcomeCleanupDelta,
		ControlLoopOutcomeBlockedMissingEvidence,
		ControlLoopOutcomeRefreshRequired,
		ControlLoopOutcomeGraceRetained,
		ControlLoopOutcomeDefer:
		return true
	default:
		return false
	}
}

// ControlLoopRuntimeSignals carries at most one authoritative runtime-derived
// evidence source for one owner in one control-loop cycle.
type ControlLoopRuntimeSignals struct {
	RuntimeEvidence       *discovery.RuntimeEvidenceChurnDecision  `json:"runtime_evidence,omitempty"`
	UUIDMembershipRefresh *correlation.UUIDMembershipRefreshResult `json:"uuid_membership_refresh,omitempty"`
	UUIDMembershipGrace   *correlation.UUIDMembershipGraceResult   `json:"uuid_membership_grace,omitempty"`
}

func (s ControlLoopRuntimeSignals) Validate() error {
	if s.RuntimeEvidence != nil {
		if err := s.RuntimeEvidence.Validate(); err != nil {
			return fmt.Errorf("invalid runtime evidence churn decision: %w", err)
		}
	}
	if s.UUIDMembershipRefresh != nil {
		if err := s.UUIDMembershipRefresh.Validate(); err != nil {
			return fmt.Errorf("invalid uuid membership refresh result: %w", err)
		}
	}
	if s.UUIDMembershipGrace != nil {
		if err := s.UUIDMembershipGrace.Validate(); err != nil {
			return fmt.Errorf("invalid uuid membership grace result: %w", err)
		}
	}
	if s.authoritativeSourceCount() > 1 {
		return errors.New("control-loop runtime signals require at most one authoritative signal source per cycle")
	}

	return nil
}

func (s ControlLoopRuntimeSignals) authoritativeSourceCount() int {
	count := 0
	if s.RuntimeEvidence != nil {
		count++
	}
	if s.UUIDMembershipRefresh != nil {
		count++
	}
	if s.UUIDMembershipGrace != nil {
		count++
	}

	return count
}

// ControlLoopInput is the narrow daemon-oriented orchestration contract for one
// owner in one cheap-first reconcile cycle.
type ControlLoopInput struct {
	Desired          ManagedStateSet           `json:"desired"`
	Observed         ManagedStateSet           `json:"observed"`
	Snapshot         *Snapshot                 `json:"snapshot,omitempty"`
	NftablesSnapshot *NftablesSnapshot         `json:"nftables_snapshot,omitempty"`
	Restart          bool                      `json:"restart,omitempty"`
	RuntimeSignals   ControlLoopRuntimeSignals `json:"runtime_signals,omitempty"`
}

func (i ControlLoopInput) Validate() error {
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
	if i.Snapshot != nil {
		if err := i.Snapshot.Validate(); err != nil {
			return fmt.Errorf("invalid tc snapshot: %w", err)
		}
	}
	if i.NftablesSnapshot != nil {
		if err := i.NftablesSnapshot.Validate(); err != nil {
			return fmt.Errorf("invalid nftables snapshot: %w", err)
		}
	}
	if err := i.RuntimeSignals.Validate(); err != nil {
		return fmt.Errorf("invalid runtime signals: %w", err)
	}
	ownerKey := controlLoopOwnerKey(i.Desired, i.Observed)
	if i.RuntimeSignals.UUIDMembershipRefresh != nil {
		if err := validateControlLoopUUIDSignalOwner(ownerKey, i.RuntimeSignals.UUIDMembershipRefresh.Subject.Key(), "uuid membership refresh"); err != nil {
			return err
		}
	}
	if i.RuntimeSignals.UUIDMembershipGrace != nil {
		if err := validateControlLoopUUIDSignalOwner(ownerKey, i.RuntimeSignals.UUIDMembershipGrace.Subject.Key(), "uuid membership grace"); err != nil {
			return err
		}
	}

	return nil
}

func validateControlLoopUUIDSignalOwner(ownerKey string, signalOwnerKey string, signalName string) error {
	if strings.TrimSpace(ownerKey) == "" {
		return fmt.Errorf("%s signal requires a requested control-loop owner", strings.TrimSpace(signalName))
	}
	if strings.TrimSpace(signalOwnerKey) != strings.TrimSpace(ownerKey) {
		return fmt.Errorf("%s signal does not match the requested control-loop owner", strings.TrimSpace(signalName))
	}

	return nil
}

// ControlLoopResult captures the integrated control-loop outcome for one owner.
type ControlLoopResult struct {
	Kind              ControlLoopOutcomeKind   `json:"kind"`
	OwnerKey          string                   `json:"owner_key,omitempty"`
	RetainEvidence    ReconcileRetainEvidence  `json:"retain_evidence,omitempty"`
	GraceUntil        *time.Time               `json:"grace_until,omitempty"`
	RestartRecovery   *RestartRecoveryResult   `json:"restart_recovery,omitempty"`
	Reconcile         *PeriodicReconcileResult `json:"reconcile,omitempty"`
	GarbageCollection *GarbageCollectionPlan   `json:"garbage_collection,omitempty"`
	Reason            string                   `json:"reason"`
}

func (r ControlLoopResult) Validate() error {
	if !r.Kind.Valid() {
		return fmt.Errorf("invalid control-loop outcome kind %q", r.Kind)
	}
	if err := r.RetainEvidence.Validate(); err != nil {
		return fmt.Errorf("invalid control-loop retain evidence: %w", err)
	}
	if r.RestartRecovery != nil {
		if err := r.RestartRecovery.Validate(); err != nil {
			return fmt.Errorf("invalid restart recovery result: %w", err)
		}
	}
	if r.Reconcile != nil {
		if err := r.Reconcile.Validate(); err != nil {
			return fmt.Errorf("invalid reconcile result: %w", err)
		}
	}
	if r.GarbageCollection != nil {
		if err := r.GarbageCollection.Validate(); err != nil {
			return fmt.Errorf("invalid garbage-collection plan: %w", err)
		}
	}
	if strings.TrimSpace(r.Reason) == "" {
		return errors.New("control-loop reason is required")
	}

	switch r.Kind {
	case ControlLoopOutcomeRestartRecovery:
		if r.RestartRecovery == nil || r.RestartRecovery.Kind != RestartRecoveryRecoverableObservedState {
			return errors.New("restart_recovery result requires a recoverable restart recovery result")
		}
	case ControlLoopOutcomeApplyDelta, ControlLoopOutcomeBlockedMissingEvidence:
		if r.Reconcile == nil {
			return errors.New("apply_delta and blocked_missing_evidence results require a reconcile result")
		}
	case ControlLoopOutcomeCleanupDelta:
		if r.GarbageCollection == nil || r.GarbageCollection.Kind != GarbageCollectionOutcomeCleanupDelta {
			return errors.New("cleanup_delta result requires a cleanup_delta garbage-collection plan")
		}
	case ControlLoopOutcomeGraceRetained:
		if r.GraceUntil == nil || r.GraceUntil.IsZero() {
			return errors.New("grace_retained result requires a grace deadline")
		}
	}

	return nil
}

// ControlLoopCoordinator integrates the Phase E lifecycle foundations into one
// cheap-first daemon-oriented reconcile step.
type ControlLoopCoordinator struct{}

func (ControlLoopCoordinator) Execute(input ControlLoopInput) (ControlLoopResult, error) {
	if err := input.Validate(); err != nil {
		return ControlLoopResult{}, err
	}

	signalState, err := deriveControlLoopSignalState(input.RuntimeSignals)
	if err != nil {
		return ControlLoopResult{}, err
	}

	result := ControlLoopResult{
		OwnerKey:       controlLoopOwnerKey(input.Desired, input.Observed),
		RetainEvidence: signalState.RetainEvidence,
	}

	if input.Restart {
		return executeRestartControlLoop(input, signalState, result)
	}

	reconcile, err := (PeriodicReconciler{}).Decide(PeriodicReconcileInput{
		Desired:        input.Desired,
		Observed:       input.Observed,
		RetainEvidence: signalState.RetainEvidence,
	})
	if err != nil {
		return ControlLoopResult{}, err
	}
	result.Reconcile = &reconcile
	result.OwnerKey = reconcile.OwnerKey

	switch reconcile.Kind {
	case ReconcileOutcomeNoChange:
		if signalState.GraceRetained {
			result.Kind = ControlLoopOutcomeGraceRetained
			result.GraceUntil = copyTimePtr(signalState.GraceUntil)
			result.Reason = signalState.Reason
			break
		}
		result.Kind = ControlLoopOutcomeNoChange
		result.Reason = reconcile.Reason
	case ReconcileOutcomeApplyDelta:
		result.Kind = ControlLoopOutcomeApplyDelta
		result.Reason = reconcile.Reason
	case ReconcileOutcomeBlockedMissingEvidence:
		switch {
		case signalState.GraceRetained:
			result.Kind = ControlLoopOutcomeGraceRetained
			result.GraceUntil = copyTimePtr(signalState.GraceUntil)
			result.Reason = signalState.Reason
		case signalState.RefreshRequired:
			result.Kind = ControlLoopOutcomeRefreshRequired
			result.Reason = signalState.Reason
		case signalState.Defer:
			result.Kind = ControlLoopOutcomeDefer
			result.Reason = signalState.Reason
		default:
			result.Kind = ControlLoopOutcomeBlockedMissingEvidence
			result.Reason = reconcile.Reason
		}
	case ReconcileOutcomeCleanupStale:
		switch {
		case signalState.GraceRetained:
			result.Kind = ControlLoopOutcomeGraceRetained
			result.GraceUntil = copyTimePtr(signalState.GraceUntil)
			result.Reason = signalState.Reason
		case signalState.RefreshRequired && inventoryRequiresRuntimeEvidence(reconcile.Inventory):
			result.Kind = ControlLoopOutcomeRefreshRequired
			result.Reason = signalState.Reason
		case signalState.Defer && inventoryRequiresRuntimeEvidence(reconcile.Inventory):
			result.Kind = ControlLoopOutcomeDefer
			result.Reason = signalState.Reason
		default:
			gcResult, err := executeControlLoopGarbageCollection(input, reconcile)
			if err != nil {
				return ControlLoopResult{}, err
			}
			result.GarbageCollection = gcResult.GarbageCollection
			result.Kind = gcResult.Kind
			result.Reason = gcResult.Reason
		}
	case ReconcileOutcomeDefer:
		switch {
		case signalState.GraceRetained:
			result.Kind = ControlLoopOutcomeGraceRetained
			result.GraceUntil = copyTimePtr(signalState.GraceUntil)
			result.Reason = signalState.Reason
		case signalState.RefreshRequired:
			result.Kind = ControlLoopOutcomeRefreshRequired
			result.Reason = signalState.Reason
		case signalState.Defer:
			result.Kind = ControlLoopOutcomeDefer
			result.Reason = signalState.Reason
		default:
			result.Kind = ControlLoopOutcomeDefer
			result.Reason = reconcile.Reason
		}
	default:
		return ControlLoopResult{}, fmt.Errorf("unsupported reconcile outcome %q", reconcile.Kind)
	}

	if err := result.Validate(); err != nil {
		return ControlLoopResult{}, err
	}

	return result, nil
}

type controlLoopSignalState struct {
	RetainEvidence  ReconcileRetainEvidence
	RestartEvidence *discovery.RuntimeEvidenceChurnDecision
	GraceRetained   bool
	RefreshRequired bool
	Defer           bool
	GraceUntil      *time.Time
	Reason          string
}

func deriveControlLoopSignalState(signals ControlLoopRuntimeSignals) (controlLoopSignalState, error) {
	switch {
	case signals.UUIDMembershipGrace != nil:
		return controlLoopSignalStateFromUUIDMembershipGrace(*signals.UUIDMembershipGrace), nil
	case signals.UUIDMembershipRefresh != nil:
		return controlLoopSignalStateFromUUIDMembershipRefresh(*signals.UUIDMembershipRefresh)
	case signals.RuntimeEvidence != nil:
		return controlLoopSignalStateFromRuntimeEvidence(*signals.RuntimeEvidence), nil
	default:
		return controlLoopSignalState{}, nil
	}
}

func controlLoopSignalStateFromUUIDMembershipGrace(result correlation.UUIDMembershipGraceResult) controlLoopSignalState {
	restartEvidence := runtimeEvidenceChurnFromUUIDMembershipGrace(result)
	state := controlLoopSignalState{
		RetainEvidence:  reconcileRetainEvidenceFromUUIDMembershipGrace(result),
		RestartEvidence: &restartEvidence,
		Reason:          restartEvidence.Reason,
	}

	switch result.Action {
	case discovery.RuntimeEvidenceChurnActionGraceRetained:
		state.GraceRetained = true
		state.GraceUntil = copyTimePtr(result.GraceUntil)
	case discovery.RuntimeEvidenceChurnActionRefreshRequired:
		state.RefreshRequired = true
	case discovery.RuntimeEvidenceChurnActionDefer:
		state.Defer = true
	}

	return state
}

func controlLoopSignalStateFromUUIDMembershipRefresh(result correlation.UUIDMembershipRefreshResult) (controlLoopSignalState, error) {
	restartEvidence, err := runtimeEvidenceChurnFromUUIDMembershipRefresh(result)
	if err != nil {
		return controlLoopSignalState{}, err
	}

	state := controlLoopSignalState{
		RetainEvidence:  reconcileRetainEvidenceFromUUIDMembershipRefresh(result),
		RestartEvidence: &restartEvidence,
		Reason:          restartEvidence.Reason,
	}
	switch restartEvidence.Action {
	case discovery.RuntimeEvidenceChurnActionRefreshRequired:
		state.RefreshRequired = true
	case discovery.RuntimeEvidenceChurnActionDefer:
		state.Defer = true
	}

	return state, nil
}

func controlLoopSignalStateFromRuntimeEvidence(decision discovery.RuntimeEvidenceChurnDecision) controlLoopSignalState {
	copy := decision
	state := controlLoopSignalState{
		RetainEvidence:  reconcileRetainEvidenceFromRuntimeChurn(decision),
		RestartEvidence: &copy,
		Reason:          copy.Reason,
	}
	switch copy.Action {
	case discovery.RuntimeEvidenceChurnActionGraceRetained:
		state.GraceRetained = true
		state.GraceUntil = copyTimePtr(copy.GraceUntil)
	case discovery.RuntimeEvidenceChurnActionRefreshRequired:
		state.RefreshRequired = true
	case discovery.RuntimeEvidenceChurnActionDefer:
		state.Defer = true
	}

	return state
}

func executeRestartControlLoop(input ControlLoopInput, signals controlLoopSignalState, result ControlLoopResult) (ControlLoopResult, error) {
	inventory, err := ClassifyManagedState(input.Desired, input.Observed)
	if err != nil {
		return ControlLoopResult{}, err
	}
	recovery, err := (RestartRecoverer{}).Decide(RestartRecoveryInput{
		Inventory:       inventory,
		RuntimeEvidence: signals.RestartEvidence,
	})
	if err != nil {
		return ControlLoopResult{}, err
	}
	result.RestartRecovery = &recovery
	result.OwnerKey = recovery.OwnerKey

	switch recovery.Kind {
	case RestartRecoveryRecoverableObservedState:
		result.Kind = ControlLoopOutcomeRestartRecovery
		result.Reason = recovery.Reason
	case RestartRecoveryGraceRetained:
		result.Kind = ControlLoopOutcomeGraceRetained
		result.GraceUntil = copyTimePtr(recovery.GraceUntil)
		result.Reason = recovery.Reason
	case RestartRecoveryRefreshRequired:
		result.Kind = ControlLoopOutcomeRefreshRequired
		result.Reason = recovery.Reason
	case RestartRecoveryCleanupSafe:
		reconcile := PeriodicReconcileResult{
			Kind:              ReconcileOutcomeCleanupStale,
			OwnerKey:          recovery.OwnerKey,
			Inventory:         recovery.Inventory,
			CleanupCandidates: append([]StaleManagedObject(nil), recovery.CleanupCandidates...),
			Reason:            recovery.Reason,
		}
		gcResult, err := executeControlLoopGarbageCollection(input, reconcile)
		if err != nil {
			return ControlLoopResult{}, err
		}
		result.GarbageCollection = gcResult.GarbageCollection
		result.Kind = gcResult.Kind
		result.Reason = gcResult.Reason
	case RestartRecoveryDefer:
		result.Kind = ControlLoopOutcomeDefer
		result.Reason = recovery.Reason
	default:
		return ControlLoopResult{}, fmt.Errorf("unsupported restart recovery outcome %q", recovery.Kind)
	}

	if err := result.Validate(); err != nil {
		return ControlLoopResult{}, err
	}

	return result, nil
}

type controlLoopGCResult struct {
	Kind              ControlLoopOutcomeKind
	GarbageCollection *GarbageCollectionPlan
	Reason            string
}

func executeControlLoopGarbageCollection(input ControlLoopInput, reconcile PeriodicReconcileResult) (controlLoopGCResult, error) {
	snapshot, nftSnapshot, err := controlLoopSnapshots(input)
	if err != nil {
		return controlLoopGCResult{}, err
	}
	gcPlan, err := (GarbageCollector{}).Plan(GarbageCollectionInput{
		Reconcile:        reconcile,
		Snapshot:         snapshot,
		NftablesSnapshot: nftSnapshot,
	})
	if err != nil {
		return controlLoopGCResult{}, err
	}

	switch gcPlan.Kind {
	case GarbageCollectionOutcomeCleanupDelta:
		return controlLoopGCResult{
			Kind:              ControlLoopOutcomeCleanupDelta,
			GarbageCollection: &gcPlan,
			Reason:            gcPlan.Reason,
		}, nil
	case GarbageCollectionOutcomeNoChange:
		return controlLoopGCResult{
			Kind:              ControlLoopOutcomeNoChange,
			GarbageCollection: &gcPlan,
			Reason:            gcPlan.Reason,
		}, nil
	case GarbageCollectionOutcomeDefer:
		return controlLoopGCResult{
			Kind:              ControlLoopOutcomeDefer,
			GarbageCollection: &gcPlan,
			Reason:            gcPlan.Reason,
		}, nil
	default:
		return controlLoopGCResult{}, fmt.Errorf("unsupported garbage-collection outcome %q", gcPlan.Kind)
	}
}

func controlLoopSnapshots(input ControlLoopInput) (Snapshot, NftablesSnapshot, error) {
	if input.Snapshot == nil {
		return Snapshot{}, NftablesSnapshot{}, errors.New("control-loop cleanup requires an observed tc snapshot")
	}
	if err := input.Snapshot.Validate(); err != nil {
		return Snapshot{}, NftablesSnapshot{}, err
	}

	nftSnapshot := NftablesSnapshot{}
	if input.NftablesSnapshot != nil {
		if err := input.NftablesSnapshot.Validate(); err != nil {
			return Snapshot{}, NftablesSnapshot{}, err
		}
		nftSnapshot = *input.NftablesSnapshot
	}

	return *input.Snapshot, nftSnapshot, nil
}

func controlLoopOwnerKey(desired ManagedStateSet, observed ManagedStateSet) string {
	if ownerKey := strings.TrimSpace(desired.OwnerKey); ownerKey != "" {
		return ownerKey
	}

	return strings.TrimSpace(observed.OwnerKey)
}

func reconcileRetainEvidenceFromRuntimeChurn(decision discovery.RuntimeEvidenceChurnDecision) ReconcileRetainEvidence {
	evidence := ReconcileRetainEvidence{Reason: decision.Reason}
	switch decision.Action {
	case discovery.RuntimeEvidenceChurnActionStable:
		evidence.AllowsRetain = true
		evidence.AllowsRecreate = true
	case discovery.RuntimeEvidenceChurnActionGraceRetained:
		evidence.AllowsRetain = true
	case discovery.RuntimeEvidenceChurnActionImmediatelyRemovable,
		discovery.RuntimeEvidenceChurnActionRefreshRequired,
		discovery.RuntimeEvidenceChurnActionDefer:
	}

	return evidence
}

func reconcileRetainEvidenceFromUUIDMembershipRefresh(result correlation.UUIDMembershipRefreshResult) ReconcileRetainEvidence {
	evidence := ReconcileRetainEvidence{Reason: result.Reason}
	if result.Freshness != discovery.RuntimeEvidenceFreshnessFresh || result.Membership == nil || result.Membership.MemberCount() == 0 {
		return evidence
	}

	switch result.Action {
	case correlation.UUIDMembershipRefreshReuseCached, correlation.UUIDMembershipRefreshRefreshed:
		evidence.AllowsRetain = true
		evidence.AllowsRecreate = true
	}

	return evidence
}

func reconcileRetainEvidenceFromUUIDMembershipGrace(result correlation.UUIDMembershipGraceResult) ReconcileRetainEvidence {
	evidence := ReconcileRetainEvidence{Reason: result.Reason}
	if result.EffectiveMembership == nil || result.EffectiveMembership.MemberCount() == 0 {
		return evidence
	}

	switch result.Action {
	case discovery.RuntimeEvidenceChurnActionStable:
		evidence.AllowsRetain = true
		evidence.AllowsRecreate = true
	case discovery.RuntimeEvidenceChurnActionGraceRetained:
		evidence.AllowsRetain = true
	}

	return evidence
}

func runtimeEvidenceChurnFromUUIDMembershipGrace(result correlation.UUIDMembershipGraceResult) discovery.RuntimeEvidenceChurnDecision {
	return discovery.RuntimeEvidenceChurnDecision{
		Action:     result.Action,
		GraceUntil: copyTimePtr(result.GraceUntil),
		Reason:     result.Reason,
	}
}

func runtimeEvidenceChurnFromUUIDMembershipRefresh(result correlation.UUIDMembershipRefreshResult) (discovery.RuntimeEvidenceChurnDecision, error) {
	decision := discovery.RuntimeEvidenceChurnDecision{
		Reason: result.Reason,
	}

	switch result.Action {
	case correlation.UUIDMembershipRefreshReuseCached, correlation.UUIDMembershipRefreshRefreshed:
		if result.Freshness == discovery.RuntimeEvidenceFreshnessFresh && result.Membership != nil && result.Membership.MemberCount() > 0 {
			decision.Action = discovery.RuntimeEvidenceChurnActionStable
			decision.Reason = "fresh uuid membership refresh still proves live members are present; runtime-derived ownership can be retained cheaply"
			break
		}
		decision.Action = discovery.RuntimeEvidenceChurnActionRefreshRequired
		decision.Reason = "uuid membership refresh did not retain fresh live members strongly enough to skip a follow-up refresh or grace evaluation"
	case correlation.UUIDMembershipRefreshRefreshRequired:
		decision.Action = discovery.RuntimeEvidenceChurnActionRefreshRequired
	case correlation.UUIDMembershipRefreshEvidencePartial, correlation.UUIDMembershipRefreshEvidenceUnavailable:
		decision.Action = discovery.RuntimeEvidenceChurnActionDefer
	default:
		return discovery.RuntimeEvidenceChurnDecision{}, fmt.Errorf("unsupported uuid membership refresh action %q", result.Action)
	}

	if err := decision.Validate(); err != nil {
		return discovery.RuntimeEvidenceChurnDecision{}, err
	}

	return decision, nil
}

func copyTimePtr(value *time.Time) *time.Time {
	if value == nil {
		return nil
	}
	copy := *value
	return &copy
}
