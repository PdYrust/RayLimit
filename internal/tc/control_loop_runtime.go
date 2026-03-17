package tc

import (
	"errors"
	"fmt"
	"hash/fnv"
	"sort"
	"strconv"
	"strings"
	"time"
)

// ControlLoopOperationalMode is a restrained operator-facing summary of what
// the integrated control loop intends to do next for one owner.
type ControlLoopOperationalMode string

const (
	ControlLoopOperationalModeSteadyWatch    ControlLoopOperationalMode = "steady_watch"
	ControlLoopOperationalModeVerifyMutation ControlLoopOperationalMode = "verify_mutation"
	ControlLoopOperationalModeRefreshBackoff ControlLoopOperationalMode = "refresh_backoff"
	ControlLoopOperationalModeGraceProbe     ControlLoopOperationalMode = "grace_probe"
	ControlLoopOperationalModeDeferBackoff   ControlLoopOperationalMode = "defer_backoff"
)

func (m ControlLoopOperationalMode) Valid() bool {
	switch m {
	case ControlLoopOperationalModeSteadyWatch,
		ControlLoopOperationalModeVerifyMutation,
		ControlLoopOperationalModeRefreshBackoff,
		ControlLoopOperationalModeGraceProbe,
		ControlLoopOperationalModeDeferBackoff:
		return true
	default:
		return false
	}
}

// ControlLoopOperationalPolicy hardens the integrated control loop with bounded
// work, low-churn cadence, and deterministic jitter hooks.
type ControlLoopOperationalPolicy struct {
	MaxOwnersPerTick       int           `json:"max_owners_per_tick,omitempty"`
	SteadyInterval         time.Duration `json:"steady_interval,omitempty"`
	MutationVerifyInterval time.Duration `json:"mutation_verify_interval,omitempty"`
	RefreshBackoffBase     time.Duration `json:"refresh_backoff_base,omitempty"`
	RefreshBackoffMax      time.Duration `json:"refresh_backoff_max,omitempty"`
	DeferBackoffBase       time.Duration `json:"defer_backoff_base,omitempty"`
	DeferBackoffMax        time.Duration `json:"defer_backoff_max,omitempty"`
	GraceProbeInterval     time.Duration `json:"grace_probe_interval,omitempty"`
	JitterRatio            float64       `json:"jitter_ratio,omitempty"`
}

func (p ControlLoopOperationalPolicy) Validate() error {
	switch {
	case p.MaxOwnersPerTick <= 0:
		return errors.New("control-loop max owners per tick must be greater than zero")
	case p.SteadyInterval <= 0:
		return errors.New("control-loop steady interval must be greater than zero")
	case p.MutationVerifyInterval <= 0:
		return errors.New("control-loop mutation verify interval must be greater than zero")
	case p.RefreshBackoffBase <= 0:
		return errors.New("control-loop refresh backoff base must be greater than zero")
	case p.RefreshBackoffMax < p.RefreshBackoffBase:
		return errors.New("control-loop refresh backoff max must be greater than or equal to the base interval")
	case p.DeferBackoffBase <= 0:
		return errors.New("control-loop defer backoff base must be greater than zero")
	case p.DeferBackoffMax < p.DeferBackoffBase:
		return errors.New("control-loop defer backoff max must be greater than or equal to the base interval")
	case p.GraceProbeInterval <= 0:
		return errors.New("control-loop grace probe interval must be greater than zero")
	case p.JitterRatio < 0 || p.JitterRatio > 1:
		return errors.New("control-loop jitter ratio must stay within the inclusive range [0,1]")
	default:
		return nil
	}
}

// ControlLoopOwnerState captures the minimum persisted per-owner state later
// daemon phases can carry between integrated control-loop cycles. The streak
// tracks repeated equivalent operational outcomes so refresh and defer pressure
// stays stable even when nearby result kinds alternate.
type ControlLoopOwnerState struct {
	OwnerKey                string                 `json:"owner_key"`
	LastOutcome             ControlLoopOutcomeKind `json:"last_outcome,omitempty"`
	ConsecutiveOutcomeCount int                    `json:"consecutive_outcome_count,omitempty"`
	LastRunAt               time.Time              `json:"last_run_at,omitempty"`
	NextRunAt               time.Time              `json:"next_run_at,omitempty"`
	GraceUntil              *time.Time             `json:"grace_until,omitempty"`
	LastReason              string                 `json:"last_reason,omitempty"`
}

func (s ControlLoopOwnerState) Validate() error {
	if strings.TrimSpace(s.OwnerKey) == "" {
		return errors.New("control-loop owner state requires an owner key")
	}
	if strings.TrimSpace(string(s.LastOutcome)) != "" {
		if !s.LastOutcome.Valid() {
			return fmt.Errorf("invalid last control-loop outcome %q", s.LastOutcome)
		}
		if s.ConsecutiveOutcomeCount <= 0 {
			return errors.New("control-loop owner state requires a positive consecutive outcome count when a last outcome is present")
		}
	} else if s.ConsecutiveOutcomeCount != 0 {
		return errors.New("control-loop owner state cannot track a consecutive outcome count without a last outcome")
	}
	if s.LastRunAt.IsZero() != s.NextRunAt.IsZero() && s.LastOutcome != "" {
		return errors.New("control-loop owner state must either set both last and next run times or neither when a last outcome is present")
	}
	if !s.LastRunAt.IsZero() && s.NextRunAt.Before(s.LastRunAt) {
		return errors.New("control-loop owner state next run time cannot be before the last run time")
	}
	if s.LastOutcome == ControlLoopOutcomeGraceRetained {
		if s.GraceUntil == nil || s.GraceUntil.IsZero() {
			return errors.New("grace-retained control-loop owner state requires a grace deadline")
		}
	}
	if s.LastOutcome != ControlLoopOutcomeGraceRetained && s.GraceUntil != nil {
		return errors.New("only grace-retained control-loop owner state may include a grace deadline")
	}

	return nil
}

// ControlLoopOperationalSummary is the restrained operator-useful summary that
// later daemon or logging phases can surface without re-parsing raw outcomes.
type ControlLoopOperationalSummary struct {
	OwnerKey                string                     `json:"owner_key"`
	Outcome                 ControlLoopOutcomeKind     `json:"outcome"`
	Mode                    ControlLoopOperationalMode `json:"mode"`
	ConsecutiveOutcomeCount int                        `json:"consecutive_outcome_count"`
	NextRunAt               time.Time                  `json:"next_run_at"`
	Mutating                bool                       `json:"mutating,omitempty"`
	RefreshNeeded           bool                       `json:"refresh_needed,omitempty"`
	Reason                  string                     `json:"reason"`
}

func (s ControlLoopOperationalSummary) Validate() error {
	if strings.TrimSpace(s.OwnerKey) == "" {
		return errors.New("control-loop summary requires an owner key")
	}
	if !s.Outcome.Valid() {
		return fmt.Errorf("invalid control-loop summary outcome %q", s.Outcome)
	}
	if !s.Mode.Valid() {
		return fmt.Errorf("invalid control-loop summary mode %q", s.Mode)
	}
	if s.ConsecutiveOutcomeCount <= 0 {
		return errors.New("control-loop summary requires a positive consecutive outcome count")
	}
	if s.NextRunAt.IsZero() {
		return errors.New("control-loop summary requires a next run time")
	}
	if strings.TrimSpace(s.Reason) == "" {
		return errors.New("control-loop summary reason is required")
	}

	return nil
}

// ControlLoopProcessInput wraps one integrated control-loop execution with the
// operational state and policy needed for bounded low-churn behavior.
type ControlLoopProcessInput struct {
	State  *ControlLoopOwnerState       `json:"state,omitempty"`
	Loop   ControlLoopInput             `json:"loop"`
	Policy ControlLoopOperationalPolicy `json:"policy"`
	Now    time.Time                    `json:"now"`
}

func (i ControlLoopProcessInput) Validate() error {
	if i.State != nil {
		if err := i.State.Validate(); err != nil {
			return fmt.Errorf("invalid prior control-loop owner state: %w", err)
		}
	}
	if err := i.Loop.Validate(); err != nil {
		return fmt.Errorf("invalid control-loop input: %w", err)
	}
	if err := i.Policy.Validate(); err != nil {
		return fmt.Errorf("invalid control-loop operational policy: %w", err)
	}
	if i.Now.IsZero() {
		return errors.New("control-loop operational processing requires a reference time")
	}

	ownerKey := controlLoopOwnerKey(i.Loop.Desired, i.Loop.Observed)
	if i.State != nil && strings.TrimSpace(ownerKey) != "" && strings.TrimSpace(i.State.OwnerKey) != strings.TrimSpace(ownerKey) {
		return errors.New("prior control-loop owner state does not match the requested owner")
	}

	return nil
}

// ControlLoopProcessResult captures the integrated outcome plus the next
// bounded-work state and summary.
type ControlLoopProcessResult struct {
	Loop    ControlLoopResult             `json:"loop"`
	State   ControlLoopOwnerState         `json:"state"`
	Summary ControlLoopOperationalSummary `json:"summary"`
}

func (r ControlLoopProcessResult) Validate() error {
	if err := r.Loop.Validate(); err != nil {
		return fmt.Errorf("invalid integrated control-loop result: %w", err)
	}
	if err := r.State.Validate(); err != nil {
		return fmt.Errorf("invalid next control-loop owner state: %w", err)
	}
	if err := r.Summary.Validate(); err != nil {
		return fmt.Errorf("invalid control-loop summary: %w", err)
	}
	if strings.TrimSpace(r.State.OwnerKey) != strings.TrimSpace(r.Loop.OwnerKey) ||
		strings.TrimSpace(r.Summary.OwnerKey) != strings.TrimSpace(r.Loop.OwnerKey) {
		return errors.New("control-loop process result owner keys must remain aligned")
	}

	return nil
}

// ControlLoopSelectionInput describes the bounded-work owner-selection surface
// for one loop tick.
type ControlLoopSelectionInput struct {
	States []ControlLoopOwnerState      `json:"states"`
	Policy ControlLoopOperationalPolicy `json:"policy"`
	Now    time.Time                    `json:"now"`
}

func (i ControlLoopSelectionInput) Validate() error {
	if err := i.Policy.Validate(); err != nil {
		return fmt.Errorf("invalid control-loop operational policy: %w", err)
	}
	if i.Now.IsZero() {
		return errors.New("control-loop owner selection requires a reference time")
	}
	seen := make(map[string]struct{}, len(i.States))
	for index, state := range i.States {
		if err := state.Validate(); err != nil {
			return fmt.Errorf("invalid control-loop owner state at index %d: %w", index, err)
		}
		key := strings.TrimSpace(state.OwnerKey)
		if _, ok := seen[key]; ok {
			return fmt.Errorf("duplicate control-loop owner state %q", key)
		}
		seen[key] = struct{}{}
	}

	return nil
}

// ControlLoopSelectionResult captures the bounded set of owners that should run
// now plus any due owners deferred by the current work budget.
type ControlLoopSelectionResult struct {
	Scheduled []ControlLoopOwnerState `json:"scheduled,omitempty"`
	Deferred  []ControlLoopOwnerState `json:"deferred,omitempty"`
	Reason    string                  `json:"reason"`
}

func (r ControlLoopSelectionResult) Validate() error {
	for index, state := range r.Scheduled {
		if err := state.Validate(); err != nil {
			return fmt.Errorf("invalid scheduled control-loop owner state at index %d: %w", index, err)
		}
	}
	for index, state := range r.Deferred {
		if err := state.Validate(); err != nil {
			return fmt.Errorf("invalid deferred control-loop owner state at index %d: %w", index, err)
		}
	}
	if strings.TrimSpace(r.Reason) == "" {
		return errors.New("control-loop selection reason is required")
	}

	return nil
}

// UpsertControlLoopOwnerState applies one validated per-owner state update into
// the current owner set without allowing duplicates or order drift.
func UpsertControlLoopOwnerState(states []ControlLoopOwnerState, state ControlLoopOwnerState) ([]ControlLoopOwnerState, error) {
	if err := state.Validate(); err != nil {
		return nil, fmt.Errorf("invalid control-loop owner state update: %w", err)
	}

	normalized, err := normalizeControlLoopOwnerStates(states)
	if err != nil {
		return nil, err
	}

	updated := append([]ControlLoopOwnerState(nil), normalized...)
	ownerKey := strings.TrimSpace(state.OwnerKey)
	for index := range updated {
		if strings.TrimSpace(updated[index].OwnerKey) != ownerKey {
			continue
		}
		updated[index] = state
		sortControlLoopOwnerStates(updated)
		return updated, nil
	}

	updated = append(updated, state)
	sortControlLoopOwnerStates(updated)
	return updated, nil
}

// RetainControlLoopOwnerStates drops owner state entries whose owners are no
// longer part of the current retained control-loop owner set.
func RetainControlLoopOwnerStates(states []ControlLoopOwnerState, ownerKeys []string) ([]ControlLoopOwnerState, error) {
	normalized, err := normalizeControlLoopOwnerStates(states)
	if err != nil {
		return nil, err
	}

	retain := make(map[string]struct{}, len(ownerKeys))
	for _, ownerKey := range ownerKeys {
		if normalizedKey := strings.TrimSpace(ownerKey); normalizedKey != "" {
			retain[normalizedKey] = struct{}{}
		}
	}
	if len(retain) == 0 {
		return nil, nil
	}

	filtered := make([]ControlLoopOwnerState, 0, len(normalized))
	for _, state := range normalized {
		if _, ok := retain[strings.TrimSpace(state.OwnerKey)]; !ok {
			continue
		}
		filtered = append(filtered, state)
	}

	sortControlLoopOwnerStates(filtered)
	return filtered, nil
}

// ControlLoopOperator wraps the coordinator with bounded-work cadence and
// low-churn operational state updates.
type ControlLoopOperator struct{}

func (ControlLoopOperator) Process(input ControlLoopProcessInput) (ControlLoopProcessResult, error) {
	if err := input.Validate(); err != nil {
		return ControlLoopProcessResult{}, err
	}

	loopResult, err := (ControlLoopCoordinator{}).Execute(input.Loop)
	if err != nil {
		return ControlLoopProcessResult{}, err
	}

	nextState, summary, err := advanceControlLoopOwnerState(input.State, loopResult, input.Policy, input.Now)
	if err != nil {
		return ControlLoopProcessResult{}, err
	}

	result := ControlLoopProcessResult{
		Loop:    loopResult,
		State:   nextState,
		Summary: summary,
	}
	if err := result.Validate(); err != nil {
		return ControlLoopProcessResult{}, err
	}

	return result, nil
}

func (ControlLoopOperator) SelectDueOwners(input ControlLoopSelectionInput) (ControlLoopSelectionResult, error) {
	if err := input.Validate(); err != nil {
		return ControlLoopSelectionResult{}, err
	}

	due := make([]ControlLoopOwnerState, 0, len(input.States))
	for _, state := range input.States {
		if state.NextRunAt.IsZero() || !state.NextRunAt.After(input.Now) {
			due = append(due, state)
		}
	}

	sort.Slice(due, func(i, j int) bool {
		left := due[i].NextRunAt
		right := due[j].NextRunAt
		if left.Equal(right) {
			return strings.TrimSpace(due[i].OwnerKey) < strings.TrimSpace(due[j].OwnerKey)
		}
		if left.IsZero() {
			return true
		}
		if right.IsZero() {
			return false
		}
		return left.Before(right)
	})

	result := ControlLoopSelectionResult{}
	if len(due) <= input.Policy.MaxOwnersPerTick {
		result.Scheduled = due
		result.Reason = "due control-loop owners fit within the current per-tick work budget"
	} else {
		result.Scheduled = append([]ControlLoopOwnerState(nil), due[:input.Policy.MaxOwnersPerTick]...)
		result.Deferred = append([]ControlLoopOwnerState(nil), due[input.Policy.MaxOwnersPerTick:]...)
		result.Reason = "due control-loop owners exceeded the current per-tick work budget and were deterministically deferred without mutation"
	}

	if err := result.Validate(); err != nil {
		return ControlLoopSelectionResult{}, err
	}

	return result, nil
}

func advanceControlLoopOwnerState(
	previous *ControlLoopOwnerState,
	result ControlLoopResult,
	policy ControlLoopOperationalPolicy,
	now time.Time,
) (ControlLoopOwnerState, ControlLoopOperationalSummary, error) {
	if err := result.Validate(); err != nil {
		return ControlLoopOwnerState{}, ControlLoopOperationalSummary{}, err
	}
	if err := policy.Validate(); err != nil {
		return ControlLoopOwnerState{}, ControlLoopOperationalSummary{}, err
	}
	if now.IsZero() {
		return ControlLoopOwnerState{}, ControlLoopOperationalSummary{}, errors.New("control-loop state advancement requires a reference time")
	}

	streak := 1
	if previous != nil && controlLoopOutcomeMode(previous.LastOutcome) == controlLoopOutcomeMode(result.Kind) {
		streak = previous.ConsecutiveOutcomeCount + 1
	}
	streak = capControlLoopOutcomeStreak(result.Kind, policy, streak)

	mode, delay, refreshNeeded := nextControlLoopCadence(result, policy, streak, now)
	delay = addDeterministicJitter(delay, result.OwnerKey, result.Kind, streak, policy.JitterRatio)
	if result.Kind == ControlLoopOutcomeGraceRetained && result.GraceUntil != nil {
		remaining := result.GraceUntil.Sub(now)
		switch {
		case remaining <= 0:
			delay = 0
		case delay > remaining:
			delay = remaining
		}
	}

	nextState := ControlLoopOwnerState{
		OwnerKey:                result.OwnerKey,
		LastOutcome:             result.Kind,
		ConsecutiveOutcomeCount: streak,
		LastRunAt:               now,
		NextRunAt:               now.Add(delay),
		LastReason:              result.Reason,
	}
	if result.Kind == ControlLoopOutcomeGraceRetained {
		nextState.GraceUntil = copyTimePtr(result.GraceUntil)
	}

	summary := ControlLoopOperationalSummary{
		OwnerKey:                result.OwnerKey,
		Outcome:                 result.Kind,
		Mode:                    mode,
		ConsecutiveOutcomeCount: streak,
		NextRunAt:               nextState.NextRunAt,
		Mutating:                result.Kind == ControlLoopOutcomeApplyDelta || result.Kind == ControlLoopOutcomeCleanupDelta,
		RefreshNeeded:           refreshNeeded,
		Reason:                  result.Reason,
	}

	if err := nextState.Validate(); err != nil {
		return ControlLoopOwnerState{}, ControlLoopOperationalSummary{}, err
	}
	if err := summary.Validate(); err != nil {
		return ControlLoopOwnerState{}, ControlLoopOperationalSummary{}, err
	}

	return nextState, summary, nil
}

func nextControlLoopCadence(
	result ControlLoopResult,
	policy ControlLoopOperationalPolicy,
	streak int,
	now time.Time,
) (ControlLoopOperationalMode, time.Duration, bool) {
	switch controlLoopOutcomeMode(result.Kind) {
	case ControlLoopOperationalModeSteadyWatch:
		return ControlLoopOperationalModeSteadyWatch, policy.SteadyInterval, false
	case ControlLoopOperationalModeVerifyMutation:
		return ControlLoopOperationalModeVerifyMutation, policy.MutationVerifyInterval, false
	case ControlLoopOperationalModeRefreshBackoff:
		return ControlLoopOperationalModeRefreshBackoff, boundedBackoff(policy.RefreshBackoffBase, policy.RefreshBackoffMax, streak), true
	case ControlLoopOperationalModeGraceProbe:
		if result.GraceUntil != nil && result.GraceUntil.Before(now) {
			return ControlLoopOperationalModeGraceProbe, 0, false
		}
		return ControlLoopOperationalModeGraceProbe, policy.GraceProbeInterval, false
	case ControlLoopOperationalModeDeferBackoff:
		return ControlLoopOperationalModeDeferBackoff, boundedBackoff(policy.DeferBackoffBase, policy.DeferBackoffMax, streak), false
	default:
		return ControlLoopOperationalModeDeferBackoff, policy.DeferBackoffBase, false
	}
}

func controlLoopOutcomeMode(outcome ControlLoopOutcomeKind) ControlLoopOperationalMode {
	switch outcome {
	case ControlLoopOutcomeNoChange, ControlLoopOutcomeRestartRecovery:
		return ControlLoopOperationalModeSteadyWatch
	case ControlLoopOutcomeApplyDelta, ControlLoopOutcomeCleanupDelta:
		return ControlLoopOperationalModeVerifyMutation
	case ControlLoopOutcomeRefreshRequired, ControlLoopOutcomeBlockedMissingEvidence:
		return ControlLoopOperationalModeRefreshBackoff
	case ControlLoopOutcomeGraceRetained:
		return ControlLoopOperationalModeGraceProbe
	case ControlLoopOutcomeDefer:
		return ControlLoopOperationalModeDeferBackoff
	default:
		return ControlLoopOperationalModeDeferBackoff
	}
}

func capControlLoopOutcomeStreak(
	outcome ControlLoopOutcomeKind,
	policy ControlLoopOperationalPolicy,
	streak int,
) int {
	if streak <= 1 {
		return 1
	}

	switch controlLoopOutcomeMode(outcome) {
	case ControlLoopOperationalModeSteadyWatch,
		ControlLoopOperationalModeVerifyMutation,
		ControlLoopOperationalModeGraceProbe:
		return 1
	case ControlLoopOperationalModeRefreshBackoff:
		return minInt(streak, backoffSaturationStreak(policy.RefreshBackoffBase, policy.RefreshBackoffMax))
	case ControlLoopOperationalModeDeferBackoff:
		return minInt(streak, backoffSaturationStreak(policy.DeferBackoffBase, policy.DeferBackoffMax))
	default:
		return streak
	}
}

func backoffSaturationStreak(base, max time.Duration) int {
	if base <= 0 || max <= 0 || max <= base {
		return 1
	}

	streak := 1
	delay := base
	for delay < max {
		streak++
		if delay > max/2 {
			return streak
		}
		delay *= 2
	}

	return streak
}

func normalizeControlLoopOwnerStates(states []ControlLoopOwnerState) ([]ControlLoopOwnerState, error) {
	if len(states) == 0 {
		return nil, nil
	}

	normalized := make([]ControlLoopOwnerState, 0, len(states))
	seen := make(map[string]struct{}, len(states))
	for index, state := range states {
		if err := state.Validate(); err != nil {
			return nil, fmt.Errorf("invalid control-loop owner state at index %d: %w", index, err)
		}
		key := strings.TrimSpace(state.OwnerKey)
		if _, ok := seen[key]; ok {
			return nil, fmt.Errorf("duplicate control-loop owner state %q", key)
		}
		seen[key] = struct{}{}
		normalized = append(normalized, state)
	}

	sortControlLoopOwnerStates(normalized)
	return normalized, nil
}

func sortControlLoopOwnerStates(states []ControlLoopOwnerState) {
	sort.Slice(states, func(i, j int) bool {
		return strings.TrimSpace(states[i].OwnerKey) < strings.TrimSpace(states[j].OwnerKey)
	})
}

func minInt(left, right int) int {
	if left < right {
		return left
	}
	return right
}

func boundedBackoff(base, max time.Duration, streak int) time.Duration {
	if streak <= 1 {
		return base
	}

	delay := base
	for remaining := streak - 1; remaining > 0; remaining-- {
		if delay >= max {
			return max
		}
		if delay > max/2 {
			return max
		}
		delay *= 2
	}

	if delay > max {
		return max
	}
	return delay
}

func addDeterministicJitter(
	base time.Duration,
	ownerKey string,
	outcome ControlLoopOutcomeKind,
	streak int,
	ratio float64,
) time.Duration {
	if base <= 0 || ratio <= 0 {
		return base
	}

	spread := time.Duration(float64(base) * ratio)
	if spread <= 0 {
		return base
	}

	hasher := fnv.New32a()
	_, _ = hasher.Write([]byte(strings.TrimSpace(ownerKey)))
	_, _ = hasher.Write([]byte{0})
	_, _ = hasher.Write([]byte(strings.TrimSpace(string(outcome))))
	_, _ = hasher.Write([]byte{0})
	_, _ = hasher.Write([]byte(strconv.Itoa(streak)))
	hash := hasher.Sum32()

	extra := time.Duration((uint64(spread) * uint64(hash)) / uint64(^uint32(0)))
	return base + extra
}
