package discovery

import (
	"errors"
	"fmt"
	"strings"
	"time"
)

// RuntimeEvidenceChurnAction describes how later control-plane phases should
// treat runtime-derived state under reconnect-heavy conditions.
type RuntimeEvidenceChurnAction string

const (
	RuntimeEvidenceChurnActionStable               RuntimeEvidenceChurnAction = "stable"
	RuntimeEvidenceChurnActionImmediatelyRemovable RuntimeEvidenceChurnAction = "immediately_removable"
	RuntimeEvidenceChurnActionGraceRetained        RuntimeEvidenceChurnAction = "grace_retained"
	RuntimeEvidenceChurnActionRefreshRequired      RuntimeEvidenceChurnAction = "refresh_required"
	RuntimeEvidenceChurnActionDefer                RuntimeEvidenceChurnAction = "defer"
)

func (a RuntimeEvidenceChurnAction) Valid() bool {
	switch a {
	case RuntimeEvidenceChurnActionStable,
		RuntimeEvidenceChurnActionImmediatelyRemovable,
		RuntimeEvidenceChurnActionGraceRetained,
		RuntimeEvidenceChurnActionRefreshRequired,
		RuntimeEvidenceChurnActionDefer:
		return true
	default:
		return false
	}
}

// RuntimeEvidenceChurnPolicy controls how long recently trusted runtime-derived
// state may survive a confirmed but brief disconnect before cleanup should win.
type RuntimeEvidenceChurnPolicy struct {
	DisconnectGraceTTL time.Duration `json:"disconnect_grace_ttl,omitempty"`
}

func (p RuntimeEvidenceChurnPolicy) Validate() error {
	if p.DisconnectGraceTTL <= 0 {
		return errors.New("runtime evidence disconnect grace ttl must be greater than zero")
	}

	return nil
}

// RuntimeEvidenceChurnInput captures the minimum cheap-first decision surface
// for anti-flap handling of one runtime-derived owner.
type RuntimeEvidenceChurnInput struct {
	Assessment          RuntimeEvidenceAssessment  `json:"assessment"`
	ConfirmedAbsent     bool                       `json:"confirmed_absent,omitempty"`
	HadTrustedPresence  bool                       `json:"had_trusted_presence,omitempty"`
	LastTrustedPresence time.Time                  `json:"last_trusted_presence,omitempty"`
	Policy              RuntimeEvidenceChurnPolicy `json:"policy"`
	Now                 time.Time                  `json:"now"`
}

func (i RuntimeEvidenceChurnInput) Validate() error {
	if err := i.Assessment.Validate(); err != nil {
		return fmt.Errorf("invalid runtime evidence assessment: %w", err)
	}
	if err := i.Policy.Validate(); err != nil {
		return fmt.Errorf("invalid churn policy: %w", err)
	}
	if i.Now.IsZero() {
		return errors.New("runtime evidence churn evaluation requires a reference time")
	}
	if i.HadTrustedPresence {
		if i.LastTrustedPresence.IsZero() {
			return errors.New("last trusted presence time is required when trusted presence was observed")
		}
		if i.LastTrustedPresence.After(i.Now) {
			return errors.New("last trusted presence time cannot be in the future")
		}
	}

	return nil
}

// RuntimeEvidenceChurnDecision captures whether runtime-derived state is stable,
// removable now, grace-retained, refresh-required, or deferred.
type RuntimeEvidenceChurnDecision struct {
	Action     RuntimeEvidenceChurnAction `json:"action"`
	GraceUntil *time.Time                 `json:"grace_until,omitempty"`
	Reason     string                     `json:"reason"`
}

func (d RuntimeEvidenceChurnDecision) Validate() error {
	if !d.Action.Valid() {
		return fmt.Errorf("invalid runtime evidence churn action %q", d.Action)
	}
	if strings.TrimSpace(d.Reason) == "" {
		return errors.New("runtime evidence churn reason is required")
	}
	switch d.Action {
	case RuntimeEvidenceChurnActionGraceRetained:
		if d.GraceUntil == nil || d.GraceUntil.IsZero() {
			return errors.New("grace-retained runtime evidence requires a grace deadline")
		}
	default:
		if d.GraceUntil != nil {
			return errors.New("only grace-retained runtime evidence may include a grace deadline")
		}
	}

	return nil
}

// DecideRuntimeEvidenceChurn applies a narrow grace/debounce contract to one
// runtime-derived owner without building the full reconcile loop yet.
func DecideRuntimeEvidenceChurn(input RuntimeEvidenceChurnInput) (RuntimeEvidenceChurnDecision, error) {
	if err := input.Validate(); err != nil {
		return RuntimeEvidenceChurnDecision{}, err
	}

	decision := RuntimeEvidenceChurnDecision{}

	switch input.Assessment.Freshness {
	case RuntimeEvidenceFreshnessFresh:
		if !input.ConfirmedAbsent {
			decision.Action = RuntimeEvidenceChurnActionStable
			decision.Reason = "fresh trusted runtime evidence does not confirm owner absence; no anti-flap retention is needed"
			break
		}

		if input.HadTrustedPresence {
			graceUntil := input.LastTrustedPresence.Add(input.Policy.DisconnectGraceTTL)
			if !graceUntil.Before(input.Now) {
				decision.Action = RuntimeEvidenceChurnActionGraceRetained
				decision.GraceUntil = &graceUntil
				decision.Reason = "fresh trusted runtime evidence currently shows absence, but recent trusted presence remains within the disconnect grace period"
				break
			}
		}

		decision.Action = RuntimeEvidenceChurnActionImmediatelyRemovable
		decision.Reason = "fresh trusted runtime evidence confirms absence and no recent trusted presence remains within grace"
	case RuntimeEvidenceFreshnessStale:
		decision.Action = RuntimeEvidenceChurnActionRefreshRequired
		decision.Reason = "runtime evidence is stale, so churn handling still requires a fresher refresh before cleanup or repair"
	case RuntimeEvidenceFreshnessPartial:
		decision.Action = RuntimeEvidenceChurnActionDefer
		decision.Reason = "runtime evidence is only partially trustworthy, so anti-flap handling defers mutation"
	case RuntimeEvidenceFreshnessUnavailable:
		decision.Action = RuntimeEvidenceChurnActionDefer
		decision.Reason = "runtime evidence is unavailable, so anti-flap handling defers mutation"
	default:
		return RuntimeEvidenceChurnDecision{}, fmt.Errorf("unsupported runtime evidence freshness %q", input.Assessment.Freshness)
	}

	if err := decision.Validate(); err != nil {
		return RuntimeEvidenceChurnDecision{}, err
	}

	return decision, nil
}
