package discovery

import (
	"errors"
	"fmt"
	"strings"
	"time"
)

// RuntimeEvidenceFreshness classifies whether live runtime evidence is still
// current enough to drive control-plane decisions.
type RuntimeEvidenceFreshness string

const (
	RuntimeEvidenceFreshnessFresh       RuntimeEvidenceFreshness = "fresh"
	RuntimeEvidenceFreshnessStale       RuntimeEvidenceFreshness = "stale"
	RuntimeEvidenceFreshnessUnavailable RuntimeEvidenceFreshness = "unavailable"
	RuntimeEvidenceFreshnessPartial     RuntimeEvidenceFreshness = "partial"
)

func (f RuntimeEvidenceFreshness) Valid() bool {
	switch f {
	case RuntimeEvidenceFreshnessFresh,
		RuntimeEvidenceFreshnessStale,
		RuntimeEvidenceFreshnessUnavailable,
		RuntimeEvidenceFreshnessPartial:
		return true
	default:
		return false
	}
}

// RuntimeEvidencePolicy controls how long previously observed live evidence can
// be reused before the control plane should request a refresh.
type RuntimeEvidencePolicy struct {
	FreshTTL time.Duration `json:"fresh_ttl,omitempty"`
}

func (p RuntimeEvidencePolicy) Validate() error {
	if p.FreshTTL <= 0 {
		return errors.New("runtime evidence fresh ttl must be greater than zero")
	}

	return nil
}

// RuntimeEvidenceSnapshot captures one observed live-evidence result together
// with the timestamp when it was collected.
type RuntimeEvidenceSnapshot struct {
	Result     SessionEvidenceResult `json:"result"`
	ObservedAt time.Time             `json:"observed_at"`
}

func (s RuntimeEvidenceSnapshot) Validate() error {
	if err := s.Result.Validate(); err != nil {
		return fmt.Errorf("invalid runtime evidence result: %w", err)
	}
	if s.ObservedAt.IsZero() {
		return errors.New("runtime evidence observation time is required")
	}

	return nil
}

// RuntimeEvidenceAssessment captures the cheap-first decision surface later
// reconcile phases can use without guessing about freshness.
type RuntimeEvidenceAssessment struct {
	Freshness     RuntimeEvidenceFreshness `json:"freshness"`
	Age           time.Duration            `json:"age,omitempty"`
	Trusted       bool                     `json:"trusted,omitempty"`
	RefreshNeeded bool                     `json:"refresh_needed,omitempty"`
	Reason        string                   `json:"reason"`
}

func (a RuntimeEvidenceAssessment) Validate() error {
	if !a.Freshness.Valid() {
		return fmt.Errorf("invalid runtime evidence freshness %q", a.Freshness)
	}
	if a.Age < 0 {
		return errors.New("runtime evidence age cannot be negative")
	}
	if strings.TrimSpace(a.Reason) == "" {
		return errors.New("runtime evidence assessment reason is required")
	}

	return nil
}

// AssessRuntimeEvidence classifies one cached or freshly observed runtime
// evidence snapshot as fresh, stale, unavailable, or partial.
func AssessRuntimeEvidence(snapshot RuntimeEvidenceSnapshot, policy RuntimeEvidencePolicy, now time.Time) (RuntimeEvidenceAssessment, error) {
	if err := snapshot.Validate(); err != nil {
		return RuntimeEvidenceAssessment{}, err
	}
	if err := policy.Validate(); err != nil {
		return RuntimeEvidenceAssessment{}, err
	}
	if now.IsZero() {
		return RuntimeEvidenceAssessment{}, errors.New("runtime evidence assessment requires a reference time")
	}
	if snapshot.ObservedAt.After(now) {
		return RuntimeEvidenceAssessment{}, errors.New("runtime evidence observation time cannot be in the future")
	}

	assessment := RuntimeEvidenceAssessment{
		Age: now.Sub(snapshot.ObservedAt),
	}

	if snapshotHasPartialRuntimeEvidence(snapshot.Result) {
		assessment.Freshness = RuntimeEvidenceFreshnessPartial
		assessment.RefreshNeeded = true
		assessment.Reason = "live runtime evidence is only partially trustworthy"
		if err := assessment.Validate(); err != nil {
			return RuntimeEvidenceAssessment{}, err
		}
		return assessment, nil
	}

	switch snapshot.Result.State() {
	case SessionEvidenceStateUnavailable:
		assessment.Freshness = RuntimeEvidenceFreshnessUnavailable
		assessment.RefreshNeeded = true
		assessment.Reason = "live runtime evidence is currently unavailable"
	case SessionEvidenceStateInsufficient:
		assessment.Freshness = RuntimeEvidenceFreshnessPartial
		assessment.RefreshNeeded = true
		assessment.Reason = "live runtime evidence is only partially trustworthy"
	case SessionEvidenceStateAvailable, SessionEvidenceStateNoSessions:
		if assessment.Age <= policy.FreshTTL {
			assessment.Freshness = RuntimeEvidenceFreshnessFresh
			assessment.Trusted = true
			assessment.Reason = "live runtime evidence is fresh enough to reuse without a refresh"
		} else {
			assessment.Freshness = RuntimeEvidenceFreshnessStale
			assessment.RefreshNeeded = true
			assessment.Reason = "live runtime evidence is stale and should be refreshed before reuse"
		}
	default:
		return RuntimeEvidenceAssessment{}, fmt.Errorf("unsupported session evidence state %q", snapshot.Result.State())
	}

	if err := assessment.Validate(); err != nil {
		return RuntimeEvidenceAssessment{}, err
	}

	return assessment, nil
}

func snapshotHasPartialRuntimeEvidence(result SessionEvidenceResult) bool {
	if len(result.Evidence) == 0 || len(result.Issues) == 0 {
		return false
	}

	return true
}
