package correlation

import (
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/PdYrust/RayLimit/internal/discovery"
)

// UUIDMembershipRefreshAction describes how the control plane should treat the
// current UUID aggregate membership snapshot.
type UUIDMembershipRefreshAction string

const (
	UUIDMembershipRefreshReuseCached         UUIDMembershipRefreshAction = "reuse_cached"
	UUIDMembershipRefreshRefreshed           UUIDMembershipRefreshAction = "refreshed"
	UUIDMembershipRefreshRefreshRequired     UUIDMembershipRefreshAction = "refresh_required"
	UUIDMembershipRefreshEvidenceUnavailable UUIDMembershipRefreshAction = "evidence_unavailable"
	UUIDMembershipRefreshEvidencePartial     UUIDMembershipRefreshAction = "evidence_partial"
)

func (a UUIDMembershipRefreshAction) Valid() bool {
	switch a {
	case UUIDMembershipRefreshReuseCached,
		UUIDMembershipRefreshRefreshed,
		UUIDMembershipRefreshRefreshRequired,
		UUIDMembershipRefreshEvidenceUnavailable,
		UUIDMembershipRefreshEvidencePartial:
		return true
	default:
		return false
	}
}

// UUIDMembershipSnapshot captures one cached UUID membership together with the
// evidence snapshot that produced it.
type UUIDMembershipSnapshot struct {
	Membership UUIDAggregateMembership           `json:"membership"`
	Evidence   discovery.RuntimeEvidenceSnapshot `json:"evidence"`
}

func (s UUIDMembershipSnapshot) Validate() error {
	if err := s.Membership.Validate(); err != nil {
		return fmt.Errorf("invalid cached uuid membership: %w", err)
	}
	if err := s.Evidence.Validate(); err != nil {
		return fmt.Errorf("invalid cached runtime evidence: %w", err)
	}
	if !sameRuntime(s.Membership.Subject.Runtime, s.Evidence.Result.Runtime) {
		return errors.New("cached runtime evidence does not match the membership runtime")
	}

	derived, err := membershipFromRuntimeEvidence(s.Membership.Subject, s.Evidence)
	if err != nil {
		return err
	}
	if !equalUUIDAggregateMemberships(s.Membership, derived) {
		return errors.New("cached uuid membership does not match the cached runtime evidence")
	}

	return nil
}

// UUIDMembershipRefreshInput captures the cheap-first cached vs refreshed
// membership inputs later reconcile loops can consume safely.
type UUIDMembershipRefreshInput struct {
	Subject UUIDAggregateSubject               `json:"subject"`
	Cached  *UUIDMembershipSnapshot            `json:"cached,omitempty"`
	Latest  *discovery.RuntimeEvidenceSnapshot `json:"latest,omitempty"`
	Policy  discovery.RuntimeEvidencePolicy    `json:"policy"`
	Now     time.Time                          `json:"now"`
}

func (i UUIDMembershipRefreshInput) Validate() error {
	if err := i.Subject.Validate(); err != nil {
		return fmt.Errorf("invalid refresh subject: %w", err)
	}
	if i.Cached != nil {
		if err := i.Cached.Validate(); err != nil {
			return fmt.Errorf("invalid cached membership snapshot: %w", err)
		}
		if i.Cached.Membership.Subject.Key() != i.Subject.Key() {
			return errors.New("cached membership snapshot does not match the requested subject")
		}
	}
	if i.Latest != nil {
		if err := i.Latest.Validate(); err != nil {
			return fmt.Errorf("invalid latest runtime evidence snapshot: %w", err)
		}
		if !sameRuntime(i.Subject.Runtime, i.Latest.Result.Runtime) {
			return errors.New("latest runtime evidence does not match the requested subject runtime")
		}
	}
	if err := i.Policy.Validate(); err != nil {
		return fmt.Errorf("invalid refresh policy: %w", err)
	}
	if i.Now.IsZero() {
		return errors.New("membership refresh requires a reference time")
	}

	return nil
}

// UUIDMembershipRefreshResult captures whether cached membership can be reused,
// whether a refresh produced new membership, or whether evidence remains too
// stale, partial, or unavailable.
type UUIDMembershipRefreshResult struct {
	Action        UUIDMembershipRefreshAction        `json:"action"`
	Subject       UUIDAggregateSubject               `json:"subject"`
	Membership    *UUIDAggregateMembership           `json:"membership,omitempty"`
	Freshness     discovery.RuntimeEvidenceFreshness `json:"freshness"`
	Changed       bool                               `json:"changed,omitempty"`
	RefreshNeeded bool                               `json:"refresh_needed,omitempty"`
	Reason        string                             `json:"reason"`
}

func (r UUIDMembershipRefreshResult) Validate() error {
	if !r.Action.Valid() {
		return fmt.Errorf("invalid membership refresh action %q", r.Action)
	}
	if err := r.Subject.Validate(); err != nil {
		return fmt.Errorf("invalid membership refresh subject: %w", err)
	}
	if !r.Freshness.Valid() {
		return fmt.Errorf("invalid runtime evidence freshness %q", r.Freshness)
	}
	if r.Membership != nil {
		if err := r.Membership.Validate(); err != nil {
			return fmt.Errorf("invalid refreshed membership: %w", err)
		}
		if r.Membership.Subject.Key() != r.Subject.Key() {
			return errors.New("refreshed membership does not match the requested subject")
		}
	}
	if strings.TrimSpace(r.Reason) == "" {
		return errors.New("membership refresh reason is required")
	}

	return nil
}

// UUIDMembershipRefresher decides whether cached UUID membership can be reused
// cheaply or whether later control-plane phases still need a fresh runtime
// evidence refresh.
type UUIDMembershipRefresher struct{}

func (UUIDMembershipRefresher) Refresh(input UUIDMembershipRefreshInput) (UUIDMembershipRefreshResult, error) {
	if err := input.Validate(); err != nil {
		return UUIDMembershipRefreshResult{}, err
	}

	if input.Cached != nil {
		cachedAssessment, err := discovery.AssessRuntimeEvidence(input.Cached.Evidence, input.Policy, input.Now)
		if err != nil {
			return UUIDMembershipRefreshResult{}, err
		}
		if cachedAssessment.Freshness == discovery.RuntimeEvidenceFreshnessFresh {
			result := UUIDMembershipRefreshResult{
				Action:        UUIDMembershipRefreshReuseCached,
				Subject:       input.Subject,
				Membership:    cloneUUIDAggregateMembership(&input.Cached.Membership),
				Freshness:     cachedAssessment.Freshness,
				RefreshNeeded: false,
				Reason:        "cached live runtime evidence is still fresh; membership refresh can reuse it cheaply",
			}
			if err := result.Validate(); err != nil {
				return UUIDMembershipRefreshResult{}, err
			}
			return result, nil
		}
	}

	if input.Latest == nil {
		return refreshResultFromCachedOnly(input)
	}

	assessment, err := discovery.AssessRuntimeEvidence(*input.Latest, input.Policy, input.Now)
	if err != nil {
		return UUIDMembershipRefreshResult{}, err
	}

	var membership *UUIDAggregateMembership
	if assessment.Freshness != discovery.RuntimeEvidenceFreshnessUnavailable {
		derived, deriveErr := membershipFromRuntimeEvidence(input.Subject, *input.Latest)
		if deriveErr != nil {
			return UUIDMembershipRefreshResult{}, deriveErr
		}
		membership = &derived
	}

	result := UUIDMembershipRefreshResult{
		Subject:       input.Subject,
		Membership:    membership,
		Freshness:     assessment.Freshness,
		RefreshNeeded: assessment.RefreshNeeded,
	}
	if input.Cached != nil && membership != nil {
		result.Changed = !equalUUIDAggregateMemberships(input.Cached.Membership, *membership)
	}

	switch assessment.Freshness {
	case discovery.RuntimeEvidenceFreshnessFresh:
		result.Action = UUIDMembershipRefreshRefreshed
		result.Reason = "live runtime evidence was refreshed and produced a fresh uuid aggregate membership snapshot"
	case discovery.RuntimeEvidenceFreshnessStale:
		result.Action = UUIDMembershipRefreshRefreshRequired
		result.Reason = "live runtime evidence is already stale; the derived uuid membership is available for context only and still requires a newer refresh"
	case discovery.RuntimeEvidenceFreshnessPartial:
		result.Action = UUIDMembershipRefreshEvidencePartial
		result.Reason = "live runtime evidence is only partially trustworthy; the derived uuid membership remains evidence-gated"
	case discovery.RuntimeEvidenceFreshnessUnavailable:
		result.Action = UUIDMembershipRefreshEvidenceUnavailable
		result.Membership = cachedMembershipOrNil(input.Cached)
		result.Reason = "live runtime evidence is unavailable; cached uuid membership, if any, cannot be treated as current"
	default:
		return UUIDMembershipRefreshResult{}, fmt.Errorf("unsupported runtime evidence freshness %q", assessment.Freshness)
	}

	if err := result.Validate(); err != nil {
		return UUIDMembershipRefreshResult{}, err
	}

	return result, nil
}

func refreshResultFromCachedOnly(input UUIDMembershipRefreshInput) (UUIDMembershipRefreshResult, error) {
	result := UUIDMembershipRefreshResult{
		Subject:       input.Subject,
		Freshness:     discovery.RuntimeEvidenceFreshnessUnavailable,
		RefreshNeeded: true,
		Reason:        "no fresh live runtime evidence is currently available for uuid membership refresh",
	}

	if input.Cached == nil {
		result.Action = UUIDMembershipRefreshRefreshRequired
		if err := result.Validate(); err != nil {
			return UUIDMembershipRefreshResult{}, err
		}
		return result, nil
	}

	assessment, err := discovery.AssessRuntimeEvidence(input.Cached.Evidence, input.Policy, input.Now)
	if err != nil {
		return UUIDMembershipRefreshResult{}, err
	}
	result.Freshness = assessment.Freshness
	result.Membership = cloneUUIDAggregateMembership(&input.Cached.Membership)

	switch assessment.Freshness {
	case discovery.RuntimeEvidenceFreshnessStale:
		result.Action = UUIDMembershipRefreshRefreshRequired
		result.Reason = "cached uuid membership remains available for context, but its live runtime evidence is stale and requires refresh"
	case discovery.RuntimeEvidenceFreshnessPartial:
		result.Action = UUIDMembershipRefreshEvidencePartial
		result.Reason = "cached uuid membership remains available for context, but its live runtime evidence is only partially trustworthy"
	case discovery.RuntimeEvidenceFreshnessUnavailable:
		result.Action = UUIDMembershipRefreshEvidenceUnavailable
		result.Reason = "cached uuid membership remains available for context, but its live runtime evidence is unavailable"
	default:
		return UUIDMembershipRefreshResult{}, fmt.Errorf("unsupported cached runtime evidence freshness %q", assessment.Freshness)
	}

	if err := result.Validate(); err != nil {
		return UUIDMembershipRefreshResult{}, err
	}

	return result, nil
}

func membershipFromRuntimeEvidence(subject UUIDAggregateSubject, snapshot discovery.RuntimeEvidenceSnapshot) (UUIDAggregateMembership, error) {
	if err := subject.Validate(); err != nil {
		return UUIDAggregateMembership{}, err
	}
	if err := snapshot.Validate(); err != nil {
		return UUIDAggregateMembership{}, err
	}
	if !sameRuntime(subject.Runtime, snapshot.Result.Runtime) {
		return UUIDAggregateMembership{}, errors.New("runtime evidence does not match the requested uuid aggregate runtime")
	}

	sessions := make([]discovery.Session, 0, len(snapshot.Result.Evidence))
	for _, session := range snapshot.Result.Sessions() {
		if session.Policy.Key() != normalizeUUID(subject.UUID) {
			continue
		}
		sessions = append(sessions, session)
	}

	return NewUUIDAggregateMembership(subject, sessions)
}

func equalUUIDAggregateMemberships(left UUIDAggregateMembership, right UUIDAggregateMembership) bool {
	if left.Subject.Key() != right.Subject.Key() || len(left.Members) != len(right.Members) {
		return false
	}
	for index := range left.Members {
		if left.Members[index].Key() != right.Members[index].Key() || left.Members[index].Session != right.Members[index].Session {
			return false
		}
	}

	return true
}

func cloneUUIDAggregateMembership(membership *UUIDAggregateMembership) *UUIDAggregateMembership {
	if membership == nil {
		return nil
	}

	copy := UUIDAggregateMembership{
		Subject: membership.Subject,
		Members: append([]UUIDAggregateMember(nil), membership.Members...),
	}

	return &copy
}

func cachedMembershipOrNil(cached *UUIDMembershipSnapshot) *UUIDAggregateMembership {
	if cached == nil {
		return nil
	}

	return cloneUUIDAggregateMembership(&cached.Membership)
}
