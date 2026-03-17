package correlation

import (
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/PdYrust/RayLimit/internal/discovery"
)

// UUIDMembershipGraceInput captures the narrow anti-flap inputs for one
// runtime-local UUID aggregate owner.
type UUIDMembershipGraceInput struct {
	Subject UUIDAggregateSubject                 `json:"subject"`
	Cached  *UUIDMembershipSnapshot              `json:"cached,omitempty"`
	Refresh UUIDMembershipRefreshResult          `json:"refresh"`
	Policy  discovery.RuntimeEvidenceChurnPolicy `json:"policy"`
	Now     time.Time                            `json:"now"`
}

func (i UUIDMembershipGraceInput) Validate() error {
	if err := i.Subject.Validate(); err != nil {
		return fmt.Errorf("invalid uuid grace subject: %w", err)
	}
	if i.Cached != nil {
		if err := i.Cached.Validate(); err != nil {
			return fmt.Errorf("invalid cached uuid membership snapshot: %w", err)
		}
		if i.Cached.Membership.Subject.Key() != i.Subject.Key() {
			return errors.New("cached uuid membership snapshot does not match the requested subject")
		}
	}
	if err := i.Refresh.Validate(); err != nil {
		return fmt.Errorf("invalid uuid membership refresh result: %w", err)
	}
	if i.Refresh.Subject.Key() != i.Subject.Key() {
		return errors.New("uuid membership refresh result does not match the requested subject")
	}
	if err := i.Policy.Validate(); err != nil {
		return fmt.Errorf("invalid uuid grace policy: %w", err)
	}
	if i.Now.IsZero() {
		return errors.New("uuid membership grace evaluation requires a reference time")
	}

	return nil
}

// UUIDMembershipGraceResult captures the anti-flap decision and the membership
// view later reconcile phases should treat as effective for now.
type UUIDMembershipGraceResult struct {
	Action              discovery.RuntimeEvidenceChurnAction `json:"action"`
	Subject             UUIDAggregateSubject                 `json:"subject"`
	EffectiveMembership *UUIDAggregateMembership             `json:"effective_membership,omitempty"`
	GraceUntil          *time.Time                           `json:"grace_until,omitempty"`
	Reason              string                               `json:"reason"`
}

func (r UUIDMembershipGraceResult) Validate() error {
	if !r.Action.Valid() {
		return fmt.Errorf("invalid uuid membership grace action %q", r.Action)
	}
	if err := r.Subject.Validate(); err != nil {
		return fmt.Errorf("invalid uuid membership grace subject: %w", err)
	}
	if r.EffectiveMembership != nil {
		if err := r.EffectiveMembership.Validate(); err != nil {
			return fmt.Errorf("invalid effective uuid membership: %w", err)
		}
		if r.EffectiveMembership.Subject.Key() != r.Subject.Key() {
			return errors.New("effective uuid membership does not match the requested subject")
		}
	}
	if strings.TrimSpace(r.Reason) == "" {
		return errors.New("uuid membership grace reason is required")
	}
	switch r.Action {
	case discovery.RuntimeEvidenceChurnActionGraceRetained:
		if r.GraceUntil == nil || r.GraceUntil.IsZero() {
			return errors.New("grace-retained uuid membership requires a grace deadline")
		}
	default:
		if r.GraceUntil != nil {
			return errors.New("only grace-retained uuid membership may include a grace deadline")
		}
	}

	return nil
}

// UUIDMembershipGraceEvaluator decides whether a freshly missing UUID
// membership should be retained briefly, removed immediately, refreshed again,
// or deferred because evidence is weak.
type UUIDMembershipGraceEvaluator struct{}

func (UUIDMembershipGraceEvaluator) Decide(input UUIDMembershipGraceInput) (UUIDMembershipGraceResult, error) {
	if err := input.Validate(); err != nil {
		return UUIDMembershipGraceResult{}, err
	}

	churnInput, err := buildUUIDMembershipChurnInput(input)
	if err != nil {
		return UUIDMembershipGraceResult{}, err
	}
	churnDecision, err := discovery.DecideRuntimeEvidenceChurn(churnInput)
	if err != nil {
		return UUIDMembershipGraceResult{}, err
	}

	result := UUIDMembershipGraceResult{
		Action:  churnDecision.Action,
		Subject: input.Subject,
		Reason:  churnDecision.Reason,
	}
	if churnDecision.GraceUntil != nil {
		copy := *churnDecision.GraceUntil
		result.GraceUntil = &copy
	}

	switch churnDecision.Action {
	case discovery.RuntimeEvidenceChurnActionStable:
		result.EffectiveMembership = cloneUUIDAggregateMembership(input.Refresh.Membership)
	case discovery.RuntimeEvidenceChurnActionGraceRetained:
		result.EffectiveMembership = cachedMembershipOrNil(input.Cached)
	case discovery.RuntimeEvidenceChurnActionRefreshRequired:
		if input.Cached != nil {
			result.EffectiveMembership = cachedMembershipOrNil(input.Cached)
		}
	case discovery.RuntimeEvidenceChurnActionDefer:
		if input.Refresh.Membership != nil {
			result.EffectiveMembership = cloneUUIDAggregateMembership(input.Refresh.Membership)
		} else {
			result.EffectiveMembership = cachedMembershipOrNil(input.Cached)
		}
	case discovery.RuntimeEvidenceChurnActionImmediatelyRemovable:
	}

	if err := result.Validate(); err != nil {
		return UUIDMembershipGraceResult{}, err
	}

	return result, nil
}

func buildUUIDMembershipChurnInput(input UUIDMembershipGraceInput) (discovery.RuntimeEvidenceChurnInput, error) {
	assessment := discovery.RuntimeEvidenceAssessment{
		Freshness:     input.Refresh.Freshness,
		Trusted:       input.Refresh.Freshness == discovery.RuntimeEvidenceFreshnessFresh,
		RefreshNeeded: input.Refresh.RefreshNeeded,
		Reason:        input.Refresh.Reason,
	}
	if err := assessment.Validate(); err != nil {
		return discovery.RuntimeEvidenceChurnInput{}, err
	}

	churnInput := discovery.RuntimeEvidenceChurnInput{
		Assessment: assessment,
		Policy:     input.Policy,
		Now:        input.Now,
	}
	if input.Refresh.Membership != nil && input.Refresh.Membership.MemberCount() == 0 && input.Refresh.Freshness == discovery.RuntimeEvidenceFreshnessFresh {
		churnInput.ConfirmedAbsent = true
	}
	if input.Cached != nil && input.Cached.Membership.MemberCount() > 0 {
		churnInput.HadTrustedPresence = true
		churnInput.LastTrustedPresence = input.Cached.Evidence.ObservedAt
	}

	return churnInput, nil
}
