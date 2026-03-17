package correlation

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"

	"github.com/PdYrust/RayLimit/internal/discovery"
)

type UUIDScope string

const (
	UUIDScopeRuntime UUIDScope = "runtime"
)

func (s UUIDScope) Valid() bool {
	switch s {
	case UUIDScopeRuntime:
		return true
	default:
		return false
	}
}

type UUIDStatus string

const (
	UUIDStatusUnavailable      UUIDStatus = "unavailable"
	UUIDStatusZeroSessions     UUIDStatus = "zero_sessions"
	UUIDStatusSingleSession    UUIDStatus = "single_session"
	UUIDStatusMultipleSessions UUIDStatus = "multiple_sessions"
)

func (s UUIDStatus) Valid() bool {
	switch s {
	case UUIDStatusUnavailable, UUIDStatusZeroSessions, UUIDStatusSingleSession, UUIDStatusMultipleSessions:
		return true
	default:
		return false
	}
}

type UUIDRequest struct {
	UUID    string                   `json:"uuid"`
	Runtime discovery.SessionRuntime `json:"runtime"`
}

func (r UUIDRequest) Validate() error {
	if strings.TrimSpace(r.UUID) == "" {
		return errors.New("uuid correlation requires a uuid")
	}
	if err := r.Runtime.Validate(); err != nil {
		return fmt.Errorf("invalid runtime: %w", err)
	}

	return nil
}

type UUIDResult struct {
	Request       UUIDRequest                         `json:"request"`
	Provider      string                              `json:"provider,omitempty"`
	Scope         UUIDScope                           `json:"scope"`
	Status        UUIDStatus                          `json:"status"`
	EvidenceState discovery.SessionEvidenceState      `json:"evidence_state,omitempty"`
	Confidence    discovery.SessionEvidenceConfidence `json:"confidence,omitempty"`
	Sessions      []discovery.Session                 `json:"sessions,omitempty"`
	Note          string                              `json:"note,omitempty"`
}

func (r UUIDResult) Validate() error {
	if err := r.Request.Validate(); err != nil {
		return err
	}
	if provider := strings.TrimSpace(r.Provider); provider == "" && r.Status != UUIDStatusUnavailable {
		return errors.New("uuid correlation provider is required for resolved results")
	}
	if !r.Scope.Valid() {
		return fmt.Errorf("invalid uuid correlation scope %q", r.Scope)
	}
	if !r.Status.Valid() {
		return fmt.Errorf("invalid uuid correlation status %q", r.Status)
	}
	if r.EvidenceState != "" && !r.EvidenceState.Valid() {
		return fmt.Errorf("invalid uuid evidence state %q", r.EvidenceState)
	}
	if r.Confidence != "" && !r.Confidence.Valid() {
		return fmt.Errorf("invalid uuid correlation confidence %q", r.Confidence)
	}

	for index, session := range r.Sessions {
		if err := session.Validate(); err != nil {
			return fmt.Errorf("invalid matched session at index %d: %w", index, err)
		}
		if !sameRuntime(r.Request.Runtime, session.Runtime) {
			return fmt.Errorf("matched session at index %d does not belong to the requested runtime", index)
		}
		if session.Policy.Key() != normalizeUUID(r.Request.UUID) {
			return fmt.Errorf("matched session at index %d does not match the requested uuid", index)
		}
	}

	switch r.Status {
	case UUIDStatusUnavailable:
		if len(r.Sessions) != 0 {
			return errors.New("unavailable correlation cannot include matched sessions")
		}
	case UUIDStatusZeroSessions:
		if len(r.Sessions) != 0 {
			return errors.New("zero-session correlation cannot include matched sessions")
		}
	case UUIDStatusSingleSession:
		if len(r.Sessions) != 1 {
			return errors.New("single-session correlation requires exactly one matched session")
		}
	case UUIDStatusMultipleSessions:
		if len(r.Sessions) < 2 {
			return errors.New("multiple-session correlation requires at least two matched sessions")
		}
	}
	if (r.Status == UUIDStatusSingleSession || r.Status == UUIDStatusMultipleSessions) && r.Confidence == discovery.SessionEvidenceConfidenceLow {
		return errors.New("concrete uuid correlation outcomes require medium or high confidence evidence")
	}

	return nil
}

func (r UUIDResult) MatchedSessionCount() int {
	return len(r.Sessions)
}

type UUIDResolver struct {
	Provider discovery.SessionEvidenceProvider
}

func (r UUIDResolver) Correlate(ctx context.Context, req UUIDRequest) (UUIDResult, error) {
	if err := req.Validate(); err != nil {
		return UUIDResult{}, err
	}

	result := UUIDResult{
		Request: req,
		Scope:   UUIDScopeRuntime,
		Status:  UUIDStatusUnavailable,
	}

	if r.Provider == nil {
		result.Note = "no live session provider is configured for UUID correlation; the requested UUID remains runtime-scoped only"
		return result, nil
	}

	evidence, err := r.Provider.ObserveSessions(ctx, req.Runtime)
	if err != nil {
		result.Provider = strings.TrimSpace(r.Provider.Name())
		result.Note = fmt.Sprintf("live session evidence could not be loaded: %v", err)
		return result, nil
	}
	if err := evidence.Validate(); err != nil {
		result.Provider = strings.TrimSpace(r.Provider.Name())
		result.Note = fmt.Sprintf("live session evidence was invalid: %v", err)
		return result, nil
	}
	if !sameRuntime(req.Runtime, evidence.Runtime) {
		result.Provider = strings.TrimSpace(evidence.Provider)
		result.Note = "live session evidence did not match the requested runtime"
		return result, nil
	}

	result.Provider = strings.TrimSpace(evidence.Provider)
	result.EvidenceState = evidence.State()

	matches, weakMatches, confidence := filterUUIDMatches(req, evidence.Evidence)
	result.Confidence = confidence

	if len(matches) == 0 {
		targetedMatches, targetedWeakMatches, targetedConfidence, targetedEvidence, targeted := correlateTargetedUUIDEvidence(ctx, r.Provider, req)
		if targeted {
			evidence = targetedEvidence
			result.Provider = strings.TrimSpace(evidence.Provider)
			result.EvidenceState = evidence.State()
			matches = targetedMatches
			weakMatches = targetedWeakMatches
			result.Confidence = targetedConfidence
		}
	}

	if len(matches) == 0 && weakMatches != 0 {
		result.Note = lowConfidenceNote(weakMatches, evidence)
		return result, nil
	}

	if len(matches) == 0 {
		switch evidence.State() {
		case discovery.SessionEvidenceStateUnavailable, discovery.SessionEvidenceStateInsufficient:
			result.Note = evidenceNote(evidence, "live session evidence was unavailable for UUID correlation")
		default:
			result.Status = UUIDStatusZeroSessions
			if len(evidence.Issues) != 0 {
				result.Note = evidenceNote(evidence, "session evidence included provider limitations; no matching live sessions were confirmed for the requested UUID")
			}
		}
		return result, nil
	}

	result.Sessions = matches
	switch len(matches) {
	case 1:
		result.Status = UUIDStatusSingleSession
	default:
		result.Status = UUIDStatusMultipleSessions
	}

	result.Note = matchedEvidenceNote(evidence, weakMatches)

	return result, nil
}

func correlateTargetedUUIDEvidence(
	ctx context.Context,
	provider discovery.SessionEvidenceProvider,
	req UUIDRequest,
) ([]discovery.Session, int, discovery.SessionEvidenceConfidence, discovery.SessionEvidenceResult, bool) {
	uuidProvider, ok := provider.(discovery.UUIDSessionEvidenceProvider)
	if !ok {
		return nil, 0, "", discovery.SessionEvidenceResult{}, false
	}

	evidence, err := uuidProvider.ObserveUUIDSessions(ctx, req.Runtime, req.UUID)
	if err != nil {
		return nil, 0, "", discovery.SessionEvidenceResult{}, false
	}
	if err := evidence.Validate(); err != nil {
		return nil, 0, "", discovery.SessionEvidenceResult{}, false
	}
	if !sameRuntime(req.Runtime, evidence.Runtime) {
		return nil, 0, "", discovery.SessionEvidenceResult{}, false
	}

	matches, weakMatches, confidence := filterUUIDMatches(req, evidence.Evidence)
	return matches, weakMatches, confidence, evidence, true
}

func filterUUIDMatches(req UUIDRequest, evidence []discovery.SessionEvidence) ([]discovery.Session, int, discovery.SessionEvidenceConfidence) {
	if len(evidence) == 0 {
		return nil, 0, ""
	}

	matches := make([]discovery.Session, 0, len(evidence))
	seen := make(map[string]struct{}, len(evidence))
	weakMatches := 0
	confidence := discovery.SessionEvidenceConfidenceHigh
	requestedUUID := normalizeUUID(req.UUID)

	for _, observation := range evidence {
		session := observation.Session
		if !sameRuntime(req.Runtime, session.Runtime) {
			continue
		}
		if session.Policy.Key() != requestedUUID {
			continue
		}
		if !trustedConfidence(observation.Confidence) {
			weakMatches++
			continue
		}

		key := uuidSessionKey(session)
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}

		matches = append(matches, session)
		if observation.Confidence == discovery.SessionEvidenceConfidenceMedium {
			confidence = discovery.SessionEvidenceConfidenceMedium
		}
	}

	sort.Slice(matches, func(i, j int) bool {
		return uuidSessionKey(matches[i]) < uuidSessionKey(matches[j])
	})

	if len(matches) == 0 {
		return nil, weakMatches, ""
	}

	return matches, weakMatches, confidence
}

func normalizeUUID(value string) string {
	return strings.ToLower(strings.TrimSpace(value))
}

func evidenceNote(result discovery.SessionEvidenceResult, fallback string) string {
	if summary := strings.TrimSpace(result.IssueSummary()); summary != "" {
		return summary
	}

	return fallback
}

func lowConfidenceNote(weakMatches int, evidence discovery.SessionEvidenceResult) string {
	note := fmt.Sprintf("only low-confidence live session evidence matched the requested UUID (%d match(es)); correlation remains preview-only", weakMatches)
	if summary := strings.TrimSpace(evidence.IssueSummary()); summary != "" {
		return note + "; " + summary
	}

	return note
}

func matchedEvidenceNote(evidence discovery.SessionEvidenceResult, weakMatches int) string {
	parts := make([]string, 0, 2)
	if weakMatches != 0 {
		parts = append(parts, fmt.Sprintf("ignored %d low-confidence UUID match(es)", weakMatches))
	}
	if summary := strings.TrimSpace(evidence.IssueSummary()); summary != "" {
		parts = append(parts, summary)
	}
	if len(parts) == 0 {
		return ""
	}

	return strings.Join(parts, "; ")
}

func trustedConfidence(confidence discovery.SessionEvidenceConfidence) bool {
	switch confidence {
	case discovery.SessionEvidenceConfidenceHigh, discovery.SessionEvidenceConfidenceMedium:
		return true
	default:
		return false
	}
}

func uuidSessionKey(session discovery.Session) string {
	return strings.Join([]string{
		string(session.Runtime.Source),
		strings.TrimSpace(session.Runtime.Provider),
		strings.TrimSpace(session.Runtime.Name),
		fmt.Sprintf("%d", session.Runtime.HostPID),
		strings.TrimSpace(session.Runtime.ContainerID),
		strings.TrimSpace(session.ID),
		session.Policy.Key(),
		strings.TrimSpace(session.Client.IP),
		strings.TrimSpace(session.Route.InboundTag),
		strings.TrimSpace(session.Route.OutboundTag),
	}, "|")
}

func sameRuntime(left discovery.SessionRuntime, right discovery.SessionRuntime) bool {
	return left.Source == right.Source &&
		strings.TrimSpace(left.Provider) == strings.TrimSpace(right.Provider) &&
		strings.TrimSpace(left.Name) == strings.TrimSpace(right.Name) &&
		left.HostPID == right.HostPID &&
		strings.TrimSpace(left.ContainerID) == strings.TrimSpace(right.ContainerID)
}
