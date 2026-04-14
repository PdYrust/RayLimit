package discovery

import (
	"context"
	"errors"
	"fmt"
	"strings"
)

// SessionEvidenceConfidence reports how trustworthy an observed session record is.
type SessionEvidenceConfidence string

const (
	SessionEvidenceConfidenceHigh   SessionEvidenceConfidence = "high"
	SessionEvidenceConfidenceMedium SessionEvidenceConfidence = "medium"
	SessionEvidenceConfidenceLow    SessionEvidenceConfidence = "low"
)

func (c SessionEvidenceConfidence) Valid() bool {
	switch c {
	case SessionEvidenceConfidenceHigh, SessionEvidenceConfidenceMedium, SessionEvidenceConfidenceLow:
		return true
	default:
		return false
	}
}

// SessionEvidenceState summarizes what a provider could currently observe.
type SessionEvidenceState string

const (
	SessionEvidenceStateAvailable    SessionEvidenceState = "available"
	SessionEvidenceStateNoSessions   SessionEvidenceState = "no_sessions"
	SessionEvidenceStateUnavailable  SessionEvidenceState = "unavailable"
	SessionEvidenceStateInsufficient SessionEvidenceState = "insufficient"
)

func (s SessionEvidenceState) Valid() bool {
	switch s {
	case SessionEvidenceStateAvailable, SessionEvidenceStateNoSessions, SessionEvidenceStateUnavailable, SessionEvidenceStateInsufficient:
		return true
	default:
		return false
	}
}

// SessionEvidence captures one provider-backed live session observation.
type SessionEvidence struct {
	Runtime    SessionRuntime            `json:"runtime"`
	Session    Session                   `json:"session"`
	Confidence SessionEvidenceConfidence `json:"confidence"`
	Note       string                    `json:"note,omitempty"`
}

func (e SessionEvidence) Validate() error {
	if err := e.Runtime.Validate(); err != nil {
		return fmt.Errorf("invalid evidence runtime: %w", err)
	}
	if err := e.Session.Validate(); err != nil {
		return fmt.Errorf("invalid evidence session: %w", err)
	}
	if !e.Confidence.Valid() {
		return fmt.Errorf("invalid evidence confidence %q", e.Confidence)
	}
	if !sameEvidenceRuntime(e.Runtime, e.Session.Runtime) {
		return errors.New("evidence session does not match the evidence runtime")
	}

	return nil
}

// SessionEvidenceIssueCode identifies why live session evidence could not be
// observed or trusted fully.
type SessionEvidenceIssueCode string

const (
	SessionEvidenceIssueUnavailable      SessionEvidenceIssueCode = "unavailable"
	SessionEvidenceIssueInsufficient     SessionEvidenceIssueCode = "insufficient"
	SessionEvidenceIssuePermissionDenied SessionEvidenceIssueCode = "permission_denied"
)

func (c SessionEvidenceIssueCode) Valid() bool {
	switch c {
	case SessionEvidenceIssueUnavailable, SessionEvidenceIssueInsufficient, SessionEvidenceIssuePermissionDenied:
		return true
	default:
		return false
	}
}

// SessionEvidenceIssue records a non-fatal observation limitation.
type SessionEvidenceIssue struct {
	Code    SessionEvidenceIssueCode `json:"code"`
	Message string                   `json:"message"`
}

func (i SessionEvidenceIssue) Validate() error {
	if !i.Code.Valid() {
		return fmt.Errorf("invalid evidence issue code %q", i.Code)
	}
	if strings.TrimSpace(i.Message) == "" {
		return errors.New("evidence issue message is required")
	}

	return nil
}

// SessionEvidenceResult captures what one provider could observe for a runtime.
type SessionEvidenceResult struct {
	Provider string                 `json:"provider"`
	Runtime  SessionRuntime         `json:"runtime"`
	Evidence []SessionEvidence      `json:"evidence,omitempty"`
	Issues   []SessionEvidenceIssue `json:"issues,omitempty"`
}

func (r SessionEvidenceResult) Validate() error {
	if strings.TrimSpace(r.Provider) == "" {
		return errors.New("session evidence provider name is required")
	}
	if err := r.Runtime.Validate(); err != nil {
		return fmt.Errorf("invalid evidence runtime: %w", err)
	}
	for index, evidence := range r.Evidence {
		if err := evidence.Validate(); err != nil {
			return fmt.Errorf("invalid evidence at index %d: %w", index, err)
		}
		if !sameEvidenceRuntime(r.Runtime, evidence.Runtime) {
			return fmt.Errorf("evidence at index %d does not belong to the requested runtime", index)
		}
	}
	for index, issue := range r.Issues {
		if err := issue.Validate(); err != nil {
			return fmt.Errorf("invalid evidence issue at index %d: %w", index, err)
		}
	}

	return nil
}

// State summarizes whether evidence was available, absent, or limited.
func (r SessionEvidenceResult) State() SessionEvidenceState {
	if len(r.Evidence) != 0 {
		return SessionEvidenceStateAvailable
	}
	for _, issue := range r.Issues {
		switch issue.Code {
		case SessionEvidenceIssueInsufficient:
			return SessionEvidenceStateInsufficient
		case SessionEvidenceIssueUnavailable, SessionEvidenceIssuePermissionDenied:
			return SessionEvidenceStateUnavailable
		}
	}

	return SessionEvidenceStateNoSessions
}

// Sessions returns the observed sessions in provider order.
func (r SessionEvidenceResult) Sessions() []Session {
	if len(r.Evidence) == 0 {
		return nil
	}

	sessions := make([]Session, 0, len(r.Evidence))
	for _, evidence := range r.Evidence {
		sessions = append(sessions, evidence.Session)
	}

	return sessions
}

// IssueSummary joins provider issue messages for later reporting.
func (r SessionEvidenceResult) IssueSummary() string {
	if len(r.Issues) == 0 {
		return ""
	}

	messages := make([]string, 0, len(r.Issues))
	for _, issue := range r.Issues {
		message := strings.TrimSpace(issue.Message)
		if message == "" {
			continue
		}
		messages = append(messages, message)
	}

	return strings.Join(messages, "; ")
}

// SessionEvidenceProvider gathers runtime-scoped live session evidence from one source.
type SessionEvidenceProvider interface {
	Name() string
	ObserveSessions(ctx context.Context, runtime SessionRuntime) (SessionEvidenceResult, error)
}

func sameEvidenceRuntime(left SessionRuntime, right SessionRuntime) bool {
	return left.Source == right.Source &&
		strings.TrimSpace(left.Provider) == strings.TrimSpace(right.Provider) &&
		strings.TrimSpace(left.Name) == strings.TrimSpace(right.Name) &&
		left.HostPID == right.HostPID &&
		strings.TrimSpace(left.ContainerID) == strings.TrimSpace(right.ContainerID)
}
