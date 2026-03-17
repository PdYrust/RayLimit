package limiter

import (
	"errors"
	"fmt"
	"strings"

	"github.com/PdYrust/RayLimit/internal/discovery"
	"github.com/PdYrust/RayLimit/internal/ipaddr"
	"github.com/PdYrust/RayLimit/internal/policy"
)

// ActionKind identifies the intended limiter operation.
type ActionKind string

const (
	ActionApply     ActionKind = "apply"
	ActionRemove    ActionKind = "remove"
	ActionReconcile ActionKind = "reconcile"
	ActionInspect   ActionKind = "inspect"
)

func (k ActionKind) Valid() bool {
	switch k {
	case ActionApply, ActionRemove, ActionReconcile, ActionInspect:
		return true
	default:
		return false
	}
}

// RuntimeBinding ties an enforcement subject to a concrete runtime instance.
// Connection-scoped subjects additionally require a session identifier.
type RuntimeBinding struct {
	Runtime   discovery.SessionRuntime `json:"runtime"`
	SessionID string                   `json:"session_id,omitempty"`
}

// ValidateFor checks that the binding is internally consistent for the given target kind.
func (b RuntimeBinding) ValidateFor(kind policy.TargetKind) error {
	if err := b.Runtime.Validate(); err != nil {
		return fmt.Errorf("invalid runtime binding: %w", err)
	}

	sessionID := strings.TrimSpace(b.SessionID)
	if kind == policy.TargetKindConnection {
		if sessionID == "" {
			return errors.New("connection binding requires a session id")
		}
		return nil
	}

	if sessionID != "" {
		return errors.New("non-connection binding cannot include a session id")
	}

	return nil
}

// Subject identifies the runtime-scoped object a limiter action refers to.
type Subject struct {
	Kind    policy.TargetKind `json:"kind"`
	Value   string            `json:"value,omitempty"`
	Binding RuntimeBinding    `json:"binding"`
}

// Validate checks that an enforcement subject is internally consistent.
func (s Subject) Validate() error {
	if !s.Kind.Valid() {
		return fmt.Errorf("invalid subject kind %q", s.Kind)
	}

	if err := s.Binding.ValidateFor(s.Kind); err != nil {
		return err
	}

	value := strings.TrimSpace(s.Value)
	switch s.Kind {
	case policy.TargetKindConnection:
		if value != "" {
			return errors.New("connection subject cannot define a generic value")
		}
	case policy.TargetKindUUID, policy.TargetKindInbound, policy.TargetKindOutbound:
		if value == "" {
			return fmt.Errorf("%s subject requires a value", s.Kind)
		}
	case policy.TargetKindIP:
		if value == "" {
			return errors.New("ip subject requires a value")
		}
		if _, err := ipaddr.Normalize(value); err != nil {
			return fmt.Errorf("invalid ip subject value %q", value)
		}
	}

	return nil
}

// Equal reports whether two subjects refer to the same runtime-scoped identity.
func (s Subject) Equal(other Subject) bool {
	if s.Kind != other.Kind {
		return false
	}
	if !sameBinding(s.Binding, other.Binding) {
		return false
	}

	switch s.Kind {
	case policy.TargetKindUUID:
		return strings.EqualFold(strings.TrimSpace(s.Value), strings.TrimSpace(other.Value))
	case policy.TargetKindIP:
		return ipaddr.Equal(s.Value, other.Value)
	default:
		return strings.TrimSpace(s.Value) == strings.TrimSpace(other.Value)
	}
}

// SubjectFromSession derives an enforcement subject from a discovered runtime session.
func SubjectFromSession(kind policy.TargetKind, session discovery.Session) (Subject, error) {
	if err := session.Validate(); err != nil {
		return Subject{}, fmt.Errorf("invalid session: %w", err)
	}

	subject := Subject{
		Kind: kind,
		Binding: RuntimeBinding{
			Runtime: session.Runtime,
		},
	}

	switch kind {
	case policy.TargetKindConnection:
		subject.Binding.SessionID = strings.TrimSpace(session.ID)
		if subject.Binding.SessionID == "" {
			return Subject{}, errors.New("connection subject requires a session id")
		}
	case policy.TargetKindUUID:
		subject.Value = strings.TrimSpace(session.Policy.UUID)
	case policy.TargetKindIP:
		normalized, err := ipaddr.Normalize(session.Client.IP)
		if err != nil {
			return Subject{}, err
		}
		subject.Value = normalized
	case policy.TargetKindInbound:
		subject.Value = strings.TrimSpace(session.Route.InboundTag)
	case policy.TargetKindOutbound:
		subject.Value = strings.TrimSpace(session.Route.OutboundTag)
	default:
		return Subject{}, fmt.Errorf("unsupported subject kind %q", kind)
	}

	if err := subject.Validate(); err != nil {
		return Subject{}, err
	}

	return subject, nil
}

// DesiredState describes the limit state RayLimit intends to exist for a subject.
type DesiredState struct {
	Subject          Subject            `json:"subject"`
	Limits           policy.LimitPolicy `json:"limits"`
	PolicyEvaluation policy.Evaluation  `json:"policy_evaluation"`
}

// Validate checks that the desired state is internally consistent.
func (s DesiredState) Validate() error {
	if err := s.Subject.Validate(); err != nil {
		return fmt.Errorf("invalid desired subject: %w", err)
	}

	if err := s.Limits.Validate(); err != nil {
		return fmt.Errorf("invalid desired limits: %w", err)
	}

	if !s.PolicyEvaluation.HasMatch() {
		return errors.New("desired state requires a matching policy evaluation")
	}
	if s.PolicyEvaluation.Excluded() {
		return errors.New("desired state cannot be built from an excluded policy evaluation")
	}
	if s.PolicyEvaluation.Selection.Kind != s.Subject.Kind {
		return errors.New("desired state subject kind does not match policy evaluation")
	}
	if !sameLimitPolicy(s.Limits, s.PolicyEvaluation.EffectiveLimits) {
		return errors.New("desired state limits do not match policy evaluation")
	}

	return nil
}

// DesiredStateFromEvaluation derives a desired limit state from a session and policy evaluation.
func DesiredStateFromEvaluation(session discovery.Session, evaluation policy.Evaluation) (DesiredState, error) {
	if !evaluation.HasMatch() {
		return DesiredState{}, errors.New("policy evaluation has no matches")
	}
	if evaluation.Excluded() {
		return DesiredState{}, errors.New("excluded policy evaluation does not define a desired state")
	}
	if !evaluation.EffectiveLimits.HasAny() {
		return DesiredState{}, errors.New("policy evaluation does not define effective limits")
	}

	subject, err := SubjectFromSession(evaluation.Selection.Kind, session)
	if err != nil {
		return DesiredState{}, err
	}

	desired := DesiredState{
		Subject:          subject,
		Limits:           evaluation.EffectiveLimits,
		PolicyEvaluation: evaluation,
	}
	if err := desired.Validate(); err != nil {
		return DesiredState{}, err
	}

	return desired, nil
}

// AppliedState describes limiter state that has already been realized by a future backend.
type AppliedState struct {
	Subject   Subject            `json:"subject"`
	Limits    policy.LimitPolicy `json:"limits"`
	Driver    string             `json:"driver"`
	Reference string             `json:"reference,omitempty"`
}

// Validate checks that an applied limiter state is internally consistent.
func (s AppliedState) Validate() error {
	if err := s.Subject.Validate(); err != nil {
		return fmt.Errorf("invalid applied subject: %w", err)
	}
	if err := s.Limits.Validate(); err != nil {
		return fmt.Errorf("invalid applied limits: %w", err)
	}
	if strings.TrimSpace(s.Driver) == "" {
		return errors.New("applied state requires a driver")
	}

	return nil
}

// MatchesDesired reports whether the applied state already satisfies the desired state.
func (s AppliedState) MatchesDesired(desired DesiredState) bool {
	return s.Subject.Equal(desired.Subject) && sameLimitPolicy(s.Limits, desired.Limits)
}

// Action captures a future limiter operation without performing system changes.
type Action struct {
	Kind    ActionKind     `json:"kind"`
	Subject Subject        `json:"subject"`
	Desired *DesiredState  `json:"desired,omitempty"`
	Applied []AppliedState `json:"applied,omitempty"`
}

// Validate checks that an action is internally consistent.
func (a Action) Validate() error {
	if !a.Kind.Valid() {
		return fmt.Errorf("invalid action kind %q", a.Kind)
	}
	if err := a.Subject.Validate(); err != nil {
		return fmt.Errorf("invalid action subject: %w", err)
	}

	for index, applied := range a.Applied {
		if err := applied.Validate(); err != nil {
			return fmt.Errorf("invalid applied state at index %d: %w", index, err)
		}
		if !applied.Subject.Equal(a.Subject) {
			return fmt.Errorf("applied state at index %d does not match the action subject", index)
		}
	}

	if a.Desired != nil {
		if err := a.Desired.Validate(); err != nil {
			return fmt.Errorf("invalid desired state: %w", err)
		}
		if !a.Desired.Subject.Equal(a.Subject) {
			return errors.New("desired state does not match the action subject")
		}
	}

	switch a.Kind {
	case ActionApply:
		if a.Desired == nil {
			return errors.New("apply action requires a desired state")
		}
		if len(a.Applied) != 0 {
			return errors.New("apply action cannot include applied state")
		}
	case ActionRemove:
		if a.Desired != nil {
			return errors.New("remove action cannot include a desired state")
		}
	case ActionReconcile:
		if a.Desired == nil {
			return errors.New("reconcile action requires a desired state")
		}
	case ActionInspect:
		if a.Desired != nil {
			return errors.New("inspect action cannot include a desired state")
		}
		if len(a.Applied) != 0 {
			return errors.New("inspect action cannot include applied state")
		}
	}

	return nil
}

func sameBinding(left RuntimeBinding, right RuntimeBinding) bool {
	return strings.TrimSpace(left.SessionID) == strings.TrimSpace(right.SessionID) &&
		left.Runtime.Source == right.Runtime.Source &&
		strings.TrimSpace(left.Runtime.Provider) == strings.TrimSpace(right.Runtime.Provider) &&
		strings.TrimSpace(left.Runtime.Name) == strings.TrimSpace(right.Runtime.Name) &&
		left.Runtime.HostPID == right.Runtime.HostPID &&
		strings.TrimSpace(left.Runtime.ContainerID) == strings.TrimSpace(right.Runtime.ContainerID)
}

func sameLimitPolicy(left policy.LimitPolicy, right policy.LimitPolicy) bool {
	return sameRateLimit(left.Upload, right.Upload) && sameRateLimit(left.Download, right.Download)
}

func sameRateLimit(left *policy.RateLimit, right *policy.RateLimit) bool {
	switch {
	case left == nil && right == nil:
		return true
	case left == nil || right == nil:
		return false
	default:
		return left.BytesPerSecond == right.BytesPerSecond
	}
}
