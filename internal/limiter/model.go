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
type RuntimeBinding struct {
	Runtime discovery.SessionRuntime `json:"runtime"`
}

// ValidateFor checks that the binding is internally consistent for the given target kind.
func (b RuntimeBinding) ValidateFor(kind policy.TargetKind) error {
	if err := b.Runtime.Validate(); err != nil {
		return fmt.Errorf("invalid runtime binding: %w", err)
	}

	return nil
}

// Subject identifies the runtime-scoped object a limiter action refers to.
type Subject struct {
	Kind          policy.TargetKind        `json:"kind"`
	All           bool                     `json:"all,omitempty"`
	Value         string                   `json:"value,omitempty"`
	IPAggregation policy.IPAggregationMode `json:"ip_aggregation,omitempty"`
	Binding       RuntimeBinding           `json:"binding"`
}

// NormalizedIPAggregation reports the effective aggregation mode for an all-IP
// subject. An unspecified all-IP subject defaults to shared.
func (s Subject) NormalizedIPAggregation() policy.IPAggregationMode {
	if s.Kind != policy.TargetKindIP || !s.All {
		return ""
	}

	if strings.TrimSpace(string(s.IPAggregation)) == "" {
		return policy.IPAggregationModeShared
	}

	return s.IPAggregation
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
	aggregation := strings.TrimSpace(string(s.IPAggregation))
	switch s.Kind {
	case policy.TargetKindInbound, policy.TargetKindOutbound:
		if s.All {
			return fmt.Errorf("%s subject cannot use all", s.Kind)
		}
		if aggregation != "" {
			return fmt.Errorf("%s subject cannot use ip_aggregation", s.Kind)
		}
		if value == "" {
			return fmt.Errorf("%s subject requires a value", s.Kind)
		}
	case policy.TargetKindIP:
		if aggregation != "" && !s.IPAggregation.Valid() {
			return fmt.Errorf("invalid ip aggregation mode %q", s.IPAggregation)
		}
		switch {
		case s.All && value != "":
			return errors.New("ip subject cannot combine all with a specific value")
		case !s.All && value == "":
			return errors.New("ip subject requires a value")
		case !s.All && aggregation != "":
			return errors.New("specific ip subject cannot use ip_aggregation")
		case s.All:
			return nil
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
	if s.All != other.All {
		return false
	}
	if s.Kind == policy.TargetKindIP && s.All && s.NormalizedIPAggregation() != other.NormalizedIPAggregation() {
		return false
	}
	if !sameBinding(s.Binding, other.Binding) {
		return false
	}

	switch s.Kind {
	case policy.TargetKindIP:
		if s.All {
			return true
		}
		return ipaddr.Equal(s.Value, other.Value)
	default:
		return strings.TrimSpace(s.Value) == strings.TrimSpace(other.Value)
	}
}

// SubjectFromTarget derives an enforcement subject from a discovered runtime
// session and a selected policy target.
func SubjectFromTarget(target policy.Target, session discovery.Session) (Subject, error) {
	if err := target.Validate(); err != nil {
		return Subject{}, fmt.Errorf("invalid target: %w", err)
	}
	if err := session.Validate(); err != nil {
		return Subject{}, fmt.Errorf("invalid session: %w", err)
	}

	subject := Subject{
		Kind: target.Kind,
		All:  target.All,
		Binding: RuntimeBinding{
			Runtime: session.Runtime,
		},
	}

	switch target.Kind {
	case policy.TargetKindIP:
		if target.All {
			subject.IPAggregation = target.NormalizedIPAggregation()
			break
		}
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
		return Subject{}, fmt.Errorf("unsupported subject kind %q", target.Kind)
	}

	if err := subject.Validate(); err != nil {
		return Subject{}, err
	}

	return subject, nil
}

// SubjectFromSession derives an enforcement subject from a discovered runtime session.
func SubjectFromSession(kind policy.TargetKind, session discovery.Session) (Subject, error) {
	target := policy.Target{Kind: kind}
	switch kind {
	case policy.TargetKindIP:
		target.Value = session.Client.IP
	case policy.TargetKindInbound:
		target.Value = session.Route.InboundTag
	case policy.TargetKindOutbound:
		target.Value = session.Route.OutboundTag
	default:
		return Subject{}, fmt.Errorf("unsupported subject kind %q", kind)
	}

	return SubjectFromTarget(target, session)
}

// DesiredMode identifies which IP-side effect RayLimit intends to realize for a subject.
type DesiredMode string

const (
	DesiredModeLimit     DesiredMode = "limit"
	DesiredModeUnlimited DesiredMode = "unlimited"
)

func (m DesiredMode) Valid() bool {
	switch m {
	case DesiredModeLimit, DesiredModeUnlimited:
		return true
	default:
		return false
	}
}

// DesiredState describes the limiter state RayLimit intends to exist for a subject.
type DesiredState struct {
	Mode             DesiredMode        `json:"mode,omitempty"`
	Subject          Subject            `json:"subject"`
	Limits           policy.LimitPolicy `json:"limits"`
	PolicyEvaluation policy.Evaluation  `json:"policy_evaluation"`
}

// Validate checks that the desired state is internally consistent.
func (s DesiredState) Validate() error {
	if err := s.Subject.Validate(); err != nil {
		return fmt.Errorf("invalid desired subject: %w", err)
	}
	if !s.Mode.Valid() {
		return fmt.Errorf("invalid desired mode %q", s.Mode)
	}

	if !s.PolicyEvaluation.HasMatch() {
		return errors.New("desired state requires a matching policy evaluation")
	}
	if s.PolicyEvaluation.Selection.Kind != s.Subject.Kind {
		return errors.New("desired state subject kind does not match policy evaluation")
	}
	if s.PolicyEvaluation.Selection.Target.All != s.Subject.All {
		return errors.New("desired state subject scope does not match policy evaluation")
	}
	if s.Subject.Kind == policy.TargetKindIP && s.Subject.All && s.PolicyEvaluation.Selection.Target.NormalizedIPAggregation() != s.Subject.NormalizedIPAggregation() {
		return errors.New("desired state subject aggregation does not match policy evaluation")
	}
	if s.Subject.Kind == policy.TargetKindIP && !s.Subject.All && !ipaddr.Equal(s.PolicyEvaluation.Selection.Target.Value, s.Subject.Value) {
		return errors.New("desired state subject value does not match policy evaluation")
	}

	switch s.Mode {
	case DesiredModeLimit:
		if s.PolicyEvaluation.Excluded() {
			return errors.New("limit desired state cannot be built from an excluded policy evaluation")
		}
		if err := s.Limits.Validate(); err != nil {
			return fmt.Errorf("invalid desired limits: %w", err)
		}
		if !sameLimitPolicy(s.Limits, s.PolicyEvaluation.EffectiveLimits) {
			return errors.New("desired state limits do not match policy evaluation")
		}
	case DesiredModeUnlimited:
		if !s.PolicyEvaluation.Excluded() {
			return errors.New("unlimited desired state requires an excluded policy evaluation")
		}
		if s.Subject.Kind != policy.TargetKindIP || s.Subject.All {
			return errors.New("unlimited desired state requires a specific ip subject")
		}
		if s.Limits.HasAny() {
			return errors.New("unlimited desired state cannot define limits")
		}
	}

	return nil
}

// DesiredStateFromEvaluation derives a desired limit state from a session and policy evaluation.
func DesiredStateFromEvaluation(session discovery.Session, evaluation policy.Evaluation) (DesiredState, error) {
	if !evaluation.HasMatch() {
		return DesiredState{}, errors.New("policy evaluation has no matches")
	}
	subject, err := SubjectFromTarget(evaluation.Selection.Target, session)
	if err != nil {
		return DesiredState{}, err
	}

	desired := DesiredState{
		Mode:             DesiredModeLimit,
		Subject:          subject,
		PolicyEvaluation: evaluation,
	}
	if evaluation.Excluded() {
		desired.Mode = DesiredModeUnlimited
	} else {
		if !evaluation.EffectiveLimits.HasAny() {
			return DesiredState{}, errors.New("policy evaluation does not define effective limits")
		}
		desired.Limits = evaluation.EffectiveLimits
	}
	if err := desired.Validate(); err != nil {
		return DesiredState{}, err
	}

	return desired, nil
}

// AppliedState describes limiter state that has already been realized by a future backend.
type AppliedState struct {
	Mode      DesiredMode        `json:"mode,omitempty"`
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
	if !s.Mode.Valid() {
		return fmt.Errorf("invalid applied mode %q", s.Mode)
	}
	switch s.Mode {
	case DesiredModeLimit:
		if err := s.Limits.Validate(); err != nil {
			return fmt.Errorf("invalid applied limits: %w", err)
		}
	case DesiredModeUnlimited:
		if s.Limits.HasAny() {
			return errors.New("unlimited applied state cannot define limits")
		}
	}
	if strings.TrimSpace(s.Driver) == "" {
		return errors.New("applied state requires a driver")
	}

	return nil
}

// MatchesDesired reports whether the applied state already satisfies the desired state.
func (s AppliedState) MatchesDesired(desired DesiredState) bool {
	if !s.Subject.Equal(desired.Subject) || s.Mode != desired.Mode {
		return false
	}
	if desired.Mode == DesiredModeUnlimited {
		return true
	}

	return sameLimitPolicy(s.Limits, desired.Limits)
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
	return left.Runtime.Source == right.Runtime.Source &&
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
