package limiter

import (
	"errors"
	"fmt"
	"strings"
)

// DecisionKind identifies the next safe limiter action implied by reconciliation.
type DecisionKind string

const (
	DecisionNoOp    DecisionKind = "no_op"
	DecisionApply   DecisionKind = "apply"
	DecisionReplace DecisionKind = "replace"
	DecisionRemove  DecisionKind = "remove"
)

func (k DecisionKind) Valid() bool {
	switch k {
	case DecisionNoOp, DecisionApply, DecisionReplace, DecisionRemove:
		return true
	default:
		return false
	}
}

// Decision captures the outcome of comparing desired limiter state with observed applied state.
type Decision struct {
	Kind    DecisionKind   `json:"kind"`
	Subject *Subject       `json:"subject,omitempty"`
	Desired *DesiredState  `json:"desired,omitempty"`
	Applied []AppliedState `json:"applied,omitempty"`
	Reason  string         `json:"reason"`
}

// Validate checks that a reconcile decision is internally consistent.
func (d Decision) Validate() error {
	if !d.Kind.Valid() {
		return fmt.Errorf("invalid decision kind %q", d.Kind)
	}
	if strings.TrimSpace(d.Reason) == "" {
		return errors.New("decision reason is required")
	}

	if d.Desired != nil {
		if err := d.Desired.Validate(); err != nil {
			return fmt.Errorf("invalid desired state: %w", err)
		}
	}

	var observed *Subject
	for index, applied := range d.Applied {
		if err := applied.Validate(); err != nil {
			return fmt.Errorf("invalid applied state at index %d: %w", index, err)
		}
		if observed == nil {
			copy := applied.Subject
			observed = &copy
			continue
		}
		if !applied.Subject.Equal(*observed) {
			return fmt.Errorf("applied state at index %d does not match the decision subject", index)
		}
	}

	if d.Subject != nil {
		if err := d.Subject.Validate(); err != nil {
			return fmt.Errorf("invalid decision subject: %w", err)
		}
		if d.Desired != nil && !d.Desired.Subject.Equal(*d.Subject) {
			return errors.New("desired state does not match the decision subject")
		}
		if observed != nil && !observed.Equal(*d.Subject) {
			return errors.New("applied state does not match the decision subject")
		}
	} else {
		if d.Desired != nil || observed != nil {
			return errors.New("decision subject is required when desired or applied state exists")
		}
	}

	switch d.Kind {
	case DecisionNoOp:
		return nil
	case DecisionApply:
		if d.Subject == nil || d.Desired == nil {
			return errors.New("apply decision requires a subject and desired state")
		}
		if len(d.Applied) != 0 {
			return errors.New("apply decision cannot include applied state")
		}
	case DecisionReplace:
		if d.Subject == nil || d.Desired == nil {
			return errors.New("replace decision requires a subject and desired state")
		}
		if len(d.Applied) == 0 {
			return errors.New("replace decision requires applied state")
		}
	case DecisionRemove:
		if d.Subject == nil {
			return errors.New("remove decision requires a subject")
		}
		if d.Desired != nil {
			return errors.New("remove decision cannot include a desired state")
		}
	}

	return nil
}

// Action converts the decision into the next limiter action, if any.
func (d Decision) Action() (*Action, error) {
	if err := d.Validate(); err != nil {
		return nil, err
	}

	switch d.Kind {
	case DecisionNoOp:
		return nil, nil
	case DecisionApply:
		action := Action{
			Kind:    ActionApply,
			Subject: *d.Subject,
			Desired: cloneDesiredState(d.Desired),
		}
		if err := action.Validate(); err != nil {
			return nil, err
		}
		return &action, nil
	case DecisionReplace:
		action := Action{
			Kind:    ActionReconcile,
			Subject: *d.Subject,
			Desired: cloneDesiredState(d.Desired),
			Applied: cloneAppliedStates(d.Applied),
		}
		if err := action.Validate(); err != nil {
			return nil, err
		}
		return &action, nil
	case DecisionRemove:
		action := Action{
			Kind:    ActionRemove,
			Subject: *d.Subject,
			Applied: cloneAppliedStates(d.Applied),
		}
		if err := action.Validate(); err != nil {
			return nil, err
		}
		return &action, nil
	default:
		return nil, fmt.Errorf("unsupported decision kind %q", d.Kind)
	}
}

// Reconciler compares desired limiter state against observed applied state.
type Reconciler struct{}

// Decide produces an explicit next-step decision for apply, replace, remove, or no-op behavior.
func (Reconciler) Decide(desired *DesiredState, applied []AppliedState) (Decision, error) {
	subject, err := reconcileSubject(desired, applied)
	if err != nil {
		return Decision{}, err
	}

	switch {
	case desired == nil && len(applied) == 0:
		return Decision{
			Kind:   DecisionNoOp,
			Reason: "no desired or applied state was provided",
		}, nil
	case desired == nil:
		return newDecision(
			DecisionRemove,
			&subject,
			nil,
			applied,
			"applied state exists without a desired state",
		)
	case len(applied) == 0:
		return newDecision(
			DecisionApply,
			&subject,
			desired,
			nil,
			"no applied state was observed",
		)
	case len(applied) == 1 && applied[0].MatchesDesired(*desired):
		return newDecision(
			DecisionNoOp,
			&subject,
			desired,
			applied,
			"applied state already matches the desired state",
		)
	default:
		reason := "observed applied state differs from the desired state"
		if len(applied) > 1 {
			reason = "multiple applied states were observed for the same subject"
		}

		return newDecision(
			DecisionReplace,
			&subject,
			desired,
			applied,
			reason,
		)
	}
}

func reconcileSubject(desired *DesiredState, applied []AppliedState) (Subject, error) {
	if desired != nil {
		if err := desired.Validate(); err != nil {
			return Subject{}, fmt.Errorf("invalid desired state: %w", err)
		}
	}

	var subject Subject
	if desired != nil {
		subject = desired.Subject
	}

	for index, state := range applied {
		if err := state.Validate(); err != nil {
			return Subject{}, fmt.Errorf("invalid applied state at index %d: %w", index, err)
		}

		switch {
		case desired == nil && index == 0:
			subject = state.Subject
		case !state.Subject.Equal(subject):
			return Subject{}, fmt.Errorf("applied state at index %d does not match the reconcile subject", index)
		}
	}

	return subject, nil
}

func newDecision(kind DecisionKind, subject *Subject, desired *DesiredState, applied []AppliedState, reason string) (Decision, error) {
	decision := Decision{
		Kind:    kind,
		Subject: cloneSubject(subject),
		Desired: cloneDesiredState(desired),
		Applied: cloneAppliedStates(applied),
		Reason:  reason,
	}
	if err := decision.Validate(); err != nil {
		return Decision{}, err
	}

	return decision, nil
}

func cloneSubject(subject *Subject) *Subject {
	if subject == nil {
		return nil
	}

	copy := *subject
	return &copy
}

func cloneDesiredState(desired *DesiredState) *DesiredState {
	if desired == nil {
		return nil
	}

	copy := *desired
	return &copy
}

func cloneAppliedStates(applied []AppliedState) []AppliedState {
	if len(applied) == 0 {
		return nil
	}

	cloned := make([]AppliedState, len(applied))
	copy(cloned, applied)
	return cloned
}
