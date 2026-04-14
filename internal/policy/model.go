package policy

import (
	"errors"
	"fmt"
	"strings"

	"github.com/PdYrust/RayLimit/internal/discovery"
	"github.com/PdYrust/RayLimit/internal/ipaddr"
)

// TargetKind identifies the identity dimension a policy applies to.
type TargetKind string

const (
	TargetKindIP       TargetKind = "ip"
	TargetKindInbound  TargetKind = "inbound"
	TargetKindOutbound TargetKind = "outbound"
)

func (k TargetKind) Valid() bool {
	switch k {
	case TargetKindIP, TargetKindInbound, TargetKindOutbound:
		return true
	default:
		return false
	}
}

// Precedence returns the relative match priority for a target kind.
// Higher values are more specific and therefore win over broader matches.
func (k TargetKind) Precedence() int {
	switch k {
	case TargetKindIP:
		return 3
	case TargetKindInbound:
		return 2
	case TargetKindOutbound:
		return 1
	default:
		return 0
	}
}

// TargetKindPrecedenceOrder returns limiter target kinds from highest to lowest
// precedence for deterministic coexistence and reporting.
func TargetKindPrecedenceOrder() []TargetKind {
	return []TargetKind{
		TargetKindIP,
		TargetKindInbound,
		TargetKindOutbound,
	}
}

// DescribeTargetKindPrecedence returns the operator-facing precedence order used
// when multiple limiter target kinds match the same session.
func DescribeTargetKindPrecedence() string {
	parts := make([]string, 0, len(TargetKindPrecedenceOrder()))
	for _, kind := range TargetKindPrecedenceOrder() {
		parts = append(parts, string(kind))
	}

	return strings.Join(parts, " > ")
}

// Effect identifies how a policy is intended to behave.
type Effect string

const (
	EffectLimit   Effect = "limit"
	EffectExclude Effect = "exclude"
)

func (e Effect) Valid() bool {
	switch e {
	case "", EffectLimit, EffectExclude:
		return true
	default:
		return false
	}
}

func (e Effect) normalized() Effect {
	if e == "" {
		return EffectLimit
	}

	return e
}

// Policy defines a limit or future exclusion rule for a specific target.
type Policy struct {
	Name   string      `json:"name,omitempty"`
	Effect Effect      `json:"effect,omitempty"`
	Target Target      `json:"target"`
	Limits LimitPolicy `json:"limits,omitempty"`
}

// Validate checks that a policy definition is internally consistent.
func (p Policy) Validate() error {
	if p.Name != "" && strings.TrimSpace(p.Name) == "" {
		return errors.New("policy name cannot be blank")
	}

	if !p.Effect.Valid() {
		return fmt.Errorf("invalid policy effect %q", p.Effect)
	}

	if err := p.Target.Validate(); err != nil {
		return fmt.Errorf("invalid policy target: %w", err)
	}

	switch p.Effect.normalized() {
	case EffectLimit:
		if err := p.Limits.Validate(); err != nil {
			return fmt.Errorf("invalid policy limits: %w", err)
		}
	case EffectExclude:
		if p.Limits.HasAny() {
			return errors.New("exclude policy cannot define limits")
		}
	}

	return nil
}

// Selection captures the policies that survive matching and precedence resolution.
type Selection struct {
	Kind       TargetKind `json:"kind,omitempty"`
	Precedence int        `json:"precedence,omitempty"`
	Target     Target     `json:"target,omitempty"`
	Excludes   []Policy   `json:"excludes,omitempty"`
	Limits     []Policy   `json:"limits,omitempty"`
}

// HasMatch reports whether any policy matched.
func (s Selection) HasMatch() bool {
	return len(s.Excludes) != 0 || len(s.Limits) != 0
}

// Excluded reports whether matching policies produced an exclusion decision.
func (s Selection) Excluded() bool {
	return len(s.Excludes) != 0
}

// Resolve matches policies against a session and applies target-kind precedence.
// Only the highest-precedence matching target kind is retained.
// Within that precedence, exclude policies short-circuit limit policies.
func Resolve(policies []Policy, session discovery.Session) (Selection, error) {
	_, selection, _, err := matchAndSelect(policies, session)
	if err != nil {
		return Selection{}, err
	}

	return selection, nil
}

// LimitPolicy defines upload and download limits for a policy.
type LimitPolicy struct {
	Upload   *RateLimit `json:"upload,omitempty"`
	Download *RateLimit `json:"download,omitempty"`
}

// Validate checks that a limit policy is internally consistent.
func (l LimitPolicy) Validate() error {
	if !l.HasAny() {
		return errors.New("at least one direction limit must be defined")
	}

	if l.Upload != nil {
		if err := l.Upload.Validate(); err != nil {
			return fmt.Errorf("invalid upload limit: %w", err)
		}
	}

	if l.Download != nil {
		if err := l.Download.Validate(); err != nil {
			return fmt.Errorf("invalid download limit: %w", err)
		}
	}

	return nil
}

// HasAny reports whether either upload or download is defined.
func (l LimitPolicy) HasAny() bool {
	return l.Upload != nil || l.Download != nil
}

// RateLimit defines a directional transfer rate in bytes per second.
type RateLimit struct {
	BytesPerSecond int64 `json:"bytes_per_second"`
}

// Validate checks that a rate limit is internally consistent.
func (r RateLimit) Validate() error {
	if r.BytesPerSecond <= 0 {
		return errors.New("bytes_per_second must be greater than zero")
	}

	return nil
}

// Target identifies what a policy should match.
type Target struct {
	Kind  TargetKind `json:"kind"`
	All   bool       `json:"all,omitempty"`
	Value string     `json:"value,omitempty"`
}

// Validate checks that a policy target is internally consistent.
func (t Target) Validate() error {
	if !t.Kind.Valid() {
		return fmt.Errorf("invalid target kind %q", t.Kind)
	}

	value := strings.TrimSpace(t.Value)
	switch t.Kind {
	case TargetKindInbound, TargetKindOutbound:
		if t.All {
			return fmt.Errorf("%s target cannot use all", t.Kind)
		}
		if value == "" {
			return fmt.Errorf("%s target requires a value", t.Kind)
		}
	case TargetKindIP:
		switch {
		case t.All && value != "":
			return errors.New("ip target cannot combine all with a specific value")
		case !t.All && value == "":
			return errors.New("ip target requires a value")
		case t.All:
			return nil
		}
		if _, err := ipaddr.Normalize(value); err != nil {
			return fmt.Errorf("invalid ip target value %q", value)
		}
	}

	return nil
}

// MatchesSession reports whether the target matches the given session identity.
func (t Target) MatchesSession(session discovery.Session) bool {
	switch t.Kind {
	case TargetKindIP:
		if t.All {
			return true
		}
		return ipaddr.Equal(t.Value, session.Client.IP)
	case TargetKindInbound:
		return strings.TrimSpace(t.Value) == strings.TrimSpace(session.Route.InboundTag)
	case TargetKindOutbound:
		return strings.TrimSpace(t.Value) == strings.TrimSpace(session.Route.OutboundTag)
	default:
		return false
	}
}

func (t Target) specificity() int {
	switch t.Kind {
	case TargetKindIP:
		if t.All {
			return 1
		}
		if strings.TrimSpace(t.Value) != "" {
			return 2
		}
	case TargetKindInbound, TargetKindOutbound:
		if strings.TrimSpace(t.Value) != "" {
			return 1
		}
	}

	return 0
}
