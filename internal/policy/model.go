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
	TargetKindUUID       TargetKind = "uuid"
	TargetKindIP         TargetKind = "ip"
	TargetKindInbound    TargetKind = "inbound"
	TargetKindOutbound   TargetKind = "outbound"
	TargetKindConnection TargetKind = "connection"
)

func (k TargetKind) Valid() bool {
	switch k {
	case TargetKindUUID, TargetKindIP, TargetKindInbound, TargetKindOutbound, TargetKindConnection:
		return true
	default:
		return false
	}
}

// Precedence returns the relative match priority for a target kind.
// Higher values are more specific and therefore win over broader matches.
func (k TargetKind) Precedence() int {
	switch k {
	case TargetKindConnection:
		return 5
	case TargetKindUUID:
		return 4
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
		TargetKindConnection,
		TargetKindUUID,
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
	Kind       TargetKind     `json:"kind"`
	Value      string         `json:"value,omitempty"`
	Connection *ConnectionRef `json:"connection,omitempty"`
}

// Validate checks that a policy target is internally consistent.
func (t Target) Validate() error {
	if !t.Kind.Valid() {
		return fmt.Errorf("invalid target kind %q", t.Kind)
	}

	value := strings.TrimSpace(t.Value)
	switch t.Kind {
	case TargetKindUUID, TargetKindInbound, TargetKindOutbound:
		if value == "" {
			return fmt.Errorf("%s target requires a value", t.Kind)
		}
		if t.Connection != nil {
			return fmt.Errorf("%s target cannot include connection details", t.Kind)
		}
	case TargetKindIP:
		if value == "" {
			return errors.New("ip target requires a value")
		}
		if _, err := ipaddr.Normalize(value); err != nil {
			return fmt.Errorf("invalid ip target value %q", value)
		}
		if t.Connection != nil {
			return errors.New("ip target cannot include connection details")
		}
	case TargetKindConnection:
		if t.Connection == nil {
			return errors.New("connection target requires connection details")
		}
		if value != "" {
			return errors.New("connection target cannot define a generic value")
		}
		if err := t.Connection.Validate(); err != nil {
			return fmt.Errorf("invalid connection reference: %w", err)
		}
	}

	return nil
}

// MatchesSession reports whether the target matches the given session identity.
func (t Target) MatchesSession(session discovery.Session) bool {
	switch t.Kind {
	case TargetKindUUID:
		return strings.EqualFold(strings.TrimSpace(t.Value), strings.TrimSpace(session.Policy.UUID))
	case TargetKindIP:
		return ipaddr.Equal(t.Value, session.Client.IP)
	case TargetKindInbound:
		return strings.TrimSpace(t.Value) == strings.TrimSpace(session.Route.InboundTag)
	case TargetKindOutbound:
		return strings.TrimSpace(t.Value) == strings.TrimSpace(session.Route.OutboundTag)
	case TargetKindConnection:
		return t.Connection != nil && t.Connection.MatchesSession(session)
	default:
		return false
	}
}

// ConnectionRef identifies an individual runtime connection.
type ConnectionRef struct {
	SessionID string                    `json:"session_id"`
	Runtime   *discovery.SessionRuntime `json:"runtime,omitempty"`
}

// Validate checks that a connection reference is internally consistent.
func (r ConnectionRef) Validate() error {
	if strings.TrimSpace(r.SessionID) == "" {
		return errors.New("session_id is required")
	}

	if r.Runtime == nil {
		return errors.New("connection target requires a runtime association")
	}

	if err := r.Runtime.Validate(); err != nil {
		return fmt.Errorf("invalid runtime association: %w", err)
	}

	return nil
}

// MatchesSession reports whether the connection reference matches the given session.
func (r ConnectionRef) MatchesSession(session discovery.Session) bool {
	if strings.TrimSpace(r.SessionID) != strings.TrimSpace(session.ID) {
		return false
	}

	if r.Runtime == nil {
		return true
	}

	return r.Runtime.MatchesTarget(runtimeTargetFromSession(session))
}

func runtimeTargetFromSession(session discovery.Session) discovery.RuntimeTarget {
	target := discovery.RuntimeTarget{
		Source: session.Runtime.Source,
		Identity: discovery.RuntimeIdentity{
			Name: session.Runtime.Name,
		},
	}

	switch session.Runtime.Source {
	case discovery.DiscoverySourceHostProcess:
		target.HostProcess = &discovery.HostProcessCandidate{
			PID: session.Runtime.HostPID,
		}
	case discovery.DiscoverySourceDockerContainer:
		target.DockerContainer = &discovery.DockerContainerCandidate{
			ID: session.Runtime.ContainerID,
		}
	}

	return target
}
