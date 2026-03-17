package tc

import (
	"errors"
	"fmt"
	"strings"

	"github.com/PdYrust/RayLimit/internal/discovery"
	"github.com/PdYrust/RayLimit/internal/ipaddr"
	"github.com/PdYrust/RayLimit/internal/limiter"
	"github.com/PdYrust/RayLimit/internal/policy"
)

// BindingReadiness reports how directly a logical subject maps to an enforceable
// traffic-classification identity.
type BindingReadiness string

const (
	BindingReadinessReady       BindingReadiness = "ready"
	BindingReadinessPartial     BindingReadiness = "partial"
	BindingReadinessUnavailable BindingReadiness = "unavailable"
)

func (r BindingReadiness) Valid() bool {
	switch r {
	case BindingReadinessReady, BindingReadinessPartial, BindingReadinessUnavailable:
		return true
	default:
		return false
	}
}

// BindingConfidence reports how trustworthy the current binding evidence is.
type BindingConfidence string

const (
	BindingConfidenceHigh   BindingConfidence = "high"
	BindingConfidenceMedium BindingConfidence = "medium"
	BindingConfidenceLow    BindingConfidence = "low"
)

func (c BindingConfidence) Valid() bool {
	switch c {
	case BindingConfidenceHigh, BindingConfidenceMedium, BindingConfidenceLow:
		return true
	default:
		return false
	}
}

// IdentityKind identifies the traffic-facing key a future classifier would need.
type IdentityKind string

const (
	IdentityKindSession     IdentityKind = "session_id"
	IdentityKindClientIP    IdentityKind = "client_ip"
	IdentityKindInbound     IdentityKind = "inbound_tag"
	IdentityKindOutbound    IdentityKind = "outbound_tag"
	IdentityKindUUIDRouting IdentityKind = "uuid_routing_context"
)

func (k IdentityKind) Valid() bool {
	switch k {
	case IdentityKindSession, IdentityKindClientIP, IdentityKindInbound, IdentityKindOutbound, IdentityKindUUIDRouting:
		return true
	default:
		return false
	}
}

// TrafficIdentity captures the classifier-facing identity a future tc backend
// would need in order to bind traffic to a logical subject.
type TrafficIdentity struct {
	Kind  IdentityKind `json:"kind"`
	Value string       `json:"value"`
}

func (i TrafficIdentity) Validate() error {
	if !i.Kind.Valid() {
		return fmt.Errorf("invalid traffic identity kind %q", i.Kind)
	}
	if strings.TrimSpace(i.Value) == "" {
		return errors.New("traffic identity value is required")
	}

	return nil
}

// Binding describes how a logical limiter subject maps to a future
// tc-enforceable traffic identity.
type Binding struct {
	RequestedSubject limiter.Subject   `json:"requested_subject"`
	EffectiveSubject limiter.Subject   `json:"effective_subject"`
	Identity         *TrafficIdentity  `json:"identity,omitempty"`
	Readiness        BindingReadiness  `json:"readiness"`
	Confidence       BindingConfidence `json:"confidence"`
	Reason           string            `json:"reason,omitempty"`
}

func (b Binding) Validate() error {
	if err := b.RequestedSubject.Validate(); err != nil {
		return fmt.Errorf("invalid requested subject: %w", err)
	}
	if err := b.EffectiveSubject.Validate(); err != nil {
		return fmt.Errorf("invalid effective subject: %w", err)
	}
	if !b.Readiness.Valid() {
		return fmt.Errorf("invalid binding readiness %q", b.Readiness)
	}
	if !b.Confidence.Valid() {
		return fmt.Errorf("invalid binding confidence %q", b.Confidence)
	}
	if b.Identity != nil {
		if err := b.Identity.Validate(); err != nil {
			return fmt.Errorf("invalid traffic identity: %w", err)
		}
	}

	if b.RequestedSubject.Kind == policy.TargetKindUUID && b.EffectiveSubject.Kind == policy.TargetKindConnection {
		if !sameRuntimeBinding(b.RequestedSubject.Binding.Runtime, b.EffectiveSubject.Binding.Runtime) {
			return errors.New("uuid bridge requires the requested and effective runtime bindings to match")
		}
		if b.Identity == nil || b.Identity.Kind != IdentityKindSession {
			return errors.New("uuid bridge requires a session identity")
		}
		return nil
	}

	if !b.RequestedSubject.Equal(b.EffectiveSubject) {
		return errors.New("requested and effective subjects must match unless an explicit uuid bridge is used")
	}

	return nil
}

// BindSubject maps a runtime-scoped limiter subject to the current best-known
// traffic identity without claiming that real classification is already solved.
func BindSubject(subject limiter.Subject) (Binding, error) {
	if err := subject.Validate(); err != nil {
		return Binding{}, err
	}

	binding := Binding{
		RequestedSubject: subject,
		EffectiveSubject: subject,
	}

	switch subject.Kind {
	case policy.TargetKindConnection:
		binding.Identity = &TrafficIdentity{
			Kind:  IdentityKindSession,
			Value: strings.TrimSpace(subject.Binding.SessionID),
		}
		binding.Readiness = BindingReadinessPartial
		binding.Confidence = BindingConfidenceMedium
		binding.Reason = "connection targets currently remain class-oriented; tc can plan class shaping and clean up observed class state, but real apply execution requires a trustworthy runtime-aware traffic classifier"
	case policy.TargetKindIP:
		identityValue, err := ipaddr.Normalize(subject.Value)
		if err != nil {
			return Binding{}, err
		}
		binding.Identity = &TrafficIdentity{
			Kind:  IdentityKindClientIP,
			Value: identityValue,
		}
		binding.Readiness = BindingReadinessReady
		binding.Confidence = BindingConfidenceHigh
	case policy.TargetKindInbound:
		binding.Identity = &TrafficIdentity{
			Kind:  IdentityKindInbound,
			Value: strings.TrimSpace(subject.Value),
		}
		binding.Readiness = BindingReadinessPartial
		binding.Confidence = BindingConfidenceMedium
		binding.Reason = "inbound targets require trustworthy runtime-aware traffic marking; when readable Xray config proves one concrete TCP listener for the selected inbound tag, RayLimit can attach that shared class concretely through nftables marking and tc fw classification"
	case policy.TargetKindOutbound:
		binding.Identity = &TrafficIdentity{
			Kind:  IdentityKindOutbound,
			Value: strings.TrimSpace(subject.Value),
		}
		binding.Readiness = BindingReadinessPartial
		binding.Confidence = BindingConfidenceMedium
		binding.Reason = "outbound targets require a trustworthy runtime-owned socket mark; when readable Xray config proves one unique non-zero outbound socket mark without proxy or dialer-proxy indirection, RayLimit can attach that shared class concretely through nftables output matching and tc fw classification"
	case policy.TargetKindUUID:
		binding.Readiness = BindingReadinessUnavailable
		binding.Confidence = BindingConfidenceLow
		binding.Reason = "uuid targets are policy identities and are not directly traffic-bindable without session correlation"
	default:
		return Binding{}, fmt.Errorf("unsupported subject kind %q", subject.Kind)
	}

	if err := binding.Validate(); err != nil {
		return Binding{}, err
	}

	return binding, nil
}

// BindUUIDSessionBridge models the trustworthy single-session case where a UUID
// target has already been correlated to one concrete runtime session.
func BindUUIDSessionBridge(requested limiter.Subject, session discovery.Session) (Binding, error) {
	if err := requested.Validate(); err != nil {
		return Binding{}, err
	}
	if requested.Kind != policy.TargetKindUUID {
		return Binding{}, errors.New("uuid bridge requires a uuid requested subject")
	}
	if err := session.Validate(); err != nil {
		return Binding{}, fmt.Errorf("invalid session: %w", err)
	}
	if !sameRuntimeBinding(requested.Binding.Runtime, session.Runtime) {
		return Binding{}, errors.New("uuid bridge session does not match the requested runtime binding")
	}
	if !strings.EqualFold(strings.TrimSpace(requested.Value), strings.TrimSpace(session.Policy.UUID)) {
		return Binding{}, errors.New("uuid bridge session does not match the requested uuid")
	}

	effective, err := limiter.SubjectFromSession(policy.TargetKindConnection, session)
	if err != nil {
		return Binding{}, err
	}

	binding := Binding{
		RequestedSubject: requested,
		EffectiveSubject: effective,
		Identity: &TrafficIdentity{
			Kind:  IdentityKindSession,
			Value: strings.TrimSpace(session.ID),
		},
		Readiness:  BindingReadinessPartial,
		Confidence: BindingConfidenceMedium,
		Reason:     "uuid became traffic-bindable through an exact single-session bridge and still requires a runtime-aware traffic classifier",
	}

	if err := binding.Validate(); err != nil {
		return Binding{}, err
	}

	return binding, nil
}

func sameRuntimeBinding(left discovery.SessionRuntime, right discovery.SessionRuntime) bool {
	return left.Source == right.Source &&
		strings.TrimSpace(left.Provider) == strings.TrimSpace(right.Provider) &&
		strings.TrimSpace(left.Name) == strings.TrimSpace(right.Name) &&
		left.HostPID == right.HostPID &&
		strings.TrimSpace(left.ContainerID) == strings.TrimSpace(right.ContainerID)
}
