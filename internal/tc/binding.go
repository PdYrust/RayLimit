package tc

import (
	"errors"
	"fmt"
	"strings"

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
	IdentityKindClientIP    IdentityKind = "client_ip"
	IdentityKindAllClientIP IdentityKind = "all_client_ips"
	IdentityKindInbound     IdentityKind = "inbound_tag"
	IdentityKindOutbound    IdentityKind = "outbound_tag"
)

func (k IdentityKind) Valid() bool {
	switch k {
	case IdentityKindClientIP, IdentityKindAllClientIP, IdentityKindInbound, IdentityKindOutbound:
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
	if i.Kind == IdentityKindAllClientIP {
		return nil
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

	if !b.RequestedSubject.Equal(b.EffectiveSubject) {
		return errors.New("requested and effective subjects must match")
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
	case policy.TargetKindIP:
		if subject.All {
			binding.Identity = &TrafficIdentity{
				Kind: IdentityKindAllClientIP,
			}
			binding.Readiness = BindingReadinessReady
			binding.Confidence = BindingConfidenceHigh
			break
		}
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
	default:
		return Binding{}, fmt.Errorf("unsupported subject kind %q", subject.Kind)
	}

	if err := binding.Validate(); err != nil {
		return Binding{}, err
	}

	return binding, nil
}
