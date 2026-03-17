package discovery

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"sort"
	"strings"
	"time"
)

// UUIDRoutingEvidenceState summarizes whether UUID-linked runtime routing
// evidence is currently ingested, only candidate-capable, partially
// trustworthy, or unavailable.
type UUIDRoutingEvidenceState string

const (
	UUIDRoutingEvidenceStateLive        UUIDRoutingEvidenceState = "live"
	UUIDRoutingEvidenceStateCandidate   UUIDRoutingEvidenceState = "candidate"
	UUIDRoutingEvidenceStateUnavailable UUIDRoutingEvidenceState = "unavailable"
	UUIDRoutingEvidenceStatePartial     UUIDRoutingEvidenceState = "partial"
)

func (s UUIDRoutingEvidenceState) Valid() bool {
	switch s {
	case UUIDRoutingEvidenceStateLive,
		UUIDRoutingEvidenceStateCandidate,
		UUIDRoutingEvidenceStateUnavailable,
		UUIDRoutingEvidenceStatePartial:
		return true
	default:
		return false
	}
}

// UUIDRoutingEvidenceFreshness classifies whether cached UUID-linked routing
// evidence is still current enough to drive later classifier work.
type UUIDRoutingEvidenceFreshness string

const (
	UUIDRoutingEvidenceFreshnessFresh       UUIDRoutingEvidenceFreshness = "fresh"
	UUIDRoutingEvidenceFreshnessStale       UUIDRoutingEvidenceFreshness = "stale"
	UUIDRoutingEvidenceFreshnessCandidate   UUIDRoutingEvidenceFreshness = "candidate"
	UUIDRoutingEvidenceFreshnessUnavailable UUIDRoutingEvidenceFreshness = "unavailable"
	UUIDRoutingEvidenceFreshnessPartial     UUIDRoutingEvidenceFreshness = "partial"
)

func (f UUIDRoutingEvidenceFreshness) Valid() bool {
	switch f {
	case UUIDRoutingEvidenceFreshnessFresh,
		UUIDRoutingEvidenceFreshnessStale,
		UUIDRoutingEvidenceFreshnessCandidate,
		UUIDRoutingEvidenceFreshnessUnavailable,
		UUIDRoutingEvidenceFreshnessPartial:
		return true
	default:
		return false
	}
}

// UUIDRoutingContext captures one runtime-linked routing observation for one
// UUID without assuming that client IP itself is the enforcement identity.
type UUIDRoutingContext struct {
	Runtime      SessionRuntime            `json:"runtime"`
	UUID         string                    `json:"uuid"`
	Network      string                    `json:"network,omitempty"`
	InboundTag   string                    `json:"inbound_tag,omitempty"`
	OutboundTag  string                    `json:"outbound_tag,omitempty"`
	Protocol     string                    `json:"protocol,omitempty"`
	TargetDomain string                    `json:"target_domain,omitempty"`
	SourceIPs    []string                  `json:"source_ips,omitempty"`
	LocalIPs     []string                  `json:"local_ips,omitempty"`
	TargetIPs    []string                  `json:"target_ips,omitempty"`
	SourcePort   int                       `json:"source_port,omitempty"`
	LocalPort    int                       `json:"local_port,omitempty"`
	TargetPort   int                       `json:"target_port,omitempty"`
	Confidence   SessionEvidenceConfidence `json:"confidence"`
	Note         string                    `json:"note,omitempty"`
}

func (c UUIDRoutingContext) Validate() error {
	if err := c.Runtime.Validate(); err != nil {
		return fmt.Errorf("invalid routing evidence runtime: %w", err)
	}
	if normalizeUUIDRoutingEvidenceKey(c.UUID) == "" {
		return errors.New("routing evidence uuid is required")
	}
	if !c.Confidence.Valid() {
		return fmt.Errorf("invalid routing evidence confidence %q", c.Confidence)
	}
	if c.SourcePort < 0 || c.SourcePort > 65535 {
		return errors.New("routing evidence source port must be between 0 and 65535")
	}
	if c.LocalPort < 0 || c.LocalPort > 65535 {
		return errors.New("routing evidence local port must be between 0 and 65535")
	}
	if c.TargetPort < 0 || c.TargetPort > 65535 {
		return errors.New("routing evidence target port must be between 0 and 65535")
	}
	if _, err := normalizeUUIDRoutingIPs(c.SourceIPs); err != nil {
		return fmt.Errorf("invalid routing evidence source ips: %w", err)
	}
	if _, err := normalizeUUIDRoutingIPs(c.LocalIPs); err != nil {
		return fmt.Errorf("invalid routing evidence local ips: %w", err)
	}
	if _, err := normalizeUUIDRoutingIPs(c.TargetIPs); err != nil {
		return fmt.Errorf("invalid routing evidence target ips: %w", err)
	}

	return nil
}

func (c UUIDRoutingContext) Key() string {
	sourceIPs, _ := normalizeUUIDRoutingIPs(c.SourceIPs)
	localIPs, _ := normalizeUUIDRoutingIPs(c.LocalIPs)
	targetIPs, _ := normalizeUUIDRoutingIPs(c.TargetIPs)

	return strings.Join([]string{
		normalizeUUIDRoutingEvidenceKey(c.UUID),
		string(c.Runtime.Source),
		strings.TrimSpace(c.Runtime.Provider),
		strings.TrimSpace(c.Runtime.Name),
		fmt.Sprintf("%d", c.Runtime.HostPID),
		strings.TrimSpace(c.Runtime.ContainerID),
		strings.ToLower(strings.TrimSpace(c.Network)),
		strings.TrimSpace(c.InboundTag),
		strings.TrimSpace(c.OutboundTag),
		strings.ToLower(strings.TrimSpace(c.Protocol)),
		strings.TrimSpace(c.TargetDomain),
		strings.Join(sourceIPs, ","),
		strings.Join(localIPs, ","),
		strings.Join(targetIPs, ","),
		fmt.Sprintf("%d", c.SourcePort),
		fmt.Sprintf("%d", c.LocalPort),
		fmt.Sprintf("%d", c.TargetPort),
	}, "|")
}

// UUIDRoutingEvidenceResult captures the currently known RoutingService-backed
// UUID runtime contexts for one runtime-local UUID.
type UUIDRoutingEvidenceResult struct {
	Provider  string                     `json:"provider"`
	Runtime   SessionRuntime             `json:"runtime"`
	UUID      string                     `json:"uuid"`
	Candidate *UUIDNonIPBackendCandidate `json:"candidate,omitempty"`
	Contexts  []UUIDRoutingContext       `json:"contexts,omitempty"`
	Issues    []SessionEvidenceIssue     `json:"issues,omitempty"`
}

func (r UUIDRoutingEvidenceResult) Validate() error {
	if strings.TrimSpace(r.Provider) == "" {
		return errors.New("uuid routing evidence provider name is required")
	}
	if err := r.Runtime.Validate(); err != nil {
		return fmt.Errorf("invalid uuid routing evidence runtime: %w", err)
	}
	if normalizeUUIDRoutingEvidenceKey(r.UUID) == "" {
		return errors.New("uuid routing evidence uuid is required")
	}
	if r.Candidate != nil {
		if err := r.Candidate.Validate(); err != nil {
			return fmt.Errorf("invalid uuid routing evidence candidate: %w", err)
		}
	}
	for index, context := range r.Contexts {
		if err := context.Validate(); err != nil {
			return fmt.Errorf("invalid routing context at index %d: %w", index, err)
		}
		if !sameEvidenceRuntime(r.Runtime, context.Runtime) {
			return fmt.Errorf("routing context at index %d does not belong to the requested runtime", index)
		}
		if normalizeUUIDRoutingEvidenceKey(context.UUID) != normalizeUUIDRoutingEvidenceKey(r.UUID) {
			return fmt.Errorf("routing context at index %d does not match the requested uuid", index)
		}
	}
	for index, issue := range r.Issues {
		if err := issue.Validate(); err != nil {
			return fmt.Errorf("invalid routing evidence issue at index %d: %w", index, err)
		}
	}

	return nil
}

func (r UUIDRoutingEvidenceResult) State() UUIDRoutingEvidenceState {
	if len(r.Issues) != 0 {
		if len(r.Contexts) != 0 {
			return UUIDRoutingEvidenceStatePartial
		}
		for _, issue := range r.Issues {
			switch issue.Code {
			case SessionEvidenceIssueInsufficient:
				return UUIDRoutingEvidenceStatePartial
			case SessionEvidenceIssueUnavailable, SessionEvidenceIssuePermissionDenied:
				return UUIDRoutingEvidenceStateUnavailable
			}
		}
	}
	if len(r.Contexts) != 0 {
		return UUIDRoutingEvidenceStateLive
	}
	if r.Candidate != nil && r.Candidate.Status == UUIDNonIPBackendStatusCandidate {
		return UUIDRoutingEvidenceStateCandidate
	}

	return UUIDRoutingEvidenceStateUnavailable
}

func (r UUIDRoutingEvidenceResult) IssueSummary() string {
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

// UUIDRoutingEvidenceSnapshot captures one routing-evidence observation and the
// time when it was collected.
type UUIDRoutingEvidenceSnapshot struct {
	Result     UUIDRoutingEvidenceResult `json:"result"`
	ObservedAt time.Time                 `json:"observed_at"`
}

func (s UUIDRoutingEvidenceSnapshot) Validate() error {
	if err := s.Result.Validate(); err != nil {
		return fmt.Errorf("invalid uuid routing evidence result: %w", err)
	}
	if s.ObservedAt.IsZero() {
		return errors.New("uuid routing evidence observation time is required")
	}

	return nil
}

// UUIDRoutingEvidenceAssessment summarizes whether cached routing evidence is
// still current enough for later classifier phases to consume safely.
type UUIDRoutingEvidenceAssessment struct {
	Freshness     UUIDRoutingEvidenceFreshness `json:"freshness"`
	Age           time.Duration                `json:"age,omitempty"`
	Trusted       bool                         `json:"trusted,omitempty"`
	RefreshNeeded bool                         `json:"refresh_needed,omitempty"`
	Reason        string                       `json:"reason"`
}

func (a UUIDRoutingEvidenceAssessment) Validate() error {
	if !a.Freshness.Valid() {
		return fmt.Errorf("invalid uuid routing evidence freshness %q", a.Freshness)
	}
	if a.Age < 0 {
		return errors.New("uuid routing evidence age cannot be negative")
	}
	if strings.TrimSpace(a.Reason) == "" {
		return errors.New("uuid routing evidence assessment reason is required")
	}

	return nil
}

// AssessUUIDRoutingEvidence classifies one cached UUID routing evidence
// snapshot as fresh, stale, candidate-only, unavailable, or partial.
func AssessUUIDRoutingEvidence(snapshot UUIDRoutingEvidenceSnapshot, policy RuntimeEvidencePolicy, now time.Time) (UUIDRoutingEvidenceAssessment, error) {
	if err := snapshot.Validate(); err != nil {
		return UUIDRoutingEvidenceAssessment{}, err
	}
	if err := policy.Validate(); err != nil {
		return UUIDRoutingEvidenceAssessment{}, err
	}
	if now.IsZero() {
		return UUIDRoutingEvidenceAssessment{}, errors.New("uuid routing evidence assessment requires a reference time")
	}
	if snapshot.ObservedAt.After(now) {
		return UUIDRoutingEvidenceAssessment{}, errors.New("uuid routing evidence observation time cannot be in the future")
	}

	assessment := UUIDRoutingEvidenceAssessment{
		Age: now.Sub(snapshot.ObservedAt),
	}

	switch snapshot.Result.State() {
	case UUIDRoutingEvidenceStateLive:
		if assessment.Age <= policy.FreshTTL {
			assessment.Freshness = UUIDRoutingEvidenceFreshnessFresh
			assessment.Trusted = true
			assessment.Reason = "uuid routing evidence is fresh enough to reuse without a refresh"
		} else {
			assessment.Freshness = UUIDRoutingEvidenceFreshnessStale
			assessment.RefreshNeeded = true
			assessment.Reason = "uuid routing evidence is stale and should be refreshed before reuse"
		}
	case UUIDRoutingEvidenceStateCandidate:
		assessment.Freshness = UUIDRoutingEvidenceFreshnessCandidate
		assessment.RefreshNeeded = true
		assessment.Reason = "a safe UUID routing backend candidate exists, but no live routing evidence is currently ingested"
	case UUIDRoutingEvidenceStatePartial:
		assessment.Freshness = UUIDRoutingEvidenceFreshnessPartial
		assessment.RefreshNeeded = true
		assessment.Reason = "uuid routing evidence is only partially trustworthy"
	case UUIDRoutingEvidenceStateUnavailable:
		assessment.Freshness = UUIDRoutingEvidenceFreshnessUnavailable
		assessment.RefreshNeeded = true
		assessment.Reason = "uuid routing evidence is currently unavailable"
	default:
		return UUIDRoutingEvidenceAssessment{}, fmt.Errorf("unsupported uuid routing evidence state %q", snapshot.Result.State())
	}

	if err := assessment.Validate(); err != nil {
		return UUIDRoutingEvidenceAssessment{}, err
	}

	return assessment, nil
}

// UUIDRoutingEvidenceProvider gathers UUID-targeted live routing evidence from
// one source.
type UUIDRoutingEvidenceProvider interface {
	Name() string
	ObserveUUIDRoutingEvidence(ctx context.Context, runtime SessionRuntime, uuid string) (UUIDRoutingEvidenceResult, error)
}

func normalizeUUIDRoutingEvidenceKey(value string) string {
	return strings.ToLower(strings.TrimSpace(value))
}

func normalizeUUIDRoutingIPs(values []string) ([]string, error) {
	if len(values) == 0 {
		return nil, nil
	}

	normalized := make([]string, 0, len(values))
	seen := make(map[string]struct{}, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}

		addr, err := netip.ParseAddr(value)
		if err != nil {
			return nil, fmt.Errorf("invalid ip %q", value)
		}

		canonical := addr.Unmap().String()
		if _, ok := seen[canonical]; ok {
			continue
		}
		seen[canonical] = struct{}{}
		normalized = append(normalized, canonical)
	}
	sort.Strings(normalized)

	return normalized, nil
}
