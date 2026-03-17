package tc

import (
	"errors"
	"fmt"
	"hash/fnv"
	"net/netip"
	"sort"
	"strings"

	"github.com/PdYrust/RayLimit/internal/correlation"
	"github.com/PdYrust/RayLimit/internal/discovery"
	"github.com/PdYrust/RayLimit/internal/limiter"
	"github.com/PdYrust/RayLimit/internal/policy"
)

// AggregateIdentityKind identifies a future shared-group traffic-shaping key.
type AggregateIdentityKind string

const (
	AggregateIdentityKindUUIDRuntimeGroup AggregateIdentityKind = "uuid_runtime_group"
)

func (k AggregateIdentityKind) Valid() bool {
	switch k {
	case AggregateIdentityKindUUIDRuntimeGroup:
		return true
	default:
		return false
	}
}

// AggregateIdentity captures the stable shaping identity for one shared UUID
// aggregate group on one selected runtime.
type AggregateIdentity struct {
	Kind  AggregateIdentityKind `json:"kind"`
	Value string                `json:"value"`
}

func (i AggregateIdentity) Validate() error {
	if !i.Kind.Valid() {
		return fmt.Errorf("invalid aggregate identity kind %q", i.Kind)
	}
	if strings.TrimSpace(i.Value) == "" {
		return errors.New("aggregate identity value is required")
	}

	return nil
}

// UUIDAggregateBinding describes how one runtime-local UUID aggregate group maps
// to one shared tc shaping identity. This is distinct from the current per-session
// UUID bridge and fan-out execution path.
type UUIDAggregateBinding struct {
	Subject             correlation.UUIDAggregateSubject    `json:"subject"`
	Membership          correlation.UUIDAggregateMembership `json:"membership"`
	Identity            AggregateIdentity                   `json:"identity"`
	ShapingReadiness    BindingReadiness                    `json:"shaping_readiness"`
	AttachmentReadiness BindingReadiness                    `json:"attachment_readiness"`
	Confidence          BindingConfidence                   `json:"confidence"`
	Reason              string                              `json:"reason,omitempty"`
}

func (b UUIDAggregateBinding) Validate() error {
	if err := b.Subject.Validate(); err != nil {
		return fmt.Errorf("invalid aggregate subject: %w", err)
	}
	if err := b.Membership.Validate(); err != nil {
		return fmt.Errorf("invalid aggregate membership: %w", err)
	}
	if b.Subject.Key() != b.Membership.Subject.Key() {
		return errors.New("aggregate binding subject does not match aggregate membership subject")
	}
	if err := b.Identity.Validate(); err != nil {
		return fmt.Errorf("invalid aggregate identity: %w", err)
	}
	if !b.ShapingReadiness.Valid() {
		return fmt.Errorf("invalid aggregate shaping readiness %q", b.ShapingReadiness)
	}
	if !b.AttachmentReadiness.Valid() {
		return fmt.Errorf("invalid aggregate attachment readiness %q", b.AttachmentReadiness)
	}
	if !b.Confidence.Valid() {
		return fmt.Errorf("invalid aggregate binding confidence %q", b.Confidence)
	}
	if b.Membership.MemberCount() == 0 && b.AttachmentReadiness == BindingReadinessReady {
		return errors.New("zero-member aggregate binding cannot report ready attachment state")
	}

	return nil
}

// BindUUIDAggregate maps one runtime-local UUID aggregate membership into a
// stable shared shaping identity while keeping the narrower concrete
// attachability gate explicit.
func BindUUIDAggregate(membership correlation.UUIDAggregateMembership) (UUIDAggregateBinding, error) {
	if err := membership.Validate(); err != nil {
		return UUIDAggregateBinding{}, err
	}

	binding := UUIDAggregateBinding{
		Subject:    membership.Subject,
		Membership: membership,
		Identity: AggregateIdentity{
			Kind:  AggregateIdentityKindUUIDRuntimeGroup,
			Value: membership.Subject.Key(),
		},
		ShapingReadiness: BindingReadinessReady,
		Confidence:       BindingConfidenceHigh,
	}

	switch membership.Cardinality() {
	case correlation.UUIDAggregateCardinalityZero:
		binding.AttachmentReadiness = BindingReadinessUnavailable
		binding.Confidence = BindingConfidenceHigh
		binding.Reason = "aggregate uuid shaping identity is known, but no live members are currently attached"
	case correlation.UUIDAggregateCardinalitySingle, correlation.UUIDAggregateCardinalityMultiple:
		binding.AttachmentReadiness = BindingReadinessPartial
		binding.Confidence = BindingConfidenceMedium
		binding.Reason = "aggregate uuid shaping identity is deterministic and member attachment identities can be derived; concrete shared-class execution currently requires either attachable client-ip evidence for every live member or fresh exact-user RoutingService socket tuples in the current safe scope"
	default:
		return UUIDAggregateBinding{}, fmt.Errorf("unsupported aggregate cardinality %q", membership.Cardinality())
	}

	if err := binding.Validate(); err != nil {
		return UUIDAggregateBinding{}, err
	}

	return binding, nil
}

// UUIDAggregateMemberAttachment describes how one live aggregate member maps to
// one shared runtime-local UUID class identity before the narrower concrete
// attachability gate is applied.
type UUIDAggregateMemberAttachment struct {
	Member           correlation.UUIDAggregateMember `json:"member"`
	EffectiveSubject limiter.Subject                 `json:"effective_subject"`
	Identity         TrafficIdentity                 `json:"identity"`
	AggregateClassID string                          `json:"aggregate_class_id"`
	Readiness        BindingReadiness                `json:"readiness"`
	Confidence       BindingConfidence               `json:"confidence"`
	Reason           string                          `json:"reason,omitempty"`
}

func (a UUIDAggregateMemberAttachment) Validate() error {
	if err := a.Member.Validate(); err != nil {
		return fmt.Errorf("invalid aggregate member attachment member: %w", err)
	}
	if err := a.EffectiveSubject.Validate(); err != nil {
		return fmt.Errorf("invalid aggregate member attachment subject: %w", err)
	}
	if a.EffectiveSubject.Kind != policy.TargetKindConnection {
		return errors.New("aggregate member attachment requires a connection-scoped effective subject")
	}
	if strings.TrimSpace(a.EffectiveSubject.Binding.SessionID) != strings.TrimSpace(a.Member.Session.ID) {
		return errors.New("aggregate member attachment subject does not match the member session id")
	}
	if !sameRuntimeBinding(a.EffectiveSubject.Binding.Runtime, a.Member.Session.Runtime) {
		return errors.New("aggregate member attachment subject does not match the member runtime")
	}
	if err := a.Identity.Validate(); err != nil {
		return fmt.Errorf("invalid aggregate member attachment identity: %w", err)
	}
	if a.Identity.Kind != IdentityKindSession {
		return errors.New("aggregate member attachment currently requires a session identity")
	}
	if strings.TrimSpace(a.Identity.Value) != strings.TrimSpace(a.Member.Session.ID) {
		return errors.New("aggregate member attachment identity does not match the member session id")
	}
	rootHandle, err := rootHandleFromClassID(a.AggregateClassID)
	if err != nil {
		return err
	}
	if err := validateClassID(strings.TrimSpace(a.AggregateClassID), rootHandle); err != nil {
		return err
	}
	if !a.Readiness.Valid() {
		return fmt.Errorf("invalid aggregate member attachment readiness %q", a.Readiness)
	}
	if !a.Confidence.Valid() {
		return fmt.Errorf("invalid aggregate member attachment confidence %q", a.Confidence)
	}

	return nil
}

func (a UUIDAggregateMemberAttachment) Key() string {
	return strings.Join([]string{
		a.Member.Key(),
		strings.TrimSpace(a.AggregateClassID),
	}, "|")
}

// UUIDAggregateAttachmentSet captures the current member-to-shared-class
// attachment intent for one runtime-local aggregate UUID subject.
type UUIDAggregateAttachmentSet struct {
	Members    []UUIDAggregateMemberAttachment `json:"members,omitempty"`
	Readiness  BindingReadiness                `json:"readiness"`
	Confidence BindingConfidence               `json:"confidence"`
	Reason     string                          `json:"reason,omitempty"`
}

func (s UUIDAggregateAttachmentSet) Validate() error {
	if !s.Readiness.Valid() {
		return fmt.Errorf("invalid aggregate attachment readiness %q", s.Readiness)
	}
	if !s.Confidence.Valid() {
		return fmt.Errorf("invalid aggregate attachment confidence %q", s.Confidence)
	}
	if len(s.Members) == 0 {
		if s.Readiness == BindingReadinessReady {
			return errors.New("empty aggregate attachment set cannot report ready attachment state")
		}
		return nil
	}

	seen := make(map[string]struct{}, len(s.Members))
	classID := strings.TrimSpace(s.Members[0].AggregateClassID)
	for index, member := range s.Members {
		if err := member.Validate(); err != nil {
			return fmt.Errorf("invalid aggregate attachment member at index %d: %w", index, err)
		}
		if strings.TrimSpace(member.AggregateClassID) != classID {
			return errors.New("aggregate attachment set members must share one aggregate class id")
		}
		key := member.Key()
		if _, ok := seen[key]; ok {
			return fmt.Errorf("duplicate aggregate attachment member %q", strings.TrimSpace(member.Member.Session.ID))
		}
		seen[key] = struct{}{}
	}

	return nil
}

// BuildUUIDAggregateAttachmentSet derives one stable member-attachment view for
// a runtime-local aggregate membership and shared class identity.
func BuildUUIDAggregateAttachmentSet(membership correlation.UUIDAggregateMembership, classID string) (UUIDAggregateAttachmentSet, error) {
	if err := membership.Validate(); err != nil {
		return UUIDAggregateAttachmentSet{}, err
	}
	rootHandle, err := rootHandleFromClassID(classID)
	if err != nil {
		return UUIDAggregateAttachmentSet{}, err
	}
	if err := validateClassID(strings.TrimSpace(classID), rootHandle); err != nil {
		return UUIDAggregateAttachmentSet{}, err
	}

	set := UUIDAggregateAttachmentSet{
		Members:    make([]UUIDAggregateMemberAttachment, 0, len(membership.Members)),
		Readiness:  BindingReadinessUnavailable,
		Confidence: BindingConfidenceHigh,
		Reason:     "aggregate uuid group has no live members to attach to the shared class",
	}
	if membership.MemberCount() == 0 {
		if err := set.Validate(); err != nil {
			return UUIDAggregateAttachmentSet{}, err
		}
		return set, nil
	}

	for index, member := range membership.Members {
		subject, err := limiter.SubjectFromSession(policy.TargetKindConnection, member.Session)
		if err != nil {
			return UUIDAggregateAttachmentSet{}, fmt.Errorf("invalid aggregate attachment member at index %d: %w", index, err)
		}

		attachment := UUIDAggregateMemberAttachment{
			Member:           member,
			EffectiveSubject: subject,
			Identity: TrafficIdentity{
				Kind:  IdentityKindSession,
				Value: strings.TrimSpace(member.Session.ID),
			},
			AggregateClassID: strings.TrimSpace(classID),
			Readiness:        BindingReadinessPartial,
			Confidence:       BindingConfidenceMedium,
			Reason:           "member attachment identity is known; concrete shared-class execution still requires either attachable client-ip evidence or fresh exact-user RoutingService socket tuples for this backend scope",
		}
		if err := attachment.Validate(); err != nil {
			return UUIDAggregateAttachmentSet{}, fmt.Errorf("invalid aggregate attachment member at index %d: %w", index, err)
		}
		set.Members = append(set.Members, attachment)
	}

	set.Readiness = BindingReadinessPartial
	set.Confidence = BindingConfidenceMedium
	set.Reason = "member attachment identities are derived from live sessions; concrete shared-class execution currently requires either attachable client-ip evidence for every live member or fresh exact-user RoutingService socket tuples in the current safe scope"
	if err := set.Validate(); err != nil {
		return UUIDAggregateAttachmentSet{}, err
	}

	return set, nil
}

// UUIDAggregateMemberAttachabilityStatus describes whether one live UUID member
// currently has concrete client-ip evidence that the shared aggregate backend
// can safely attach.
type UUIDAggregateMemberAttachabilityStatus string

const (
	UUIDAggregateMemberAttachabilityAttachable          UUIDAggregateMemberAttachabilityStatus = "attachable"
	UUIDAggregateMemberAttachabilityMissingClientIP     UUIDAggregateMemberAttachabilityStatus = "missing_client_ip"
	UUIDAggregateMemberAttachabilityUnsupportedClientIP UUIDAggregateMemberAttachabilityStatus = "unsupported_client_ip"
)

func (s UUIDAggregateMemberAttachabilityStatus) Valid() bool {
	switch s {
	case UUIDAggregateMemberAttachabilityAttachable,
		UUIDAggregateMemberAttachabilityMissingClientIP,
		UUIDAggregateMemberAttachabilityUnsupportedClientIP:
		return true
	default:
		return false
	}
}

// UUIDAggregateMemberAttachability records the current concrete attachability
// verdict for one live UUID aggregate member under the current direct client-ip
// backend.
type UUIDAggregateMemberAttachability struct {
	Member            correlation.UUIDAggregateMember        `json:"member"`
	Status            UUIDAggregateMemberAttachabilityStatus `json:"status"`
	RawClientIP       string                                 `json:"raw_client_ip,omitempty"`
	CanonicalClientIP string                                 `json:"canonical_client_ip,omitempty"`
	Reason            string                                 `json:"reason,omitempty"`
}

func (a UUIDAggregateMemberAttachability) Validate() error {
	if err := a.Member.Validate(); err != nil {
		return fmt.Errorf("invalid aggregate member attachability member: %w", err)
	}
	if !a.Status.Valid() {
		return fmt.Errorf("invalid aggregate member attachability status %q", a.Status)
	}

	raw := strings.TrimSpace(a.RawClientIP)
	canonical := strings.TrimSpace(a.CanonicalClientIP)
	switch a.Status {
	case UUIDAggregateMemberAttachabilityAttachable:
		if raw == "" {
			return errors.New("attachable aggregate member attachability requires raw client ip evidence")
		}
		addr, err := netip.ParseAddr(canonical)
		if err != nil {
			return fmt.Errorf("attachable aggregate member attachability requires a canonical client ip: %w", err)
		}
		if !addr.Is4() && !addr.Is6() {
			return errors.New("attachable aggregate member attachability currently requires a canonical ipv4 or ipv6 client ip")
		}
	case UUIDAggregateMemberAttachabilityMissingClientIP:
		if raw != "" || canonical != "" {
			return errors.New("missing-client-ip aggregate member attachability cannot carry client ip values")
		}
	case UUIDAggregateMemberAttachabilityUnsupportedClientIP:
		if raw == "" {
			return errors.New("unsupported-client-ip aggregate member attachability requires raw client ip evidence")
		}
		if canonical != "" {
			return errors.New("unsupported-client-ip aggregate member attachability cannot carry a canonical client ip")
		}
	}

	return nil
}

func (a UUIDAggregateMemberAttachability) Key() string {
	return a.Member.Key()
}

// UUIDAggregateAttachabilityMap captures which live UUID members are concretely
// attachable today and which members still block safe aggregate execution.
type UUIDAggregateAttachabilityMap struct {
	Members         []UUIDAggregateMemberAttachability `json:"members,omitempty"`
	AttachableCount int                                `json:"attachable_count,omitempty"`
	BlockingCount   int                                `json:"blocking_count,omitempty"`
	Reason          string                             `json:"reason,omitempty"`
}

func (m UUIDAggregateAttachabilityMap) Validate() error {
	if m.AttachableCount < 0 {
		return errors.New("aggregate attachability map attachable count must be greater than or equal to 0")
	}
	if m.BlockingCount < 0 {
		return errors.New("aggregate attachability map blocking count must be greater than or equal to 0")
	}
	if m.AttachableCount+m.BlockingCount != len(m.Members) {
		return errors.New("aggregate attachability map counts must match the number of members")
	}

	seen := make(map[string]struct{}, len(m.Members))
	attachable := 0
	blocking := 0
	for index, member := range m.Members {
		if err := member.Validate(); err != nil {
			return fmt.Errorf("invalid aggregate attachability member at index %d: %w", index, err)
		}
		key := member.Key()
		if _, ok := seen[key]; ok {
			return fmt.Errorf("duplicate aggregate attachability member %q", strings.TrimSpace(member.Member.Session.ID))
		}
		seen[key] = struct{}{}
		if member.Status == UUIDAggregateMemberAttachabilityAttachable {
			attachable++
		} else {
			blocking++
		}
	}
	if attachable != m.AttachableCount || blocking != m.BlockingCount {
		return errors.New("aggregate attachability map counts do not match member statuses")
	}

	return nil
}

// BuildUUIDAggregateAttachabilityMap classifies each live UUID aggregate member
// into attachable or blocking evidence states for the current direct client-ip
// aggregate backend.
func BuildUUIDAggregateAttachabilityMap(membership correlation.UUIDAggregateMembership) (UUIDAggregateAttachabilityMap, error) {
	if err := membership.Validate(); err != nil {
		return UUIDAggregateAttachabilityMap{}, err
	}

	result := UUIDAggregateAttachabilityMap{
		Members: make([]UUIDAggregateMemberAttachability, 0, membership.MemberCount()),
		Reason:  "aggregate uuid group has no live members to evaluate for concrete attachment",
	}
	if membership.MemberCount() == 0 {
		if err := result.Validate(); err != nil {
			return UUIDAggregateAttachabilityMap{}, err
		}
		return result, nil
	}

	missing := make([]string, 0)
	unsupported := make([]string, 0)
	for _, member := range membership.Members {
		sessionID := strings.TrimSpace(member.Session.ID)
		rawIP := strings.TrimSpace(member.Session.Client.IP)
		entry := UUIDAggregateMemberAttachability{
			Member:      member,
			RawClientIP: rawIP,
		}

		switch {
		case rawIP == "":
			entry.Status = UUIDAggregateMemberAttachabilityMissingClientIP
			entry.Reason = "live member has no client-ip evidence, so the current aggregate backend cannot attach it safely"
			result.BlockingCount++
			missing = append(missing, sessionID)
		default:
			addr, err := netip.ParseAddr(rawIP)
			if err != nil {
				return UUIDAggregateAttachabilityMap{}, fmt.Errorf("aggregate member %q has invalid validated client ip %q: %w", sessionID, rawIP, err)
			}
			addr = addr.Unmap()
			if addr.Is4() {
				entry.Status = UUIDAggregateMemberAttachabilityAttachable
				entry.CanonicalClientIP = addr.String()
				if rawIP == entry.CanonicalClientIP {
					entry.Reason = "exact ipv4 client-ip evidence is attachable to the shared aggregate class"
				} else {
					entry.Reason = "ipv4-mapped ipv6 client-ip evidence canonicalizes to an attachable ipv4 address"
				}
				result.AttachableCount++
			} else if addr.Is6() {
				entry.Status = UUIDAggregateMemberAttachabilityAttachable
				entry.CanonicalClientIP = addr.String()
				entry.Reason = "native ipv6 client-ip evidence is attachable to the shared aggregate class under the current u32 backend assumptions"
				result.AttachableCount++
			} else {
				entry.Status = UUIDAggregateMemberAttachabilityUnsupportedClientIP
				entry.Reason = "the current aggregate backend only attaches ipv4 or ipv6 client-ip evidence; this live member currently exposes unsupported client-ip evidence"
				result.BlockingCount++
				unsupported = append(unsupported, sessionID)
			}
		}

		if err := entry.Validate(); err != nil {
			return UUIDAggregateAttachabilityMap{}, err
		}
		result.Members = append(result.Members, entry)
	}

	if result.BlockingCount == 0 {
		result.Reason = "every live member has attachable client-ip evidence for the current shared aggregate backend"
	} else {
		reasons := make([]string, 0, 2)
		if len(missing) != 0 {
			sort.Strings(missing)
			reasons = append(reasons, fmt.Sprintf("missing client ip evidence for: %s", strings.Join(missing, ", ")))
		}
		if len(unsupported) != 0 {
			sort.Strings(unsupported)
			reasons = append(reasons, fmt.Sprintf("unsupported client ip evidence for: %s", strings.Join(unsupported, ", ")))
		}
		result.Reason = "concrete aggregate attachment currently requires attachable client ip evidence for every live member"
		if len(reasons) != 0 {
			result.Reason += "; " + strings.Join(reasons, "; ")
		}
	}

	if err := result.Validate(); err != nil {
		return UUIDAggregateAttachabilityMap{}, err
	}

	return result, nil
}

// UUIDAggregateAttachmentMatchField identifies which packet field the current
// aggregate attachment rule matches.
type UUIDAggregateAttachmentMatchField string

const (
	UUIDAggregateAttachmentMatchSource      UUIDAggregateAttachmentMatchField = "source_ip"
	UUIDAggregateAttachmentMatchDestination UUIDAggregateAttachmentMatchField = "destination_ip"
)

func (f UUIDAggregateAttachmentMatchField) Valid() bool {
	switch f {
	case UUIDAggregateAttachmentMatchSource, UUIDAggregateAttachmentMatchDestination:
		return true
	default:
		return false
	}
}

func (f UUIDAggregateAttachmentMatchField) u32Token() string {
	switch f {
	case UUIDAggregateAttachmentMatchSource:
		return "src"
	case UUIDAggregateAttachmentMatchDestination:
		return "dst"
	default:
		return ""
	}
}

// UUIDAggregateAttachmentRule captures one concrete tc filter rule that can
// attach one or more live members to the shared UUID class.
type UUIDAggregateAttachmentRule struct {
	Identity         TrafficIdentity                   `json:"identity"`
	MatchField       UUIDAggregateAttachmentMatchField `json:"match_field"`
	Preference       uint32                            `json:"preference"`
	AggregateClassID string                            `json:"aggregate_class_id"`
	MemberSessionIDs []string                          `json:"member_session_ids,omitempty"`
	Readiness        BindingReadiness                  `json:"readiness"`
	Confidence       BindingConfidence                 `json:"confidence"`
	Reason           string                            `json:"reason,omitempty"`
}

func (r UUIDAggregateAttachmentRule) Validate() error {
	if err := r.Identity.Validate(); err != nil {
		return fmt.Errorf("invalid aggregate attachment rule identity: %w", err)
	}
	if r.Identity.Kind != IdentityKindClientIP {
		return errors.New("aggregate attachment rule currently requires a client-ip identity")
	}
	ip, err := netip.ParseAddr(strings.TrimSpace(r.Identity.Value))
	if err != nil {
		return fmt.Errorf("aggregate attachment rule requires a valid client ip: %w", err)
	}
	ip = ip.Unmap()
	if !ip.Is4() && !ip.Is6() {
		return errors.New("aggregate attachment rule currently requires an ipv4 or ipv6 client ip")
	}
	if !r.MatchField.Valid() {
		return fmt.Errorf("invalid aggregate attachment rule match field %q", r.MatchField)
	}
	if r.Preference == 0 {
		return errors.New("aggregate attachment rule preference is required")
	}
	rootHandle, err := rootHandleFromClassID(r.AggregateClassID)
	if err != nil {
		return err
	}
	if err := validateClassID(strings.TrimSpace(r.AggregateClassID), rootHandle); err != nil {
		return err
	}
	if !r.Readiness.Valid() {
		return fmt.Errorf("invalid aggregate attachment rule readiness %q", r.Readiness)
	}
	if !r.Confidence.Valid() {
		return fmt.Errorf("invalid aggregate attachment rule confidence %q", r.Confidence)
	}
	if len(r.MemberSessionIDs) == 0 {
		return errors.New("aggregate attachment rule requires at least one member session id")
	}

	seen := make(map[string]struct{}, len(r.MemberSessionIDs))
	for index, sessionID := range r.MemberSessionIDs {
		normalized := strings.TrimSpace(sessionID)
		if normalized == "" {
			return fmt.Errorf("aggregate attachment rule member session id at index %d is blank", index)
		}
		if _, ok := seen[normalized]; ok {
			return fmt.Errorf("duplicate aggregate attachment rule member session id %q", normalized)
		}
		seen[normalized] = struct{}{}
	}

	return nil
}

func (r UUIDAggregateAttachmentRule) addr() (netip.Addr, error) {
	addr, err := netip.ParseAddr(strings.TrimSpace(r.Identity.Value))
	if err != nil {
		return netip.Addr{}, err
	}

	return addr.Unmap(), nil
}

func (r UUIDAggregateAttachmentRule) protocolToken() string {
	addr, err := r.addr()
	if err != nil {
		return ""
	}
	if addr.Is4() {
		return "ip"
	}
	if addr.Is6() {
		return "ipv6"
	}

	return ""
}

func (r UUIDAggregateAttachmentRule) matchFamilyToken() string {
	addr, err := r.addr()
	if err != nil {
		return ""
	}
	if addr.Is4() {
		return "ip"
	}
	if addr.Is6() {
		return "ip6"
	}

	return ""
}

func (r UUIDAggregateAttachmentRule) prefixLength() int {
	addr, err := r.addr()
	if err != nil {
		return 0
	}
	if addr.Is4() {
		return 32
	}
	if addr.Is6() {
		return 128
	}

	return 0
}

func (r UUIDAggregateAttachmentRule) Key() string {
	return strings.Join([]string{
		string(r.Identity.Kind),
		strings.TrimSpace(r.Identity.Value),
		r.MatchField.u32Token(),
		fmt.Sprintf("%d", r.Preference),
		strings.TrimSpace(r.AggregateClassID),
	}, "|")
}

// UUIDAggregateAttachmentBackend identifies which concrete classifier bridge is
// currently driving one shared UUID aggregate attachment set.
type UUIDAggregateAttachmentBackend string

const (
	UUIDAggregateAttachmentBackendClientIPU32           UUIDAggregateAttachmentBackend = "client_ip_u32"
	UUIDAggregateAttachmentBackendRoutingLocalSocketFW  UUIDAggregateAttachmentBackend = "routing_local_socket_fw"
	UUIDAggregateAttachmentBackendRoutingClientSocketFW UUIDAggregateAttachmentBackend = "routing_client_socket_fw"
)

func (b UUIDAggregateAttachmentBackend) Valid() bool {
	switch b {
	case "",
		UUIDAggregateAttachmentBackendClientIPU32,
		UUIDAggregateAttachmentBackendRoutingLocalSocketFW,
		UUIDAggregateAttachmentBackendRoutingClientSocketFW:
		return true
	default:
		return false
	}
}

// UUIDAggregateAttachmentExecution captures the current concrete attachment-rule
// execution view for one runtime-local aggregate UUID subject.
type UUIDAggregateAttachmentExecution struct {
	Backend         UUIDAggregateAttachmentBackend `json:"backend,omitempty"`
	Rules           []UUIDAggregateAttachmentRule  `json:"rules,omitempty"`
	MarkAttachments []MarkAttachmentExecution      `json:"mark_attachments,omitempty"`
	Readiness       BindingReadiness               `json:"readiness"`
	Confidence      BindingConfidence              `json:"confidence"`
	Reason          string                         `json:"reason,omitempty"`
}

func (e UUIDAggregateAttachmentExecution) Validate() error {
	if !e.Backend.Valid() {
		return fmt.Errorf("invalid aggregate attachment execution backend %q", e.Backend)
	}
	if !e.Readiness.Valid() {
		return fmt.Errorf("invalid aggregate attachment execution readiness %q", e.Readiness)
	}
	if !e.Confidence.Valid() {
		return fmt.Errorf("invalid aggregate attachment execution confidence %q", e.Confidence)
	}
	if len(e.Rules) != 0 && len(e.MarkAttachments) != 0 {
		return errors.New("aggregate attachment execution cannot mix direct and mark-backed attachment backends")
	}
	if len(e.Rules) == 0 && len(e.MarkAttachments) == 0 {
		if e.Readiness == BindingReadinessReady {
			return errors.New("empty aggregate attachment execution cannot report ready state")
		}
		return nil
	}
	if e.Readiness != BindingReadinessReady {
		return errors.New("aggregate attachment execution rules require ready state")
	}

	if len(e.Rules) != 0 {
		if e.Backend == "" {
			return errors.New("aggregate direct attachment execution backend is required")
		}
		if e.Backend != UUIDAggregateAttachmentBackendClientIPU32 {
			return errors.New("aggregate direct attachment execution must use the client_ip_u32 backend")
		}
		seen := make(map[string]struct{}, len(e.Rules))
		for index, rule := range e.Rules {
			if err := rule.Validate(); err != nil {
				return fmt.Errorf("invalid aggregate attachment execution rule at index %d: %w", index, err)
			}
			key := rule.Key()
			if _, ok := seen[key]; ok {
				return fmt.Errorf("duplicate aggregate attachment execution rule %q", key)
			}
			seen[key] = struct{}{}
		}
	}
	if len(e.MarkAttachments) != 0 {
		if e.Backend != UUIDAggregateAttachmentBackendRoutingLocalSocketFW &&
			e.Backend != UUIDAggregateAttachmentBackendRoutingClientSocketFW {
			return errors.New("aggregate mark-backed attachment execution must use a supported uuid routing mark backend")
		}
		seen := make(map[string]struct{}, len(e.MarkAttachments))
		for index, execution := range e.MarkAttachments {
			if err := execution.Validate(); err != nil {
				return fmt.Errorf("invalid aggregate mark attachment at index %d: %w", index, err)
			}
			if execution.Identity.Kind != IdentityKindUUIDRouting {
				return fmt.Errorf("aggregate mark attachment at index %d must use a uuid-routing identity", index)
			}
			key := strings.Join([]string{
				execution.Identity.Value,
				execution.Filter.ClassID,
				execution.Filter.handleArg(),
				fmt.Sprintf("%d", execution.Filter.Preference),
			}, "|")
			if _, ok := seen[key]; ok {
				return fmt.Errorf("duplicate aggregate mark attachment execution %q", key)
			}
			seen[key] = struct{}{}
		}
	}

	return nil
}

func (e UUIDAggregateAttachmentExecution) usesDirectAttachments() bool {
	return len(e.Rules) != 0
}

func (e UUIDAggregateAttachmentExecution) usesMarkAttachments() bool {
	return len(e.MarkAttachments) != 0
}

// BuildUUIDAggregateAttachmentExecution derives the first concrete aggregate
// attachment execution set. The current narrow execution step only emits IPv4
// client-ip-based u32 rules when every live member is attachable.
func BuildUUIDAggregateAttachmentExecution(membership correlation.UUIDAggregateMembership, scope Scope, classID string) (UUIDAggregateAttachmentExecution, error) {
	attachability, err := BuildUUIDAggregateAttachabilityMap(membership)
	if err != nil {
		return UUIDAggregateAttachmentExecution{}, err
	}

	return buildUUIDAggregateAttachmentExecution(membership, attachability, scope, classID, nil, nil)
}

// BuildUUIDAggregateAttachmentExecutionWithRoutingEvidence derives the current
// concrete aggregate attachment execution set using either direct attachable
// client-ip evidence or fresh RoutingService-backed socket-tuple evidence.
func BuildUUIDAggregateAttachmentExecutionWithRoutingEvidence(
	membership correlation.UUIDAggregateMembership,
	scope Scope,
	classID string,
	routingEvidence *discovery.UUIDRoutingEvidenceResult,
	routingAssessment *discovery.UUIDRoutingEvidenceAssessment,
) (UUIDAggregateAttachmentExecution, error) {
	attachability, err := BuildUUIDAggregateAttachabilityMap(membership)
	if err != nil {
		return UUIDAggregateAttachmentExecution{}, err
	}

	return buildUUIDAggregateAttachmentExecution(membership, attachability, scope, classID, routingEvidence, routingAssessment)
}

func buildUUIDAggregateAttachmentExecution(
	membership correlation.UUIDAggregateMembership,
	attachability UUIDAggregateAttachabilityMap,
	scope Scope,
	classID string,
	routingEvidence *discovery.UUIDRoutingEvidenceResult,
	routingAssessment *discovery.UUIDRoutingEvidenceAssessment,
) (UUIDAggregateAttachmentExecution, error) {
	if err := membership.Validate(); err != nil {
		return UUIDAggregateAttachmentExecution{}, err
	}
	if err := attachability.Validate(); err != nil {
		return UUIDAggregateAttachmentExecution{}, err
	}
	if err := scope.Validate(); err != nil {
		return UUIDAggregateAttachmentExecution{}, err
	}
	rootHandle, err := rootHandleFromClassID(classID)
	if err != nil {
		return UUIDAggregateAttachmentExecution{}, err
	}
	if err := validateClassID(strings.TrimSpace(classID), rootHandle); err != nil {
		return UUIDAggregateAttachmentExecution{}, err
	}

	execution := UUIDAggregateAttachmentExecution{
		Readiness:  BindingReadinessUnavailable,
		Confidence: BindingConfidenceHigh,
		Reason:     attachability.Reason,
	}
	if membership.MemberCount() == 0 {
		if err := execution.Validate(); err != nil {
			return UUIDAggregateAttachmentExecution{}, err
		}
		return execution, nil
	}

	matchField := attachmentMatchFieldForDirection(scope.Direction)
	if !matchField.Valid() {
		return UUIDAggregateAttachmentExecution{}, fmt.Errorf("unsupported aggregate attachment direction %q", scope.Direction)
	}

	if attachability.BlockingCount != 0 {
		return buildUUIDAggregateRoutingAttachmentExecution(membership, attachability, scope, classID, routingEvidence, routingAssessment)
	}

	type bucket struct {
		ip        string
		memberIDs []string
	}

	buckets := make(map[string]*bucket, membership.MemberCount())
	for _, member := range attachability.Members {
		canonical := strings.TrimSpace(member.CanonicalClientIP)
		if canonical == "" {
			continue
		}

		entry, ok := buckets[canonical]
		if !ok {
			entry = &bucket{ip: canonical}
			buckets[canonical] = entry
		}
		entry.memberIDs = append(entry.memberIDs, strings.TrimSpace(member.Member.Session.ID))
	}

	ips := make([]string, 0, len(buckets))
	for ip := range buckets {
		ips = append(ips, ip)
	}
	sort.Strings(ips)

	execution.Rules = make([]UUIDAggregateAttachmentRule, 0, len(ips))
	usesIPv6 := false
	for _, ip := range ips {
		memberIDs := append([]string(nil), buckets[ip].memberIDs...)
		sort.Strings(memberIDs)

		rule := UUIDAggregateAttachmentRule{
			Identity: TrafficIdentity{
				Kind:  IdentityKindClientIP,
				Value: ip,
			},
			MatchField:       matchField,
			Preference:       deriveUUIDAggregateAttachmentPreference(classID, scope.Direction, ip),
			AggregateClassID: strings.TrimSpace(classID),
			MemberSessionIDs: memberIDs,
			Readiness:        BindingReadinessReady,
			Confidence:       BindingConfidenceMedium,
			Reason:           "u32 client-ip attachment rule targets the shared aggregate class for the current live membership",
		}
		if addr, err := rule.addr(); err == nil && addr.Is6() {
			usesIPv6 = true
			rule.Reason = "u32 ipv6 client-ip attachment rule targets the shared aggregate class for the current live membership and assumes no ipv6 extension headers"
		}
		if err := rule.Validate(); err != nil {
			return UUIDAggregateAttachmentExecution{}, fmt.Errorf("invalid aggregate attachment execution rule for ip %s: %w", ip, err)
		}
		execution.Rules = append(execution.Rules, rule)
	}

	execution.Readiness = BindingReadinessReady
	execution.Confidence = BindingConfidenceMedium
	execution.Backend = UUIDAggregateAttachmentBackendClientIPU32
	execution.Reason = "concrete client-ip attachment rules were derived for every live aggregate member; dynamic membership updates remain deferred"
	if usesIPv6 {
		execution.Reason = "concrete client-ip attachment rules were derived for every live aggregate member; ipv6 rules assume no ipv6 extension headers and dynamic membership updates remain deferred"
	}
	if err := execution.Validate(); err != nil {
		return UUIDAggregateAttachmentExecution{}, err
	}

	return execution, nil
}

type uuidAggregateRoutingSelectorBucket struct {
	network     string
	localIP     string
	localPort   int
	contextKeys []string
}

func buildUUIDAggregateRoutingAttachmentExecution(
	membership correlation.UUIDAggregateMembership,
	attachability UUIDAggregateAttachabilityMap,
	scope Scope,
	classID string,
	routingEvidence *discovery.UUIDRoutingEvidenceResult,
	routingAssessment *discovery.UUIDRoutingEvidenceAssessment,
) (UUIDAggregateAttachmentExecution, error) {
	execution := UUIDAggregateAttachmentExecution{
		Readiness:  BindingReadinessUnavailable,
		Confidence: BindingConfidenceLow,
		Reason:     attachability.Reason,
	}
	if routingEvidence == nil || routingAssessment == nil {
		if attachability.AttachableCount != 0 {
			execution.Readiness = BindingReadinessPartial
		}
		execution.Reason = blockedUUIDAggregateRoutingEvidenceReason(attachability, nil, nil)
		if err := execution.Validate(); err != nil {
			return UUIDAggregateAttachmentExecution{}, err
		}
		return execution, nil
	}

	switch routingAssessment.Freshness {
	case discovery.UUIDRoutingEvidenceFreshnessFresh:
	case discovery.UUIDRoutingEvidenceFreshnessStale,
		discovery.UUIDRoutingEvidenceFreshnessPartial,
		discovery.UUIDRoutingEvidenceFreshnessUnavailable,
		discovery.UUIDRoutingEvidenceFreshnessCandidate:
		if attachability.AttachableCount != 0 {
			execution.Readiness = BindingReadinessPartial
		}
		execution.Reason = blockedUUIDAggregateRoutingEvidenceReason(attachability, routingEvidence, routingAssessment)
		if err := execution.Validate(); err != nil {
			return UUIDAggregateAttachmentExecution{}, err
		}
		return execution, nil
	default:
		return UUIDAggregateAttachmentExecution{}, fmt.Errorf("unsupported uuid routing evidence freshness %q", routingAssessment.Freshness)
	}

	invalidReasons := make([]string, 0)
	buckets := make(map[string]*uuidAggregateRoutingSelectorBucket, len(routingEvidence.Contexts))
	backend := UUIDAggregateAttachmentBackend("")
	blockedReasonBase := ""
	successReason := ""
	identityRole := ""

	switch scope.Direction {
	case DirectionUpload:
		backend = UUIDAggregateAttachmentBackendRoutingLocalSocketFW
		blockedReasonBase = "fresh RoutingService-backed UUID routing evidence is available, but concrete non-ip upload execution requires exact-user tcp or udp local socket tuples with concrete local ip and local port"
		successReason = "fresh RoutingService-backed local socket tuples were derived for the current UUID aggregate; nftables marking plus tc fw classification concretely attach the shared class without falling back to shared client ip"
		identityRole = "local"
		for _, context := range routingEvidence.Contexts {
			network := strings.ToLower(strings.TrimSpace(context.Network))
			switch network {
			case "tcp", "udp":
			default:
				invalidReasons = append(invalidReasons, fmt.Sprintf("routing context %q exposes unsupported network %q", context.Key(), network))
				continue
			}
			if blockedReason := uuidAggregateRoutingBlockedContextReason(context, scope.Direction); blockedReason != "" {
				invalidReasons = append(invalidReasons, blockedReason)
				continue
			}
			if context.LocalPort <= 0 {
				invalidReasons = append(invalidReasons, fmt.Sprintf("routing context %q does not expose a concrete local port", context.Key()))
				continue
			}
			if len(context.LocalIPs) == 0 {
				invalidReasons = append(invalidReasons, fmt.Sprintf("routing context %q does not expose a concrete local ip", context.Key()))
				continue
			}

			for _, localIP := range context.LocalIPs {
				addr, err := netip.ParseAddr(strings.TrimSpace(localIP))
				if err != nil {
					invalidReasons = append(invalidReasons, fmt.Sprintf("routing context %q exposes invalid local ip %q: %v", context.Key(), localIP, err))
					continue
				}
				canonicalIP := addr.Unmap().String()
				bucketKey := strings.Join([]string{
					network,
					canonicalIP,
					fmt.Sprintf("%d", context.LocalPort),
				}, "|")
				bucket, ok := buckets[bucketKey]
				if !ok {
					bucket = &uuidAggregateRoutingSelectorBucket{
						network:   network,
						localIP:   canonicalIP,
						localPort: context.LocalPort,
					}
					buckets[bucketKey] = bucket
				}
				bucket.contextKeys = append(bucket.contextKeys, context.Key())
			}
		}
	case DirectionDownload:
		backend = UUIDAggregateAttachmentBackendRoutingClientSocketFW
		blockedReasonBase = "fresh RoutingService-backed UUID routing evidence is available, but concrete non-ip download execution requires exact-user tcp or udp client socket tuples with concrete client ip and client port"
		successReason = "fresh RoutingService-backed client socket tuples were derived for the current UUID aggregate; nftables marking plus tc fw classification concretely attach the shared class without falling back to shared client ip"
		identityRole = "client"
		for _, context := range routingEvidence.Contexts {
			network := strings.ToLower(strings.TrimSpace(context.Network))
			switch network {
			case "tcp", "udp":
			default:
				invalidReasons = append(invalidReasons, fmt.Sprintf("routing context %q exposes unsupported network %q", context.Key(), network))
				continue
			}
			if blockedReason := uuidAggregateRoutingBlockedContextReason(context, scope.Direction); blockedReason != "" {
				invalidReasons = append(invalidReasons, blockedReason)
				continue
			}
			if context.SourcePort <= 0 {
				invalidReasons = append(invalidReasons, fmt.Sprintf("routing context %q does not expose a concrete client port", context.Key()))
				continue
			}
			if len(context.SourceIPs) == 0 {
				invalidReasons = append(invalidReasons, fmt.Sprintf("routing context %q does not expose a concrete client ip", context.Key()))
				continue
			}

			for _, sourceIP := range context.SourceIPs {
				addr, err := netip.ParseAddr(strings.TrimSpace(sourceIP))
				if err != nil {
					invalidReasons = append(invalidReasons, fmt.Sprintf("routing context %q exposes invalid client ip %q: %v", context.Key(), sourceIP, err))
					continue
				}
				canonicalIP := addr.Unmap().String()
				bucketKey := strings.Join([]string{
					network,
					canonicalIP,
					fmt.Sprintf("%d", context.SourcePort),
				}, "|")
				bucket, ok := buckets[bucketKey]
				if !ok {
					bucket = &uuidAggregateRoutingSelectorBucket{
						network:   network,
						localIP:   canonicalIP,
						localPort: context.SourcePort,
					}
					buckets[bucketKey] = bucket
				}
				bucket.contextKeys = append(bucket.contextKeys, context.Key())
			}
		}
	default:
		return UUIDAggregateAttachmentExecution{}, fmt.Errorf("unsupported aggregate attachment direction %q", scope.Direction)
	}

	if len(invalidReasons) != 0 || len(buckets) == 0 {
		if len(buckets) != 0 || attachability.AttachableCount != 0 {
			execution.Readiness = BindingReadinessPartial
		}
		sort.Strings(invalidReasons)
		reason := blockedReasonBase
		if len(invalidReasons) != 0 {
			reason += "; " + strings.Join(invalidReasons, "; ")
		}
		switch scope.Direction {
		case DirectionUpload:
			if len(buckets) == 0 {
				reason += "; no concrete local socket tuple remains enforceable"
			}
		case DirectionDownload:
			if len(buckets) == 0 {
				reason += "; no concrete client socket tuple remains enforceable"
			}
		}
		execution.Reason = reason
		if err := execution.Validate(); err != nil {
			return UUIDAggregateAttachmentExecution{}, err
		}
		return execution, nil
	}

	keys := make([]string, 0, len(buckets))
	for key := range buckets {
		keys = append(keys, key)
	}
	sort.Strings(keys)

	execution.Backend = backend
	execution.MarkAttachments = make([]MarkAttachmentExecution, 0, len(keys))
	for _, key := range keys {
		bucket := buckets[key]
		sort.Strings(bucket.contextKeys)
		identityValue := strings.Join([]string{
			membership.Subject.Key(),
			identityRole,
			bucket.network,
			bucket.localIP,
			fmt.Sprintf("%d", bucket.localPort),
		}, "|")

		selectorExpression := uuidAggregateRoutingLocalSocketSelectorExpression(bucket.network, bucket.localIP, bucket.localPort)
		selectorDescription := uuidAggregateRoutingLocalSocketSelectorDescription(bucket.network, bucket.localIP, bucket.localPort)
		if scope.Direction == DirectionDownload {
			selectorExpression = uuidAggregateRoutingClientSocketSelectorExpression(bucket.network, bucket.localIP, bucket.localPort)
			selectorDescription = uuidAggregateRoutingClientSocketSelectorDescription(bucket.network, bucket.localIP, bucket.localPort)
		}

		markAttachment, err := BuildMarkAttachmentExecution(MarkAttachmentInput{
			Identity: TrafficIdentity{
				Kind:  IdentityKindUUIDRouting,
				Value: identityValue,
			},
			Scope:   scope,
			ClassID: classID,
			Selector: MarkAttachmentSelector{
				Expression:  selectorExpression,
				Description: selectorDescription,
			},
			ManageChainLifecycle: true,
			Confidence:           BindingConfidenceMedium,
		})
		if err != nil {
			return UUIDAggregateAttachmentExecution{}, err
		}
		execution.MarkAttachments = append(execution.MarkAttachments, markAttachment)
	}

	execution.Readiness = BindingReadinessReady
	execution.Confidence = BindingConfidenceMedium
	execution.Reason = successReason
	if err := execution.Validate(); err != nil {
		return UUIDAggregateAttachmentExecution{}, err
	}

	return execution, nil
}

func blockedUUIDAggregateRoutingEvidenceReason(
	attachability UUIDAggregateAttachabilityMap,
	routingEvidence *discovery.UUIDRoutingEvidenceResult,
	routingAssessment *discovery.UUIDRoutingEvidenceAssessment,
) string {
	reasons := make([]string, 0, 3)
	if base := strings.TrimSpace(attachability.Reason); base != "" {
		reasons = append(reasons, base)
	}
	if routingAssessment == nil {
		reasons = append(reasons, "no fresh RoutingService-backed UUID routing evidence was supplied for the non-ip backend")
		return strings.Join(reasons, "; ")
	}
	if message := strings.TrimSpace(routingAssessment.Reason); message != "" {
		reasons = append(reasons, message)
	}
	if routingEvidence != nil {
		if summary := strings.TrimSpace(routingEvidence.IssueSummary()); summary != "" {
			reasons = append(reasons, summary)
		} else if routingEvidence.Candidate != nil && strings.TrimSpace(routingEvidence.Candidate.Reason) != "" {
			reasons = append(reasons, strings.TrimSpace(routingEvidence.Candidate.Reason))
		}
	}
	if len(reasons) == 0 {
		return "fresh RoutingService-backed UUID routing evidence is required before the non-ip aggregate backend can execute concretely"
	}

	return strings.Join(reasons, "; ")
}

func uuidAggregateRoutingBlockedContextReason(context discovery.UUIDRoutingContext, direction Direction) string {
	key := context.Key()
	hasLocal := uuidRoutingHasConcreteLocalTuple(context)
	hasClient := uuidRoutingHasConcreteClientTuple(context)
	hasTarget := uuidRoutingHasConcreteTargetTuple(context)

	switch direction {
	case DirectionUpload:
		if hasClient && !hasLocal {
			return fmt.Sprintf("routing context %q exposes a concrete client socket tuple, which is concrete for the current download backend, but upload execution still requires a concrete local socket tuple", key)
		}
	case DirectionDownload:
		if hasLocal && !hasClient {
			if hasTarget {
				return fmt.Sprintf("routing context %q exposes exact-user local-plus-target socket evidence for the outbound leg, but the current download backend still requires a concrete client socket tuple; a broader exact-user remote socket classifier remains future work", key)
			}
			return fmt.Sprintf("routing context %q exposes a concrete local socket tuple, which is concrete for the current upload backend, but download execution still requires a concrete client socket tuple", key)
		}
	}

	if !hasLocal && !hasClient {
		if hasTarget {
			if uuidRoutingHasAnyLocalSignal(context) || uuidRoutingHasAnyClientSignal(context) {
				return fmt.Sprintf("routing context %q exposes partial socket evidence plus a concrete remote target tuple; the next broader safe uuid backend would need an exact-user remote socket classifier that combines local and target tuple evidence, which is not implemented yet", key)
			}
			return fmt.Sprintf("routing context %q exposes only remote target tuple evidence; remote target ip and port can be shared across users and are not yet a safe uuid classifier on their own", key)
		}
		if uuidRoutingHasOnlyMetadata(context) {
			return fmt.Sprintf("routing context %q exposes only routing metadata such as inbound tag, outbound tag, domain, or protocol; that metadata is not yet a kernel-visible exact-user-safe uuid classifier", key)
		}
	}

	return ""
}

func uuidRoutingHasConcreteClientTuple(context discovery.UUIDRoutingContext) bool {
	return context.SourcePort > 0 && len(context.SourceIPs) != 0
}

func uuidRoutingHasConcreteLocalTuple(context discovery.UUIDRoutingContext) bool {
	return context.LocalPort > 0 && len(context.LocalIPs) != 0
}

func uuidRoutingHasConcreteTargetTuple(context discovery.UUIDRoutingContext) bool {
	return context.TargetPort > 0 && len(context.TargetIPs) != 0
}

func uuidRoutingHasAnyClientSignal(context discovery.UUIDRoutingContext) bool {
	return context.SourcePort > 0 || len(context.SourceIPs) != 0
}

func uuidRoutingHasAnyLocalSignal(context discovery.UUIDRoutingContext) bool {
	return context.LocalPort > 0 || len(context.LocalIPs) != 0
}

func uuidRoutingHasAnyTargetSignal(context discovery.UUIDRoutingContext) bool {
	return context.TargetPort > 0 || len(context.TargetIPs) != 0
}

func uuidRoutingHasOnlyMetadata(context discovery.UUIDRoutingContext) bool {
	if uuidRoutingHasAnyClientSignal(context) || uuidRoutingHasAnyLocalSignal(context) || uuidRoutingHasAnyTargetSignal(context) {
		return false
	}

	return strings.TrimSpace(context.InboundTag) != "" ||
		strings.TrimSpace(context.OutboundTag) != "" ||
		strings.TrimSpace(context.TargetDomain) != "" ||
		strings.TrimSpace(context.Protocol) != ""
}

func uuidAggregateRoutingLocalSocketSelectorExpression(network string, localIP string, localPort int) []string {
	family := "ip"
	if addr, err := netip.ParseAddr(strings.TrimSpace(localIP)); err == nil && addr.Is6() {
		family = "ip6"
	}

	return []string{
		"meta", "l4proto", network,
		family, "saddr", localIP,
		network, "sport", fmt.Sprintf("%d", localPort),
	}
}

func uuidAggregateRoutingLocalSocketSelectorDescription(network string, localIP string, localPort int) string {
	return fmt.Sprintf(
		"fresh RoutingService-derived %s local socket %s:%d selects the shared uuid class without falling back to shared client ip",
		strings.ToUpper(strings.TrimSpace(network)),
		strings.TrimSpace(localIP),
		localPort,
	)
}

func uuidAggregateRoutingClientSocketSelectorExpression(network string, clientIP string, clientPort int) []string {
	family := "ip"
	if addr, err := netip.ParseAddr(strings.TrimSpace(clientIP)); err == nil && addr.Is6() {
		family = "ip6"
	}

	return []string{
		"meta", "l4proto", network,
		family, "daddr", clientIP,
		network, "dport", fmt.Sprintf("%d", clientPort),
	}
}

func uuidAggregateRoutingClientSocketSelectorDescription(network string, clientIP string, clientPort int) string {
	return fmt.Sprintf(
		"fresh RoutingService-derived %s client socket %s:%d selects the shared uuid class without falling back to shared client ip",
		strings.ToUpper(strings.TrimSpace(network)),
		strings.TrimSpace(clientIP),
		clientPort,
	)
}

// UUIDAggregatePlanInput captures the planner inputs for one shared runtime-local
// UUID aggregate cap.
type UUIDAggregatePlanInput struct {
	Operation                 UUIDAggregateOperation                   `json:"operation,omitempty"`
	Membership                correlation.UUIDAggregateMembership      `json:"membership"`
	Scope                     Scope                                    `json:"scope"`
	Limits                    policy.LimitPolicy                       `json:"limits,omitempty"`
	CleanupRootQDisc          bool                                     `json:"cleanup_root_qdisc,omitempty"`
	RoutingEvidence           *discovery.UUIDRoutingEvidenceResult     `json:"routing_evidence,omitempty"`
	RoutingEvidenceAssessment *discovery.UUIDRoutingEvidenceAssessment `json:"routing_evidence_assessment,omitempty"`
}

func (i UUIDAggregatePlanInput) Validate() error {
	operation := i.Operation.normalized()
	if !operation.Valid() {
		return fmt.Errorf("invalid aggregate operation %q", i.Operation)
	}
	if err := i.Membership.Validate(); err != nil {
		return err
	}
	if err := i.Scope.Validate(); err != nil {
		return err
	}
	if (i.RoutingEvidence == nil) != (i.RoutingEvidenceAssessment == nil) {
		return errors.New("aggregate uuid planning requires routing evidence and its assessment together")
	}
	if i.RoutingEvidence != nil {
		if err := i.RoutingEvidence.Validate(); err != nil {
			return fmt.Errorf("invalid uuid routing evidence: %w", err)
		}
		if err := i.RoutingEvidenceAssessment.Validate(); err != nil {
			return fmt.Errorf("invalid uuid routing evidence assessment: %w", err)
		}
		if !strings.EqualFold(strings.TrimSpace(i.RoutingEvidence.UUID), strings.TrimSpace(i.Membership.Subject.UUID)) {
			return errors.New("aggregate uuid routing evidence does not match the requested uuid")
		}
		if !sameRuntimeBinding(i.Membership.Subject.Runtime, i.RoutingEvidence.Runtime) {
			return errors.New("aggregate uuid routing evidence does not match the requested runtime")
		}
	}

	switch operation {
	case UUIDAggregateOperationApply:
		if err := i.Limits.Validate(); err != nil {
			return err
		}
		if !i.Limits.HasAny() {
			return errors.New("aggregate uuid planning requires at least one directional limit")
		}
	case UUIDAggregateOperationRemove:
		if i.Limits.HasAny() {
			return errors.New("aggregate uuid remove planning does not accept directional limits")
		}
	}

	return nil
}

// UUIDAggregateOperation identifies which shared UUID aggregate action the
// planner should prepare.
type UUIDAggregateOperation string

const (
	UUIDAggregateOperationApply  UUIDAggregateOperation = "apply"
	UUIDAggregateOperationRemove UUIDAggregateOperation = "remove"
)

func (o UUIDAggregateOperation) Valid() bool {
	switch o {
	case UUIDAggregateOperationApply, UUIDAggregateOperationRemove:
		return true
	default:
		return false
	}
}

func (o UUIDAggregateOperation) normalized() UUIDAggregateOperation {
	if o == "" {
		return UUIDAggregateOperationApply
	}

	return o
}

// UUIDAggregatePlan is the planner-ready representation of one shared UUID cap.
// It covers the shared shaping identity plus the first concrete member
// attachment-rule execution step, while still deferring richer classifier
// coverage and dynamic membership updates.
type UUIDAggregatePlan struct {
	Operation           UUIDAggregateOperation               `json:"operation"`
	Membership          correlation.UUIDAggregateMembership  `json:"membership"`
	Scope               Scope                                `json:"scope"`
	Binding             UUIDAggregateBinding                 `json:"binding"`
	Handles             Handles                              `json:"handles"`
	Attachability       UUIDAggregateAttachabilityMap        `json:"attachability"`
	Attachments         UUIDAggregateAttachmentSet           `json:"attachments"`
	AttachmentExecution UUIDAggregateAttachmentExecution     `json:"attachment_execution"`
	Cardinality         correlation.UUIDAggregateCardinality `json:"cardinality"`
	Steps               []Step                               `json:"steps,omitempty"`
	NoOp                bool                                 `json:"no_op,omitempty"`
	CleanupRootQDisc    bool                                 `json:"cleanup_root_qdisc,omitempty"`
	Reason              string                               `json:"reason,omitempty"`
}

func (p UUIDAggregatePlan) Validate() error {
	if !p.Operation.Valid() {
		return fmt.Errorf("invalid aggregate operation %q", p.Operation)
	}
	if err := p.Membership.Validate(); err != nil {
		return fmt.Errorf("invalid aggregate membership: %w", err)
	}
	if err := p.Scope.Validate(); err != nil {
		return fmt.Errorf("invalid aggregate scope: %w", err)
	}
	if err := p.Binding.Validate(); err != nil {
		return fmt.Errorf("invalid aggregate binding: %w", err)
	}
	if p.Binding.Subject.Key() != p.Membership.Subject.Key() {
		return errors.New("aggregate plan binding subject does not match the aggregate membership")
	}
	if err := p.Handles.Validate(); err != nil {
		return fmt.Errorf("invalid aggregate handles: %w", err)
	}
	if err := p.Attachability.Validate(); err != nil {
		return fmt.Errorf("invalid aggregate attachability: %w", err)
	}
	if err := p.Attachments.Validate(); err != nil {
		return fmt.Errorf("invalid aggregate attachments: %w", err)
	}
	if err := p.AttachmentExecution.Validate(); err != nil {
		return fmt.Errorf("invalid aggregate attachment execution: %w", err)
	}
	for index, attachment := range p.Attachments.Members {
		if strings.TrimSpace(attachment.AggregateClassID) != strings.TrimSpace(p.Handles.ClassID) {
			return fmt.Errorf("aggregate attachment at index %d does not match the plan class id", index)
		}
	}
	if !p.Cardinality.Valid() {
		return fmt.Errorf("invalid aggregate cardinality %q", p.Cardinality)
	}
	if p.Cardinality == correlation.UUIDAggregateCardinalityZero && len(p.Attachments.Members) != 0 {
		return errors.New("zero-member aggregate plan cannot define member attachments")
	}
	if len(p.Attachability.Members) != p.Membership.MemberCount() {
		return errors.New("aggregate attachability map must cover every aggregate member")
	}
	if p.Cardinality != correlation.UUIDAggregateCardinalityZero && len(p.Attachments.Members) != p.Membership.MemberCount() {
		return errors.New("aggregate plan attachments must cover every aggregate member")
	}
	if p.Cardinality == correlation.UUIDAggregateCardinalityZero && len(p.AttachmentExecution.Rules) != 0 {
		return errors.New("zero-member aggregate plan cannot define concrete attachment rules")
	}
	if p.Cardinality == correlation.UUIDAggregateCardinalityZero && len(p.AttachmentExecution.MarkAttachments) != 0 {
		return errors.New("zero-member aggregate plan cannot define concrete mark attachments")
	}
	if len(p.AttachmentExecution.Rules) != 0 && p.Attachability.BlockingCount != 0 {
		return errors.New("aggregate attachment execution rules require every aggregate member to be attachable")
	}
	if len(p.AttachmentExecution.Rules) != 0 {
		covered := make(map[string]struct{}, p.Membership.MemberCount())
		for index, rule := range p.AttachmentExecution.Rules {
			if strings.TrimSpace(rule.AggregateClassID) != strings.TrimSpace(p.Handles.ClassID) {
				return fmt.Errorf("aggregate attachment execution rule at index %d does not match the plan class id", index)
			}
			for _, sessionID := range rule.MemberSessionIDs {
				normalized := strings.TrimSpace(sessionID)
				if !p.Membership.HasMember(normalized) {
					return fmt.Errorf("aggregate attachment execution rule at index %d references unknown member session %q", index, normalized)
				}
				if _, ok := covered[normalized]; ok {
					return fmt.Errorf("aggregate attachment execution rule at index %d duplicates member session %q", index, normalized)
				}
				covered[normalized] = struct{}{}
			}
		}
		if len(covered) != p.Membership.MemberCount() {
			return errors.New("aggregate attachment execution rules must cover every aggregate member when concrete execution is ready")
		}
	}
	if len(p.AttachmentExecution.MarkAttachments) != 0 {
		for index, execution := range p.AttachmentExecution.MarkAttachments {
			if strings.TrimSpace(execution.Filter.ClassID) != strings.TrimSpace(p.Handles.ClassID) {
				return fmt.Errorf("aggregate mark attachment execution at index %d does not match the plan class id", index)
			}
		}
	}
	for index, step := range p.Steps {
		if err := step.Validate(); err != nil {
			return fmt.Errorf("invalid aggregate step at index %d: %w", index, err)
		}
	}
	if strings.TrimSpace(p.Reason) == "" {
		return errors.New("aggregate plan reason is required")
	}
	if p.NoOp && len(p.Steps) != 0 {
		return errors.New("aggregate no-op plan cannot include steps")
	}
	if p.NoOp && p.CleanupRootQDisc {
		return errors.New("aggregate no-op plan cannot request root qdisc cleanup")
	}

	return nil
}

// UUIDAggregateObservation captures the shared aggregate class state currently
// visible on one scope.
type UUIDAggregateObservation struct {
	Available                  bool   `json:"available"`
	Reconcilable               bool   `json:"reconcilable"`
	Matched                    bool   `json:"matched"`
	AttachmentComparable       bool   `json:"attachment_comparable,omitempty"`
	AttachmentMatched          bool   `json:"attachment_matched,omitempty"`
	ObservedAttachmentPresent  bool   `json:"observed_attachment_present,omitempty"`
	CleanupRootQDisc           bool   `json:"cleanup_root_qdisc,omitempty"`
	ExpectedClassID            string `json:"expected_class_id,omitempty"`
	ObservedClassID            string `json:"observed_class_id,omitempty"`
	ObservedRateBytesPerSecond int64  `json:"observed_rate_bytes_per_second,omitempty"`
	Error                      string `json:"error,omitempty"`
}

// UUIDAggregateDecision captures the shared aggregate reconcile outcome without
// claiming that dynamic attachment reconciliation is already complete.
type UUIDAggregateDecision struct {
	Kind   limiter.DecisionKind `json:"kind"`
	Reason string               `json:"reason"`
}

func (d UUIDAggregateDecision) Validate() error {
	switch d.Kind {
	case limiter.DecisionApply, limiter.DecisionRemove, limiter.DecisionNoOp:
	default:
		return fmt.Errorf("invalid aggregate decision kind %q", d.Kind)
	}
	if strings.TrimSpace(d.Reason) == "" {
		return errors.New("aggregate decision reason is required")
	}

	return nil
}

// PlanUUIDAggregate builds the shared shaping plan for one runtime-local UUID
// aggregate subject. It includes deterministic member attachment intents and,
// when every live member is attachable, the first concrete client-ip attachment
// rules for the shared class.
func (p Planner) PlanUUIDAggregate(input UUIDAggregatePlanInput) (UUIDAggregatePlan, error) {
	if err := input.Validate(); err != nil {
		return UUIDAggregatePlan{}, err
	}

	binding, err := BindUUIDAggregate(input.Membership)
	if err != nil {
		return UUIDAggregatePlan{}, err
	}

	plan := UUIDAggregatePlan{
		Operation:        input.Operation.normalized(),
		Membership:       input.Membership,
		Scope:            input.Scope,
		Binding:          binding,
		Handles:          aggregateHandles(input.Membership.Subject, input.Scope),
		Cardinality:      input.Membership.Cardinality(),
		CleanupRootQDisc: input.CleanupRootQDisc,
	}
	attachability, err := BuildUUIDAggregateAttachabilityMap(input.Membership)
	if err != nil {
		return UUIDAggregatePlan{}, err
	}
	plan.Attachability = attachability
	attachments, err := BuildUUIDAggregateAttachmentSet(input.Membership, plan.Handles.ClassID)
	if err != nil {
		return UUIDAggregatePlan{}, err
	}
	plan.Attachments = attachments
	plan.AttachmentExecution, err = buildUUIDAggregateAttachmentExecution(
		input.Membership,
		plan.Attachability,
		input.Scope,
		plan.Handles.ClassID,
		input.RoutingEvidence,
		input.RoutingEvidenceAssessment,
	)
	if err != nil {
		return UUIDAggregatePlan{}, err
	}

	switch plan.Operation {
	case UUIDAggregateOperationApply:
		switch plan.Cardinality {
		case correlation.UUIDAggregateCardinalityZero:
			plan.NoOp = true
			plan.Reason = "aggregate uuid group has no live members; no shared tc class should be planned"
		default:
			rate, err := rateForDirection(input.Limits, input.Scope.Direction)
			if err != nil {
				return UUIDAggregatePlan{}, err
			}
			plan.Steps = []Step{
				p.step("ensure-root-qdisc", "qdisc", "replace", "dev", input.Scope.Device, "root", "handle", plan.Handles.RootHandle, "htb", "default", "1"),
				p.step("upsert-aggregate-class", "class", "replace", "dev", input.Scope.Device, "parent", plan.Handles.RootHandle, "classid", plan.Handles.ClassID, "htb", "rate", rate, "ceil", rate),
			}
			if plan.AttachmentExecution.Readiness == BindingReadinessReady {
				plan.Steps = append(plan.Steps, p.aggregateAttachmentApplySteps(plan)...)
				if plan.AttachmentExecution.usesMarkAttachments() {
					plan.Reason = "aggregate uuid planning defines one shared tc class for the runtime-local uuid group and adds concrete RoutingService-backed socket-tuple mark attachments for the current live membership"
				} else {
					plan.Reason = "aggregate uuid planning defines one shared tc class for the runtime-local uuid group and adds concrete client-ip attachment rules for the current live membership"
				}
			} else {
				plan.Reason = "aggregate uuid planning defines one shared tc class for the runtime-local uuid group, but concrete member attachment execution is not currently possible"
			}
		}
	case UUIDAggregateOperationRemove:
		plan.Steps = make([]Step, 0, len(plan.AttachmentExecution.Rules)+(len(plan.AttachmentExecution.MarkAttachments)*2)+2)
		if plan.AttachmentExecution.Readiness == BindingReadinessReady {
			plan.Steps = append(plan.Steps, p.aggregateAttachmentRemoveSteps(plan)...)
		}
		plan.Steps = append(plan.Steps, p.step("delete-aggregate-class", "class", "del", "dev", input.Scope.Device, "classid", plan.Handles.ClassID))
		plan.Reason = "aggregate uuid remove planning deletes the shared tc class for the runtime-local uuid group"
		if plan.AttachmentExecution.Readiness == BindingReadinessReady {
			if plan.AttachmentExecution.usesMarkAttachments() {
				plan.Reason = "aggregate uuid remove planning deletes the shared tc class and uses observed RoutingService-backed mark attachment state to clean up the current concrete UUID backend"
			} else {
				plan.Reason = "aggregate uuid remove planning deletes the shared tc class and current concrete attachment rules for the runtime-local uuid group"
			}
		}
		if plan.CleanupRootQDisc {
			plan.Steps = append(plan.Steps, p.step("delete-root-qdisc", "qdisc", "del", "dev", input.Scope.Device, "root"))
			plan.Reason = "aggregate uuid remove planning deletes the shared tc class and cleans up the root htb qdisc when no other RayLimit-managed state remains"
			if plan.AttachmentExecution.Readiness == BindingReadinessReady {
				if plan.AttachmentExecution.usesMarkAttachments() {
					plan.Reason = "aggregate uuid remove planning deletes the shared tc class, cleans up observed RoutingService-backed mark attachments, and removes the root htb qdisc when no other RayLimit-managed state remains"
				} else {
					plan.Reason = "aggregate uuid remove planning deletes the shared tc class, removes current concrete attachment rules, and cleans up the root htb qdisc when no other RayLimit-managed state remains"
				}
			}
		}
	default:
		return UUIDAggregatePlan{}, fmt.Errorf("unsupported aggregate operation %q", plan.Operation)
	}

	if err := plan.Validate(); err != nil {
		return UUIDAggregatePlan{}, err
	}

	return plan, nil
}

// ObserveUUIDAggregate maps read-only tc and optional nftables state into the
// shared aggregate class view for one UUID aggregate plan.
func ObserveUUIDAggregate(snapshot Snapshot, nftSnapshot *NftablesSnapshot, plan UUIDAggregatePlan) (UUIDAggregateObservation, error) {
	if err := snapshot.Validate(); err != nil {
		return UUIDAggregateObservation{}, err
	}
	if nftSnapshot != nil {
		if err := nftSnapshot.Validate(); err != nil {
			return UUIDAggregateObservation{}, err
		}
	}
	if err := plan.Validate(); err != nil {
		return UUIDAggregateObservation{}, err
	}

	observation := UUIDAggregateObservation{
		Available:       true,
		Reconcilable:    true,
		ExpectedClassID: plan.Handles.ClassID,
	}
	observedDirectFilters := snapshot.UUIDAggregateAttachmentFilters(plan.Handles.RootHandle, plan.Handles.ClassID)
	observedMarkFilters := uuidAggregateObservedFWFilters(snapshot, plan.Handles.RootHandle, plan.Handles.ClassID)
	var observedMarkRules []NftablesRuleState
	if nftSnapshot != nil {
		observedMarkRules = uuidAggregateObservedMarkAttachmentRules(*nftSnapshot, plan.Scope.Direction, plan.Handles.ClassID)
	}
	observation.ObservedAttachmentPresent = len(observedDirectFilters) != 0 || len(observedMarkFilters) != 0 || len(observedMarkRules) != 0

	if expected := plan.AttachmentExecution.filterExpectationKeys(plan.Handles.RootHandle); len(expected) != 0 {
		observation.AttachmentComparable = true
		if plan.AttachmentExecution.usesDirectAttachments() {
			if len(observedDirectFilters) == len(expected) && len(observedMarkFilters) == 0 && len(observedMarkRules) == 0 {
				matched := true
				for _, filter := range observedDirectFilters {
					if _, ok := expected[uuidAggregateAttachmentFilterKey(filter)]; !ok {
						matched = false
						break
					}
				}
				observation.AttachmentMatched = matched
			}
		} else if plan.AttachmentExecution.usesMarkAttachments() {
			if nftSnapshot == nil {
				observation.Reconcilable = false
				observation.Error = "nftables state could not be compared for RoutingService-backed UUID mark attachments"
			} else {
				expectedRules := plan.AttachmentExecution.markRuleExpectationKeys()
				if len(observedMarkFilters) == len(expected) &&
					len(observedMarkRules) == len(expectedRules) &&
					len(observedDirectFilters) == 0 {
					matched := true
					for _, filter := range observedMarkFilters {
						if _, ok := expected[markAttachmentFilterKey(filter)]; !ok {
							matched = false
							break
						}
					}
					if matched {
						for _, rule := range observedMarkRules {
							if _, ok := expectedRules[uuidAggregateManagedMarkRuleKey(rule.Family, rule.Table, rule.Chain, rule.Comment)]; !ok {
								matched = false
								break
							}
						}
					}
					observation.AttachmentMatched = matched
				}
			}
		}
	}

	class, ok := snapshot.Class(plan.Handles.ClassID)
	if !ok {
		if plan.Operation == UUIDAggregateOperationRemove && observation.ObservedAttachmentPresent {
			if plan.AttachmentExecution.usesMarkAttachments() {
				observation.CleanupRootQDisc = eligibleForRootQDiscCleanupAfterUUIDAggregateMarkAttachmentRemoval(snapshot, plan.Handles.RootHandle, plan.Handles.ClassID)
			} else {
				observation.CleanupRootQDisc = snapshot.EligibleForRootQDiscCleanupAfterUUIDAggregateAttachmentRemoval(plan.Handles.RootHandle, plan.Handles.ClassID)
			}
		}
		return observation, nil
	}

	observation.Matched = true
	observation.ObservedClassID = class.ClassID
	if plan.Operation == UUIDAggregateOperationRemove {
		if plan.AttachmentExecution.usesMarkAttachments() {
			observation.CleanupRootQDisc = eligibleForRootQDiscCleanupAfterUUIDAggregateMarkAttachmentRemoval(snapshot, plan.Handles.RootHandle, plan.Handles.ClassID)
		} else {
			observation.CleanupRootQDisc = snapshot.EligibleForRootQDiscCleanup(plan.Handles.RootHandle, plan.Handles.ClassID)
		}
	}

	rate := observedAggregateRate(class)
	if rate == 0 && plan.Operation == UUIDAggregateOperationApply {
		observation.Reconcilable = false
		observation.Error = fmt.Sprintf("observed aggregate class %s does not expose a parsable rate", class.ClassID)
		return observation, nil
	}
	observation.ObservedRateBytesPerSecond = rate

	return observation, nil
}

// DecideUUIDAggregate derives the aggregate apply/remove decision from one
// shared UUID plan plus the currently observed aggregate state.
func DecideUUIDAggregate(plan UUIDAggregatePlan, observation UUIDAggregateObservation, desiredRateBytes int64) (UUIDAggregateDecision, error) {
	if err := plan.Validate(); err != nil {
		return UUIDAggregateDecision{}, err
	}
	if plan.Operation == UUIDAggregateOperationApply && desiredRateBytes <= 0 && !plan.NoOp {
		return UUIDAggregateDecision{}, errors.New("aggregate apply decision requires a desired rate greater than zero")
	}

	var decision UUIDAggregateDecision
	switch plan.Operation {
	case UUIDAggregateOperationApply:
		switch {
		case plan.Cardinality == correlation.UUIDAggregateCardinalityZero:
			decision = UUIDAggregateDecision{
				Kind:   limiter.DecisionNoOp,
				Reason: "aggregate uuid group has no live members; no shared tc class should be planned",
			}
		case plan.AttachmentExecution.Readiness != BindingReadinessReady:
			decision = UUIDAggregateDecision{
				Kind:   limiter.DecisionApply,
				Reason: blockedUUIDAggregateAttachabilityDecisionReason(plan.AttachmentExecution),
			}
		case observation.Reconcilable &&
			observation.Matched &&
			observation.AttachmentComparable &&
			observation.AttachmentMatched &&
			observation.ObservedRateBytesPerSecond == desiredRateBytes:
			decision = UUIDAggregateDecision{
				Kind:   limiter.DecisionNoOp,
				Reason: "matching shared aggregate class and concrete attachment rules already satisfy the requested UUID rate",
			}
		case observation.Reconcilable && observation.Matched && observation.ObservedRateBytesPerSecond == desiredRateBytes:
			decision = UUIDAggregateDecision{
				Kind:   limiter.DecisionApply,
				Reason: "matching shared aggregate class already satisfies the requested UUID rate, but concrete attachment rules did not fully match the current live membership; reconcile the concrete attachment delta",
			}
		case observation.Reconcilable && observation.Matched:
			decision = UUIDAggregateDecision{
				Kind:   limiter.DecisionApply,
				Reason: "matching shared aggregate class was observed with a different rate; replace the shared class and reconcile the concrete attachment delta for the UUID aggregate",
			}
		case observation.Reconcilable:
			decision = UUIDAggregateDecision{
				Kind:   limiter.DecisionApply,
				Reason: "no shared aggregate class was observed for the requested UUID on the selected runtime; apply the shared class and the current attachment rules",
			}
		default:
			decision = UUIDAggregateDecision{
				Kind:   limiter.DecisionApply,
				Reason: fallbackUUIDAggregateApplyReason(observation),
			}
		}
	case UUIDAggregateOperationRemove:
		switch {
		case observation.Reconcilable && observation.Matched:
			decision = UUIDAggregateDecision{
				Kind:   limiter.DecisionRemove,
				Reason: "matching shared aggregate class was observed for the requested UUID aggregate",
			}
		case observation.Reconcilable && observation.ObservedAttachmentPresent:
			decision = UUIDAggregateDecision{
				Kind:   limiter.DecisionRemove,
				Reason: "observed managed aggregate attachment rules still target the requested UUID class even though the shared aggregate class is no longer present",
			}
		case observation.Reconcilable:
			decision = UUIDAggregateDecision{
				Kind:   limiter.DecisionNoOp,
				Reason: "no shared aggregate class matching the requested UUID was observed",
			}
		default:
			decision = UUIDAggregateDecision{
				Kind:   limiter.DecisionRemove,
				Reason: fallbackUUIDAggregateRemoveReason(observation),
			}
		}
	default:
		return UUIDAggregateDecision{}, fmt.Errorf("unsupported aggregate operation %q", plan.Operation)
	}

	if err := decision.Validate(); err != nil {
		return UUIDAggregateDecision{}, err
	}

	return decision, nil
}

func aggregateHandles(subject correlation.UUIDAggregateSubject, scope Scope) Handles {
	rootHandle := scope.rootHandle()
	return Handles{
		RootHandle: rootHandle,
		ClassID:    deriveUUIDAggregateClassID(subject, scope.Direction, rootHandle),
	}
}

func observedAggregateRate(class ClassState) int64 {
	if class.RateBytesPerSecond > 0 {
		return class.RateBytesPerSecond
	}
	if class.CeilBytesPerSecond > 0 {
		return class.CeilBytesPerSecond
	}

	return 0
}

func fallbackUUIDAggregateApplyReason(observation UUIDAggregateObservation) string {
	if message := strings.TrimSpace(observation.Error); message != "" {
		return message + "; proceeding with a shared aggregate apply plan without comparable observed state"
	}

	return "tc state could not be compared; proceeding with a shared aggregate apply plan without observed state"
}

func fallbackUUIDAggregateRemoveReason(observation UUIDAggregateObservation) string {
	if message := strings.TrimSpace(observation.Error); message != "" {
		return message + "; proceeding with a shared aggregate remove plan without comparable observed state"
	}

	return "tc state could not be compared; proceeding with a shared aggregate remove plan without observed state"
}

func blockedUUIDAggregateAttachabilityDecisionReason(execution UUIDAggregateAttachmentExecution) string {
	reason := strings.TrimSpace(execution.Reason)
	blocked := "concrete uuid aggregate execution remains blocked until either every live member is attachable by client ip or fresh RoutingService-backed non-ip classifier evidence is concrete and safe to enforce"
	if reason == "" {
		return blocked
	}

	return fmt.Sprintf("%s; %s", reason, blocked)
}

// AppendUUIDAggregateObservedApplyDelta narrows an aggregate apply plan to the
// observed mutation delta for the currently selected concrete backend.
func AppendUUIDAggregateObservedApplyDelta(plan UUIDAggregatePlan, snapshot Snapshot, nftSnapshot *NftablesSnapshot, desiredRateBytes int64) (UUIDAggregatePlan, error) {
	if err := plan.Validate(); err != nil {
		return UUIDAggregatePlan{}, err
	}
	if err := snapshot.Validate(); err != nil {
		return UUIDAggregatePlan{}, err
	}
	if nftSnapshot != nil {
		if err := nftSnapshot.Validate(); err != nil {
			return UUIDAggregatePlan{}, err
		}
	}
	if plan.Operation != UUIDAggregateOperationApply || plan.AttachmentExecution.Readiness != BindingReadinessReady {
		return plan, nil
	}
	if desiredRateBytes <= 0 {
		return UUIDAggregatePlan{}, errors.New("aggregate apply delta narrowing requires a desired rate greater than zero")
	}

	next := plan
	builder := Planner{Binary: defaultBinary}
	steps := make([]Step, 0, len(plan.Steps))

	rootPresent := snapshotHasManagedRootQDisc(snapshot, plan.Handles.RootHandle)
	if !rootPresent {
		steps = append(steps, builder.step(
			"ensure-root-qdisc",
			"qdisc", "replace",
			"dev", plan.Scope.Device,
			"root", "handle", plan.Handles.RootHandle,
			"htb", "default", "1",
		))
	}

	class, classPresent := snapshot.Class(plan.Handles.ClassID)
	classMatchesRate := classPresent && observedAggregateRate(class) == desiredRateBytes
	if !classMatchesRate {
		rate := fmt.Sprintf("%dbps", desiredRateBytes)
		steps = append(steps, builder.step(
			"upsert-aggregate-class",
			"class", "replace",
			"dev", plan.Scope.Device,
			"parent", plan.Handles.RootHandle,
			"classid", plan.Handles.ClassID,
			"htb", "rate", rate, "ceil", rate,
		))
	}

	staleCount := 0
	missingCount := 0

	if plan.AttachmentExecution.usesDirectAttachments() {
		expected := plan.AttachmentExecution.filterExpectationKeys(plan.Handles.RootHandle)
		observedFilters := snapshot.UUIDAggregateAttachmentFilters(plan.Handles.RootHandle, plan.Handles.ClassID)
		matchedExpected := make(map[string]struct{}, len(expected))

		for _, filter := range observedFilters {
			key := uuidAggregateAttachmentFilterKey(filter)
			if _, ok := expected[key]; ok {
				if _, alreadyMatched := matchedExpected[key]; !alreadyMatched {
					matchedExpected[key] = struct{}{}
					continue
				}
			}
			protocol := strings.TrimSpace(filter.Protocol)
			if protocol == "" {
				protocol = "ip"
			}
			staleCount++
			steps = append(steps, builder.step(
				fmt.Sprintf("delete-stale-aggregate-attachment-%d", staleCount),
				"filter", "del",
				"dev", plan.Scope.Device,
				"parent", plan.Handles.RootHandle,
				"protocol", protocol,
				"pref", fmt.Sprintf("%d", filter.Preference),
				"u32",
			))
		}
		if nftSnapshot != nil {
			for _, filter := range uuidAggregateObservedFWFilters(snapshot, plan.Handles.RootHandle, plan.Handles.ClassID) {
				staleCount++
				protocol := strings.TrimSpace(filter.Protocol)
				if protocol == "" {
					protocol = defaultMarkAttachmentProtocol
				}
				handle := strings.TrimSpace(filter.Handle)
				steps = append(steps, builder.step(
					fmt.Sprintf("delete-stale-aggregate-attachment-%d", staleCount),
					"filter", "del",
					"dev", plan.Scope.Device,
					"parent", plan.Handles.RootHandle,
					"protocol", protocol,
					"pref", fmt.Sprintf("%d", filter.Preference),
					"handle", handle,
					"fw",
				))
			}
			for _, rule := range uuidAggregateObservedMarkAttachmentRules(*nftSnapshot, plan.Scope.Direction, plan.Handles.ClassID) {
				staleCount++
				steps = append(steps, Step{
					Name: fmt.Sprintf("delete-stale-aggregate-attachment-%d", staleCount),
					Command: Command{
						Path: defaultNftBinary,
						Args: []string{"delete", "rule", rule.Family, rule.Table, rule.Chain, "handle", fmt.Sprintf("%d", rule.Handle)},
					},
				})
			}
		}

		for index, rule := range plan.AttachmentExecution.Rules {
			key := uuidAggregateAttachmentRuleKey(plan.Handles.RootHandle, rule)
			if _, ok := matchedExpected[key]; ok {
				continue
			}
			missingCount++
			steps = append(steps, builder.step(
				fmt.Sprintf("upsert-aggregate-attachment-%d", index+1),
				"filter", "replace",
				"dev", plan.Scope.Device,
				"parent", plan.Handles.RootHandle,
				"protocol", rule.protocolToken(),
				"pref", fmt.Sprintf("%d", rule.Preference),
				"u32",
				"match", rule.matchFamilyToken(), rule.MatchField.u32Token(), fmt.Sprintf("%s/%d", rule.Identity.Value, rule.prefixLength()),
				"flowid", rule.AggregateClassID,
			))
		}
	} else if plan.AttachmentExecution.usesMarkAttachments() {
		if nftSnapshot == nil {
			return UUIDAggregatePlan{}, errors.New("aggregate mark-backed apply delta narrowing requires observed nftables state")
		}

		shared := plan.AttachmentExecution.MarkAttachments[0]
		if _, ok := nftSnapshot.Table(shared.Table); !ok {
			steps = append(steps, Step{
				Name: "ensure-aggregate-mark-attachment-table",
				Command: Command{
					Path: defaultNftBinary,
					Args: []string{"add", "table", shared.Table.Family, shared.Table.Name},
				},
			})
		}
		if _, ok := nftSnapshot.Chain(shared.Chain); !ok {
			steps = append(steps, Step{
				Name: "ensure-aggregate-mark-attachment-chain",
				Command: Command{
					Path: defaultNftBinary,
					Args: []string{"add", "chain", shared.Chain.Family, shared.Chain.Table, shared.Chain.Name, shared.Chain.definitionArg()},
				},
			})
		}

		expectedFilters := plan.AttachmentExecution.filterExpectationKeys(plan.Handles.RootHandle)
		expectedRules := plan.AttachmentExecution.markRuleExpectationKeys()
		matchedFilters := make(map[string]struct{}, len(expectedFilters))
		matchedRules := make(map[string]struct{}, len(expectedRules))

		for _, filter := range snapshot.UUIDAggregateAttachmentFilters(plan.Handles.RootHandle, plan.Handles.ClassID) {
			staleCount++
			protocol := strings.TrimSpace(filter.Protocol)
			if protocol == "" {
				protocol = "ip"
			}
			steps = append(steps, builder.step(
				fmt.Sprintf("delete-stale-aggregate-attachment-%d", staleCount),
				"filter", "del",
				"dev", plan.Scope.Device,
				"parent", plan.Handles.RootHandle,
				"protocol", protocol,
				"pref", fmt.Sprintf("%d", filter.Preference),
				"u32",
			))
		}
		for _, filter := range uuidAggregateObservedFWFilters(snapshot, plan.Handles.RootHandle, plan.Handles.ClassID) {
			key := markAttachmentFilterKey(filter)
			if _, ok := expectedFilters[key]; ok {
				if _, seen := matchedFilters[key]; !seen {
					matchedFilters[key] = struct{}{}
					continue
				}
			}
			staleCount++
			protocol := strings.TrimSpace(filter.Protocol)
			if protocol == "" {
				protocol = defaultMarkAttachmentProtocol
			}
			steps = append(steps, builder.step(
				fmt.Sprintf("delete-stale-aggregate-attachment-%d", staleCount),
				"filter", "del",
				"dev", plan.Scope.Device,
				"parent", plan.Handles.RootHandle,
				"protocol", protocol,
				"pref", fmt.Sprintf("%d", filter.Preference),
				"handle", strings.TrimSpace(filter.Handle),
				"fw",
			))
		}
		for _, rule := range uuidAggregateObservedMarkAttachmentRules(*nftSnapshot, plan.Scope.Direction, plan.Handles.ClassID) {
			key := uuidAggregateManagedMarkRuleKey(rule.Family, rule.Table, rule.Chain, rule.Comment)
			if _, ok := expectedRules[key]; ok {
				if _, seen := matchedRules[key]; !seen {
					matchedRules[key] = struct{}{}
					continue
				}
			}
			staleCount++
			steps = append(steps, Step{
				Name: fmt.Sprintf("delete-stale-aggregate-attachment-%d", staleCount),
				Command: Command{
					Path: defaultNftBinary,
					Args: []string{"delete", "rule", rule.Family, rule.Table, rule.Chain, "handle", fmt.Sprintf("%d", rule.Handle)},
				},
			})
		}

		for index, attachment := range plan.AttachmentExecution.MarkAttachments {
			filterKey := markAttachmentFilterKey(FilterState{
				Kind:       "fw",
				Parent:     plan.Handles.RootHandle,
				Preference: attachment.Filter.Preference,
				Handle:     attachment.Filter.handleArg(),
				FlowID:     attachment.Filter.ClassID,
			})
			if _, ok := matchedRules[uuidAggregateManagedMarkRuleKey(attachment.Chain.Family, attachment.Chain.Table, attachment.Chain.Name, attachment.Rule.Comment)]; !ok {
				missingCount++
				args := []string{"add", "rule", attachment.Chain.Family, attachment.Chain.Table, attachment.Chain.Name}
				args = append(args, attachment.Rule.Selector.Expression...)
				args = append(args,
					"counter",
					"meta", "mark", "set", fmt.Sprintf("0x%x", attachment.Rule.Mark),
				)
				if attachment.Rule.PropagateConntrackMark {
					args = append(args, "ct", "mark", "set", fmt.Sprintf("0x%x", attachment.Rule.Mark))
				}
				args = append(args, "comment", attachment.Rule.Comment)
				steps = append(steps, Step{
					Name:    fmt.Sprintf("upsert-aggregate-mark-attachment-rule-%d", index+1),
					Command: Command{Path: defaultNftBinary, Args: args},
				})
			}
			if _, ok := matchedFilters[filterKey]; !ok {
				missingCount++
				steps = append(steps, Step{
					Name: fmt.Sprintf("upsert-aggregate-mark-attachment-filter-%d", index+1),
					Command: Command{
						Path: defaultBinary,
						Args: []string{
							"filter", "replace",
							"dev", plan.Scope.Device,
							"parent", plan.Handles.RootHandle,
							"protocol", attachment.Filter.Protocol,
							"pref", fmt.Sprintf("%d", attachment.Filter.Preference),
							"handle", attachment.Filter.handleArg(),
							"fw",
							"classid", attachment.Filter.ClassID,
						},
					},
				})
			}
		}
	}

	next.Steps = steps
	switch {
	case !rootPresent || !classMatchesRate:
		next.Reason = "aggregate uuid planning replaces the shared class as needed and reconciles the concrete attachment delta for the current live membership"
	case staleCount != 0 && missingCount != 0:
		next.Reason = "aggregate uuid planning reconciles the concrete attachment delta for the current live membership by removing stale or duplicate member rules and adding missing current rules"
	case staleCount != 0:
		next.Reason = "aggregate uuid planning removes stale or duplicate concrete attachment rules that no longer match the current live membership"
	case missingCount != 0:
		next.Reason = "aggregate uuid planning adds missing concrete attachment rules for the current live membership without replacing the matching shared class"
	default:
		next.Reason = "aggregate uuid planning confirms the current concrete attachment set for the live membership"
	}

	if err := next.Validate(); err != nil {
		return UUIDAggregatePlan{}, err
	}

	return next, nil
}

// AppendUUIDAggregateObservedAttachmentCleanup rewrites an aggregate remove
// plan so observed concrete attachment state is cleaned up even when the
// current live membership can no longer reproduce it.
func AppendUUIDAggregateObservedAttachmentCleanup(plan UUIDAggregatePlan, snapshot Snapshot, nftSnapshot *NftablesSnapshot) (UUIDAggregatePlan, error) {
	if err := plan.Validate(); err != nil {
		return UUIDAggregatePlan{}, err
	}
	if err := snapshot.Validate(); err != nil {
		return UUIDAggregatePlan{}, err
	}
	if nftSnapshot != nil {
		if err := nftSnapshot.Validate(); err != nil {
			return UUIDAggregatePlan{}, err
		}
	}
	if plan.Operation != UUIDAggregateOperationRemove {
		return plan, nil
	}

	cleanupSteps := make([]Step, 0)
	for _, filter := range snapshot.UUIDAggregateAttachmentFilters(plan.Handles.RootHandle, plan.Handles.ClassID) {
		protocol := strings.TrimSpace(filter.Protocol)
		if protocol == "" {
			protocol = "ip"
		}
		cleanupSteps = append(cleanupSteps, Planner{Binary: defaultBinary}.step(
			fmt.Sprintf("delete-aggregate-attachment-%d", len(cleanupSteps)+1),
			"filter", "del",
			"dev", plan.Scope.Device,
			"parent", plan.Handles.RootHandle,
			"protocol", protocol,
			"pref", fmt.Sprintf("%d", filter.Preference),
			"u32",
		))
	}
	for _, filter := range uuidAggregateObservedFWFilters(snapshot, plan.Handles.RootHandle, plan.Handles.ClassID) {
		protocol := strings.TrimSpace(filter.Protocol)
		if protocol == "" {
			protocol = defaultMarkAttachmentProtocol
		}
		cleanupSteps = append(cleanupSteps, Planner{Binary: defaultBinary}.step(
			fmt.Sprintf("delete-aggregate-attachment-%d", len(cleanupSteps)+1),
			"filter", "del",
			"dev", plan.Scope.Device,
			"parent", plan.Handles.RootHandle,
			"protocol", protocol,
			"pref", fmt.Sprintf("%d", filter.Preference),
			"handle", strings.TrimSpace(filter.Handle),
			"fw",
		))
	}
	if nftSnapshot != nil {
		for _, rule := range uuidAggregateObservedMarkAttachmentRules(*nftSnapshot, plan.Scope.Direction, plan.Handles.ClassID) {
			cleanupSteps = append(cleanupSteps, Step{
				Name: fmt.Sprintf("delete-aggregate-attachment-%d", len(cleanupSteps)+1),
				Command: Command{
					Path: defaultNftBinary,
					Args: []string{"delete", "rule", rule.Family, rule.Table, rule.Chain, "handle", fmt.Sprintf("%d", rule.Handle)},
				},
			})
		}
	}
	if len(cleanupSteps) == 0 {
		return plan, nil
	}

	next := plan
	retainedSteps := make([]Step, 0, len(plan.Steps))
	classObserved := false
	if _, ok := snapshot.Class(plan.Handles.ClassID); ok {
		classObserved = true
	}
	for _, step := range plan.Steps {
		if strings.HasPrefix(strings.TrimSpace(step.Name), "delete-aggregate-attachment-") {
			continue
		}
		if !classObserved && strings.TrimSpace(step.Name) == "delete-aggregate-class" {
			continue
		}
		retainedSteps = append(retainedSteps, step)
	}
	next.Steps = append(cleanupSteps, retainedSteps...)
	rootCleanupEligible := snapshot.EligibleForRootQDiscCleanupAfterUUIDAggregateAttachmentRemoval(next.Handles.RootHandle, next.Handles.ClassID)
	if !rootCleanupEligible {
		rootCleanupEligible = eligibleForRootQDiscCleanupAfterUUIDAggregateMarkAttachmentRemoval(snapshot, next.Handles.RootHandle, next.Handles.ClassID)
	}
	if !next.CleanupRootQDisc && rootCleanupEligible {
		next.CleanupRootQDisc = true
		next.Steps = append(next.Steps, Planner{Binary: defaultBinary}.step(
			"delete-root-qdisc",
			"qdisc", "del",
			"dev", next.Scope.Device,
			"root",
		))
	}

	if classObserved {
		next.Reason = "aggregate uuid remove planning deletes the shared tc class and removes observed concrete attachment rules for the runtime-local uuid group"
		if next.CleanupRootQDisc {
			next.Reason = "aggregate uuid remove planning deletes the shared tc class, removes observed concrete attachment rules, and cleans up the root htb qdisc when no other RayLimit-managed state remains"
		}
	} else {
		next.Reason = "aggregate uuid remove planning removes observed concrete attachment rules for the runtime-local uuid group"
		if next.CleanupRootQDisc {
			next.Reason = "aggregate uuid remove planning removes observed concrete attachment rules and cleans up the root htb qdisc when no other RayLimit-managed state remains"
		}
	}

	if err := next.Validate(); err != nil {
		return UUIDAggregatePlan{}, err
	}

	return next, nil
}

func attachmentMatchFieldForDirection(direction Direction) UUIDAggregateAttachmentMatchField {
	switch direction {
	case DirectionUpload:
		return UUIDAggregateAttachmentMatchSource
	case DirectionDownload:
		return UUIDAggregateAttachmentMatchDestination
	default:
		return ""
	}
}

func deriveUUIDAggregateAttachmentPreference(classID string, direction Direction, identityValue string) uint32 {
	key := strings.Join([]string{
		"uuid-aggregate-attachment",
		string(direction),
		strings.TrimSpace(classID),
		strings.TrimSpace(identityValue),
	}, "|")

	return 100 + (fnv32a(key) % 32000)
}

func (e UUIDAggregateAttachmentExecution) filterExpectationKeys(rootHandle string) map[string]struct{} {
	if err := validateHandleMajor(rootHandle); err != nil {
		return nil
	}
	if len(e.Rules) == 0 && len(e.MarkAttachments) == 0 {
		return nil
	}

	if e.usesDirectAttachments() {
		expectations := make(map[string]struct{}, len(e.Rules))
		for _, rule := range e.Rules {
			expectations[uuidAggregateAttachmentRuleKey(rootHandle, rule)] = struct{}{}
		}
		return expectations
	}

	expectations := make(map[string]struct{}, len(e.MarkAttachments))
	for _, attachment := range e.MarkAttachments {
		expectations[markAttachmentFilterKey(FilterState{
			Kind:       "fw",
			Parent:     rootHandle,
			Preference: attachment.Filter.Preference,
			Handle:     attachment.Filter.handleArg(),
			FlowID:     attachment.Filter.ClassID,
		})] = struct{}{}
	}

	return expectations
}

func (e UUIDAggregateAttachmentExecution) markRuleExpectationKeys() map[string]struct{} {
	if !e.usesMarkAttachments() {
		return nil
	}

	expectations := make(map[string]struct{}, len(e.MarkAttachments))
	for _, attachment := range e.MarkAttachments {
		expectations[uuidAggregateManagedMarkRuleKey(attachment.Chain.Family, attachment.Chain.Table, attachment.Chain.Name, attachment.Rule.Comment)] = struct{}{}
	}

	return expectations
}

func uuidAggregateAttachmentRuleKey(rootHandle string, rule UUIDAggregateAttachmentRule) string {
	return uuidAggregateAttachmentFilterKey(FilterState{
		Kind:       "u32",
		Parent:     rootHandle,
		Protocol:   rule.protocolToken(),
		Preference: rule.Preference,
		FlowID:     rule.AggregateClassID,
	})
}

func uuidAggregateAttachmentFilterKey(filter FilterState) string {
	return strings.Join([]string{
		strings.TrimSpace(filter.Kind),
		strings.TrimSpace(filter.Parent),
		strings.ToLower(strings.TrimSpace(filter.Protocol)),
		fmt.Sprintf("%d", filter.Preference),
		strings.TrimSpace(filter.FlowID),
	}, "|")
}

func uuidAggregateManagedMarkRuleKey(family string, table string, chain string, comment string) string {
	return strings.Join([]string{
		strings.TrimSpace(family),
		strings.TrimSpace(table),
		strings.TrimSpace(chain),
		strings.TrimSpace(comment),
	}, "|")
}

func uuidAggregateObservedFWFilters(snapshot Snapshot, rootHandle string, classID string) []FilterState {
	if err := validateHandleMajor(rootHandle); err != nil {
		return nil
	}
	if err := validateClassID(classID, rootHandle); err != nil {
		return nil
	}

	filters := make([]FilterState, 0)
	for _, filter := range snapshot.Filters {
		if strings.TrimSpace(filter.Kind) != "fw" {
			continue
		}
		if strings.TrimSpace(filter.Parent) != strings.TrimSpace(rootHandle) {
			continue
		}
		if strings.TrimSpace(filter.FlowID) != strings.TrimSpace(classID) {
			continue
		}
		if _, _, ok := parseTCFilterHandle(strings.TrimSpace(filter.Handle)); !ok {
			continue
		}
		filters = append(filters, filter)
	}
	sort.Slice(filters, func(i, j int) bool {
		if filters[i].Preference != filters[j].Preference {
			return filters[i].Preference < filters[j].Preference
		}
		return strings.TrimSpace(filters[i].Handle) < strings.TrimSpace(filters[j].Handle)
	})

	return filters
}

func uuidAggregateObservedMarkAttachmentRules(nftSnapshot NftablesSnapshot, direction Direction, classID string) []NftablesRuleState {
	prefix := fmt.Sprintf("raylimit:mark-attachment:%s:%s:%s:", IdentityKindUUIDRouting, direction, strings.TrimSpace(classID))
	rules := make([]NftablesRuleState, 0)
	for _, rule := range nftSnapshot.Rules {
		if !strings.HasPrefix(strings.TrimSpace(rule.Comment), prefix) {
			continue
		}
		rules = append(rules, rule)
	}
	sort.Slice(rules, func(i, j int) bool {
		if rules[i].Handle != rules[j].Handle {
			return rules[i].Handle < rules[j].Handle
		}
		return uuidAggregateManagedMarkRuleKey(rules[i].Family, rules[i].Table, rules[i].Chain, rules[i].Comment) <
			uuidAggregateManagedMarkRuleKey(rules[j].Family, rules[j].Table, rules[j].Chain, rules[j].Comment)
	})

	return rules
}

func eligibleForRootQDiscCleanupAfterUUIDAggregateMarkAttachmentRemoval(snapshot Snapshot, rootHandle string, classID string) bool {
	if err := validateHandleMajor(rootHandle); err != nil {
		return false
	}
	if err := validateClassID(classID, rootHandle); err != nil {
		return false
	}
	if len(snapshot.QDiscs) != 1 || len(snapshot.Classes) > 1 {
		return false
	}

	managedFilters := uuidAggregateObservedFWFilters(snapshot, rootHandle, classID)
	if len(managedFilters) == 0 {
		return false
	}
	ignored := make(map[string]struct{}, len(managedFilters))
	for _, filter := range managedFilters {
		ignored[markAttachmentFilterKey(filter)] = struct{}{}
	}

	for _, filter := range snapshot.Filters {
		if strings.TrimSpace(filter.Kind) == "fw" &&
			strings.TrimSpace(filter.Parent) == strings.TrimSpace(rootHandle) &&
			strings.TrimSpace(filter.FlowID) == strings.TrimSpace(classID) {
			if _, ok := ignored[markAttachmentFilterKey(filter)]; ok {
				continue
			}
		}
		return false
	}

	qdisc := snapshot.QDiscs[0]
	if strings.TrimSpace(qdisc.Kind) != "htb" ||
		strings.TrimSpace(qdisc.Handle) != strings.TrimSpace(rootHandle) ||
		strings.TrimSpace(qdisc.Parent) != "root" {
		return false
	}
	if len(snapshot.Classes) == 1 {
		class := snapshot.Classes[0]
		if strings.TrimSpace(class.ClassID) != strings.TrimSpace(classID) ||
			strings.TrimSpace(class.Parent) != strings.TrimSpace(rootHandle) {
			return false
		}
	}

	return true
}

func (p Planner) aggregateAttachmentApplySteps(plan UUIDAggregatePlan) []Step {
	if plan.AttachmentExecution.usesMarkAttachments() {
		attachments := plan.AttachmentExecution.MarkAttachments
		if len(attachments) == 0 {
			return nil
		}
		shared := attachments[0]
		steps := []Step{
			{
				Name: "ensure-aggregate-mark-attachment-table",
				Command: Command{
					Path: defaultNftBinary,
					Args: []string{"add", "table", shared.Table.Family, shared.Table.Name},
				},
			},
			{
				Name: "ensure-aggregate-mark-attachment-chain",
				Command: Command{
					Path: defaultNftBinary,
					Args: []string{"add", "chain", shared.Chain.Family, shared.Chain.Table, shared.Chain.Name, shared.Chain.definitionArg()},
				},
			},
		}
		for index, attachment := range attachments {
			args := []string{"add", "rule", attachment.Chain.Family, attachment.Chain.Table, attachment.Chain.Name}
			args = append(args, attachment.Rule.Selector.Expression...)
			args = append(args,
				"counter",
				"meta", "mark", "set", fmt.Sprintf("0x%x", attachment.Rule.Mark),
			)
			if attachment.Rule.PropagateConntrackMark {
				args = append(args, "ct", "mark", "set", fmt.Sprintf("0x%x", attachment.Rule.Mark))
			}
			args = append(args, "comment", attachment.Rule.Comment)
			steps = append(steps, Step{
				Name: fmt.Sprintf("upsert-aggregate-mark-attachment-rule-%d", index+1),
				Command: Command{
					Path: defaultNftBinary,
					Args: args,
				},
			})
			steps = append(steps, Step{
				Name: fmt.Sprintf("upsert-aggregate-mark-attachment-filter-%d", index+1),
				Command: Command{
					Path: defaultBinary,
					Args: []string{
						"filter", "replace",
						"dev", plan.Scope.Device,
						"parent", plan.Handles.RootHandle,
						"protocol", attachment.Filter.Protocol,
						"pref", fmt.Sprintf("%d", attachment.Filter.Preference),
						"handle", attachment.Filter.handleArg(),
						"fw",
						"classid", attachment.Filter.ClassID,
					},
				},
			})
		}

		return steps
	}

	steps := make([]Step, 0, len(plan.AttachmentExecution.Rules))
	for index, rule := range plan.AttachmentExecution.Rules {
		steps = append(steps, p.step(
			fmt.Sprintf("upsert-aggregate-attachment-%d", index+1),
			"filter", "replace",
			"dev", plan.Scope.Device,
			"parent", plan.Handles.RootHandle,
			"protocol", rule.protocolToken(),
			"pref", fmt.Sprintf("%d", rule.Preference),
			"u32",
			"match", rule.matchFamilyToken(), rule.MatchField.u32Token(), fmt.Sprintf("%s/%d", rule.Identity.Value, rule.prefixLength()),
			"flowid", rule.AggregateClassID,
		))
	}

	return steps
}

func (p Planner) aggregateAttachmentRemoveSteps(plan UUIDAggregatePlan) []Step {
	if plan.AttachmentExecution.usesMarkAttachments() {
		return nil
	}

	steps := make([]Step, 0, len(plan.AttachmentExecution.Rules))
	for index, rule := range plan.AttachmentExecution.Rules {
		steps = append(steps, p.step(
			fmt.Sprintf("delete-aggregate-attachment-%d", index+1),
			"filter", "del",
			"dev", plan.Scope.Device,
			"parent", plan.Handles.RootHandle,
			"protocol", rule.protocolToken(),
			"pref", fmt.Sprintf("%d", rule.Preference),
			"u32",
		))
	}

	return steps
}

func fnv32a(value string) uint32 {
	hash := fnv.New32a()
	_, _ = hash.Write([]byte(value))
	return hash.Sum32()
}
