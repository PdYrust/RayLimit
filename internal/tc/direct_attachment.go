package tc

import (
	"errors"
	"fmt"
	"net/netip"
	"sort"
	"strconv"
	"strings"

	"github.com/PdYrust/RayLimit/internal/limiter"
)

// DirectAttachmentRule captures one concrete tc filter rule for a direct
// non-UUID limiter subject.
type DirectAttachmentRule struct {
	Identity   TrafficIdentity                   `json:"identity"`
	MatchField UUIDAggregateAttachmentMatchField `json:"match_field"`
	Preference uint32                            `json:"preference"`
	ClassID    string                            `json:"class_id"`
	Readiness  BindingReadiness                  `json:"readiness"`
	Confidence BindingConfidence                 `json:"confidence"`
	Reason     string                            `json:"reason,omitempty"`
}

func (r DirectAttachmentRule) Validate() error {
	if err := r.Identity.Validate(); err != nil {
		return fmt.Errorf("invalid direct attachment rule identity: %w", err)
	}
	if r.Identity.Kind != IdentityKindClientIP {
		return errors.New("direct attachment rule currently requires a client-ip identity")
	}
	addr, err := netip.ParseAddr(strings.TrimSpace(r.Identity.Value))
	if err != nil {
		return fmt.Errorf("direct attachment rule requires a valid client ip: %w", err)
	}
	addr = addr.Unmap()
	if !addr.Is4() && !addr.Is6() {
		return errors.New("direct attachment rule requires an ipv4 or ipv6 client ip")
	}
	if !r.MatchField.Valid() {
		return fmt.Errorf("invalid direct attachment rule match field %q", r.MatchField)
	}
	if r.Preference == 0 {
		return errors.New("direct attachment rule preference is required")
	}
	rootHandle, err := rootHandleFromClassID(r.ClassID)
	if err != nil {
		return err
	}
	if err := validateClassID(strings.TrimSpace(r.ClassID), rootHandle); err != nil {
		return err
	}
	if !r.Readiness.Valid() {
		return fmt.Errorf("invalid direct attachment rule readiness %q", r.Readiness)
	}
	if !r.Confidence.Valid() {
		return fmt.Errorf("invalid direct attachment rule confidence %q", r.Confidence)
	}

	return nil
}

func (r DirectAttachmentRule) addr() (netip.Addr, error) {
	addr, err := netip.ParseAddr(strings.TrimSpace(r.Identity.Value))
	if err != nil {
		return netip.Addr{}, err
	}

	return addr.Unmap(), nil
}

func (r DirectAttachmentRule) protocolToken() string {
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

func (r DirectAttachmentRule) matchFamilyToken() string {
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

func (r DirectAttachmentRule) prefixLength() int {
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

func (r DirectAttachmentRule) Key() string {
	return strings.Join([]string{
		string(r.Identity.Kind),
		strings.TrimSpace(r.Identity.Value),
		r.MatchField.u32Token(),
		fmt.Sprintf("%d", r.Preference),
		strings.TrimSpace(r.ClassID),
	}, "|")
}

// DirectAttachmentExecution captures the current concrete direct attachment
// execution view for a non-UUID subject.
type DirectAttachmentExecution struct {
	Rules      []DirectAttachmentRule `json:"rules,omitempty"`
	Readiness  BindingReadiness       `json:"readiness"`
	Confidence BindingConfidence      `json:"confidence"`
	Reason     string                 `json:"reason,omitempty"`
}

func (e DirectAttachmentExecution) Validate() error {
	if !e.Readiness.Valid() {
		return fmt.Errorf("invalid direct attachment execution readiness %q", e.Readiness)
	}
	if !e.Confidence.Valid() {
		return fmt.Errorf("invalid direct attachment execution confidence %q", e.Confidence)
	}
	if len(e.Rules) == 0 {
		if e.Readiness == BindingReadinessReady {
			return errors.New("empty direct attachment execution cannot report ready state")
		}
		return nil
	}
	if e.Readiness != BindingReadinessReady {
		return errors.New("direct attachment execution rules require ready state")
	}

	seen := make(map[string]struct{}, len(e.Rules))
	for index, rule := range e.Rules {
		if err := rule.Validate(); err != nil {
			return fmt.Errorf("invalid direct attachment execution rule at index %d: %w", index, err)
		}
		key := rule.Key()
		if _, ok := seen[key]; ok {
			return fmt.Errorf("duplicate direct attachment execution rule %q", key)
		}
		seen[key] = struct{}{}
	}

	return nil
}

// DirectAttachmentObservation captures whether the current observed tc state
// already includes the expected direct attachment rules.
type DirectAttachmentObservation struct {
	Comparable bool `json:"comparable"`
	Matched    bool `json:"matched"`
}

func (o DirectAttachmentObservation) Validate() error {
	if o.Matched && !o.Comparable {
		return errors.New("direct attachment observation cannot report a match without comparable state")
	}

	return nil
}

// BuildDirectAttachmentExecution derives the current concrete direct attachment
// execution set. Client-ip subjects are concretely attachable today for IPv4
// and for IPv6 traffic that matches the current u32 backend assumptions.
func BuildDirectAttachmentExecution(binding Binding, scope Scope, classID string) (DirectAttachmentExecution, error) {
	if err := binding.Validate(); err != nil {
		return DirectAttachmentExecution{}, err
	}
	if err := scope.Validate(); err != nil {
		return DirectAttachmentExecution{}, err
	}
	rootHandle, err := rootHandleFromClassID(classID)
	if err != nil {
		return DirectAttachmentExecution{}, err
	}
	if err := validateClassID(strings.TrimSpace(classID), rootHandle); err != nil {
		return DirectAttachmentExecution{}, err
	}

	execution := DirectAttachmentExecution{
		Readiness:  BindingReadinessUnavailable,
		Confidence: binding.Confidence,
		Reason:     strings.TrimSpace(binding.Reason),
	}
	if binding.Identity == nil {
		if execution.Reason == "" {
			execution.Reason = "no concrete traffic identity is available for direct attachment execution"
		}
		if err := execution.Validate(); err != nil {
			return DirectAttachmentExecution{}, err
		}
		return execution, nil
	}

	switch binding.Identity.Kind {
	case IdentityKindClientIP:
		addr, err := netip.ParseAddr(strings.TrimSpace(binding.Identity.Value))
		if err != nil {
			execution.Reason = fmt.Sprintf("concrete direct attachment requires a valid client ip: %v", err)
			if err := execution.Validate(); err != nil {
				return DirectAttachmentExecution{}, err
			}
			return execution, nil
		}
		addr = addr.Unmap()
		if !addr.Is4() && !addr.Is6() {
			execution.Reason = "concrete direct attachment currently requires an ipv4 or ipv6 client ip"
			if err := execution.Validate(); err != nil {
				return DirectAttachmentExecution{}, err
			}
			return execution, nil
		}

		matchField := attachmentMatchFieldForDirection(scope.Direction)
		if !matchField.Valid() {
			return DirectAttachmentExecution{}, fmt.Errorf("unsupported direct attachment direction %q", scope.Direction)
		}

		rule := DirectAttachmentRule{
			Identity: TrafficIdentity{
				Kind:  IdentityKindClientIP,
				Value: addr.String(),
			},
			MatchField: matchField,
			Preference: deriveDirectAttachmentPreference(classID, scope.Direction, addr.String()),
			ClassID:    strings.TrimSpace(classID),
			Readiness:  BindingReadinessReady,
			Confidence: binding.Confidence,
			Reason:     "u32 client-ip attachment rule targets the selected tc class",
		}
		if addr.Is6() {
			rule.Confidence = BindingConfidenceMedium
			rule.Reason = "u32 ipv6 client-ip attachment rule targets the selected tc class and assumes no ipv6 extension headers"
		}
		if err := rule.Validate(); err != nil {
			return DirectAttachmentExecution{}, fmt.Errorf("invalid direct attachment execution rule: %w", err)
		}

		execution.Rules = []DirectAttachmentRule{rule}
		execution.Readiness = BindingReadinessReady
		execution.Reason = "concrete client-ip attachment rule was derived for the selected direct limiter subject"
		if addr.Is6() {
			execution.Confidence = BindingConfidenceMedium
			execution.Reason = "concrete ipv6 client-ip attachment rule was derived for the selected direct limiter subject; the current u32 backend assumes no ipv6 extension headers"
		}
	default:
		switch binding.Identity.Kind {
		case IdentityKindSession:
			execution.Reason = "concrete direct attachment execution for connection session ids is unavailable until a trustworthy runtime-aware traffic classifier exists"
		case IdentityKindInbound:
			execution.Reason = "concrete inbound enforcement uses the mark-backed nftables and tc fw backend when a trustworthy inbound selector is available; there is no direct u32 attachment path for inbound tags"
		case IdentityKindOutbound:
			execution.Reason = "concrete outbound enforcement uses the mark-backed nftables and tc fw backend when readable Xray config proves one unique non-zero outbound socket mark; there is no direct u32 attachment path for outbound tags"
		default:
			if execution.Reason == "" {
				execution.Reason = fmt.Sprintf("%s identities do not currently have a concrete direct tc attachment backend", binding.Identity.Kind)
			}
		}
	}

	if err := execution.Validate(); err != nil {
		return DirectAttachmentExecution{}, err
	}

	return execution, nil
}

// ObserveDirectAttachment reports whether the expected direct attachment rules
// are already present in the observed tc snapshot.
func ObserveDirectAttachment(snapshot Snapshot, plan Plan) (DirectAttachmentObservation, error) {
	if err := snapshot.Validate(); err != nil {
		return DirectAttachmentObservation{}, err
	}
	if err := plan.Validate(); err != nil {
		return DirectAttachmentObservation{}, err
	}

	observation := DirectAttachmentObservation{}
	if plan.AttachmentExecution.Readiness != BindingReadinessReady {
		if err := observation.Validate(); err != nil {
			return DirectAttachmentObservation{}, err
		}
		return observation, nil
	}

	expected := plan.AttachmentExecution.filterExpectationKeys()
	if len(expected) == 0 {
		if err := observation.Validate(); err != nil {
			return DirectAttachmentObservation{}, err
		}
		return observation, nil
	}

	observed := snapshot.DirectAttachmentFilters(plan.Handles.RootHandle, plan.Handles.ClassID, plan.AttachmentExecution)
	observation.Comparable = true
	if len(observed) == len(expected) {
		matched := true
		for _, filter := range observed {
			if _, ok := expected[directAttachmentFilterKey(filter)]; !ok {
				matched = false
				break
			}
		}
		observation.Matched = matched
	}

	if err := observation.Validate(); err != nil {
		return DirectAttachmentObservation{}, err
	}

	return observation, nil
}

// AppendObservedDirectAttachmentCleanup narrows one direct-attachment remove
// plan to the observed cleanup delta when the managed class is already gone.
func AppendObservedDirectAttachmentCleanup(plan Plan, snapshot Snapshot) (Plan, error) {
	if err := plan.Validate(); err != nil {
		return Plan{}, err
	}
	if plan.Action.Kind != limiter.ActionRemove {
		return Plan{}, errors.New("observed direct attachment cleanup requires a remove plan")
	}
	if err := snapshot.Validate(); err != nil {
		return Plan{}, err
	}
	if plan.AttachmentExecution.Readiness != BindingReadinessReady {
		return plan, nil
	}
	if _, ok := snapshot.Class(plan.Handles.ClassID); ok {
		return plan, nil
	}

	next := plan
	retained := make([]Step, 0, len(plan.Steps))
	for _, step := range plan.Steps {
		if strings.TrimSpace(step.Name) == "delete-class" {
			continue
		}
		retained = append(retained, step)
	}
	next.Steps = retained
	if err := next.Validate(); err != nil {
		return Plan{}, err
	}

	return next, nil
}

func (e DirectAttachmentExecution) rulePreferences() map[uint32]struct{} {
	if len(e.Rules) == 0 {
		return nil
	}

	preferences := make(map[uint32]struct{}, len(e.Rules))
	for _, rule := range e.Rules {
		preferences[rule.Preference] = struct{}{}
	}

	return preferences
}

func (e DirectAttachmentExecution) filterExpectationKeys() map[string]struct{} {
	if len(e.Rules) == 0 {
		return nil
	}

	expectations := make(map[string]struct{}, len(e.Rules))
	for _, rule := range e.Rules {
		expectations[directAttachmentFilterKey(FilterState{
			Protocol:   rule.protocolToken(),
			Preference: rule.Preference,
		})] = struct{}{}
	}

	return expectations
}

func deriveDirectAttachmentPreference(classID string, direction Direction, identityValue string) uint32 {
	key := strings.Join([]string{
		"direct-attachment",
		string(direction),
		strings.TrimSpace(classID),
		strings.TrimSpace(identityValue),
	}, "|")

	return 100 + (fnv32a(key) % 32000)
}

func directAttachmentFilters(filters []FilterState, rootHandle string, classID string, execution DirectAttachmentExecution) []FilterState {
	if err := validateHandleMajor(rootHandle); err != nil {
		return nil
	}
	if err := validateClassID(classID, rootHandle); err != nil {
		return nil
	}
	expectations := execution.filterExpectationKeys()
	if len(expectations) == 0 {
		return nil
	}

	matches := make([]FilterState, 0, len(filters))
	for _, filter := range filters {
		if strings.TrimSpace(filter.Kind) != "u32" {
			continue
		}
		if strings.TrimSpace(filter.Parent) != strings.TrimSpace(rootHandle) {
			continue
		}
		if strings.TrimSpace(filter.FlowID) != strings.TrimSpace(classID) {
			continue
		}
		if _, ok := expectations[directAttachmentFilterKey(filter)]; !ok {
			continue
		}

		matches = append(matches, filter)
	}

	sort.Slice(matches, func(i, j int) bool {
		if matches[i].Preference != matches[j].Preference {
			return matches[i].Preference < matches[j].Preference
		}
		left := strings.Join([]string{
			matches[i].Kind,
			matches[i].Parent,
			matches[i].Protocol,
			matches[i].FlowID,
		}, "|")
		right := strings.Join([]string{
			matches[j].Kind,
			matches[j].Parent,
			matches[j].Protocol,
			matches[j].FlowID,
		}, "|")
		return left < right
	})

	return matches
}

func directAttachmentFilterKey(filter FilterState) string {
	return strings.Join([]string{
		strings.ToLower(strings.TrimSpace(filter.Protocol)),
		strconv.FormatUint(uint64(filter.Preference), 10),
	}, "|")
}
