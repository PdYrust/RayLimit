package tc

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strconv"
	"strings"

	"github.com/PdYrust/RayLimit/internal/limiter"
)

const (
	defaultMarkAttachmentTableName   = "raylimit"
	defaultMarkAttachmentTableFamily = "inet"
	defaultMarkAttachmentChainType   = "filter"
	defaultMarkAttachmentPriority    = -150
	defaultMarkAttachmentProtocol    = "all"
	defaultMarkAttachmentMask        = ^uint32(0)
)

// MarkAttachmentBackend identifies a non-IP attachment backend that combines
// nftables marking with tc classification.
type MarkAttachmentBackend string

const (
	MarkAttachmentBackendNFTablesTCFW MarkAttachmentBackend = "nftables_tc_fw"
)

func (b MarkAttachmentBackend) Valid() bool {
	switch b {
	case MarkAttachmentBackendNFTablesTCFW:
		return true
	default:
		return false
	}
}

// MarkAttachmentSelector captures the runtime-assisted nftables selector
// expression that will set a managed packet and conntrack mark.
type MarkAttachmentSelector struct {
	Expression  []string `json:"expression,omitempty"`
	Description string   `json:"description,omitempty"`
}

func (s MarkAttachmentSelector) Validate() error {
	if len(s.Expression) == 0 {
		return errors.New("mark attachment selector expression is required")
	}
	for index, token := range s.Expression {
		if strings.TrimSpace(token) == "" {
			return fmt.Errorf("mark attachment selector token at index %d is blank", index)
		}
	}

	return nil
}

func (s MarkAttachmentSelector) key() string {
	parts := make([]string, 0, len(s.Expression))
	for _, token := range s.Expression {
		parts = append(parts, strings.TrimSpace(token))
	}

	return strings.Join(parts, " ")
}

// MarkAttachmentTableSpec identifies the nftables table RayLimit manages for a
// mark-backed attachment path.
type MarkAttachmentTableSpec struct {
	Family string `json:"family"`
	Name   string `json:"name"`
}

func (s MarkAttachmentTableSpec) Validate() error {
	if !validNftablesFamily(s.Family) {
		return fmt.Errorf("invalid nftables table family %q", s.Family)
	}
	if strings.TrimSpace(s.Name) == "" {
		return errors.New("nftables table name is required")
	}

	return nil
}

// MarkAttachmentChainSpec identifies the base chain that applies managed packet
// marks before tc classifies them with the fw filter.
type MarkAttachmentChainSpec struct {
	Family   string `json:"family"`
	Table    string `json:"table"`
	Name     string `json:"name"`
	Type     string `json:"type"`
	Hook     string `json:"hook"`
	Priority int    `json:"priority"`
}

func (s MarkAttachmentChainSpec) Validate() error {
	if !validNftablesFamily(s.Family) {
		return fmt.Errorf("invalid nftables chain family %q", s.Family)
	}
	if strings.TrimSpace(s.Table) == "" {
		return errors.New("nftables chain table is required")
	}
	if strings.TrimSpace(s.Name) == "" {
		return errors.New("nftables chain name is required")
	}
	if strings.TrimSpace(s.Type) != defaultMarkAttachmentChainType {
		return fmt.Errorf("unsupported nftables chain type %q", s.Type)
	}
	if !validNftablesHook(s.Hook) {
		return fmt.Errorf("invalid nftables chain hook %q", s.Hook)
	}

	return nil
}

func (s MarkAttachmentChainSpec) definitionArg() string {
	return fmt.Sprintf("{ type %s hook %s priority %d; }", s.Type, s.Hook, s.Priority)
}

// MarkAttachmentRuleSpec identifies one managed nftables rule that sets the
// mark consumed by tc fw classification.
type MarkAttachmentRuleSpec struct {
	Selector               MarkAttachmentSelector `json:"selector"`
	Comment                string                 `json:"comment"`
	Mark                   uint32                 `json:"mark"`
	PropagateConntrackMark bool                   `json:"propagate_conntrack_mark"`
}

func (s MarkAttachmentRuleSpec) Validate() error {
	if err := s.Selector.Validate(); err != nil {
		return fmt.Errorf("invalid mark attachment selector: %w", err)
	}
	if strings.TrimSpace(s.Comment) == "" {
		return errors.New("mark attachment rule comment is required")
	}
	if s.Mark == 0 {
		return errors.New("mark attachment rule mark is required")
	}

	return nil
}

// MarkAttachmentRestoreRuleSpec identifies one managed nftables rule that
// restores the packet mark from the managed conntrack mark before tc fw
// classification sees the packet on egress.
type MarkAttachmentRestoreRuleSpec struct {
	Comment string `json:"comment"`
}

func (s MarkAttachmentRestoreRuleSpec) Validate() error {
	if strings.TrimSpace(s.Comment) == "" {
		return errors.New("mark attachment restore rule comment is required")
	}

	return nil
}

// MarkAttachmentFilterSpec identifies the managed tc fw filter that matches the
// nftables mark and targets the selected class.
type MarkAttachmentFilterSpec struct {
	Parent     string `json:"parent"`
	Protocol   string `json:"protocol"`
	Preference uint32 `json:"preference"`
	Mark       uint32 `json:"mark"`
	Mask       uint32 `json:"mask"`
	ClassID    string `json:"class_id"`
}

func (s MarkAttachmentFilterSpec) Validate() error {
	if err := validateHandleMajor(s.Parent); err != nil {
		return fmt.Errorf("invalid mark attachment filter parent: %w", err)
	}
	if strings.TrimSpace(s.Protocol) == "" {
		return errors.New("mark attachment filter protocol is required")
	}
	if s.Preference == 0 {
		return errors.New("mark attachment filter preference is required")
	}
	if s.Mark == 0 {
		return errors.New("mark attachment filter mark is required")
	}
	if s.Mask == 0 {
		return errors.New("mark attachment filter mask is required")
	}
	rootHandle, err := rootHandleFromClassID(s.ClassID)
	if err != nil {
		return err
	}
	if err := validateClassID(strings.TrimSpace(s.ClassID), rootHandle); err != nil {
		return err
	}

	return nil
}

func (s MarkAttachmentFilterSpec) handleArg() string {
	return fmt.Sprintf("0x%x/0x%x", s.Mark, s.Mask)
}

// MarkAttachmentExecution captures one concrete mark-backed attachment backend
// plan that later limiter-specific phases can embed into a generic Plan.
type MarkAttachmentExecution struct {
	Backend              MarkAttachmentBackend          `json:"backend,omitempty"`
	Identity             TrafficIdentity                `json:"identity,omitempty"`
	Table                MarkAttachmentTableSpec        `json:"table,omitempty"`
	Chain                MarkAttachmentChainSpec        `json:"chain,omitempty"`
	Rule                 MarkAttachmentRuleSpec         `json:"rule,omitempty"`
	RestoreChain         *MarkAttachmentChainSpec       `json:"restore_chain,omitempty"`
	RestoreRule          *MarkAttachmentRestoreRuleSpec `json:"restore_rule,omitempty"`
	Filter               MarkAttachmentFilterSpec       `json:"filter,omitempty"`
	ManageChainLifecycle bool                           `json:"manage_chain_lifecycle,omitempty"`
	Readiness            BindingReadiness               `json:"readiness"`
	Confidence           BindingConfidence              `json:"confidence"`
	Reason               string                         `json:"reason,omitempty"`
}

func (e MarkAttachmentExecution) Validate() error {
	if !e.Readiness.Valid() {
		return fmt.Errorf("invalid mark attachment execution readiness %q", e.Readiness)
	}
	if !e.Confidence.Valid() {
		return fmt.Errorf("invalid mark attachment execution confidence %q", e.Confidence)
	}
	if e.Readiness != BindingReadinessReady {
		return nil
	}
	if !e.Backend.Valid() {
		return fmt.Errorf("invalid mark attachment backend %q", e.Backend)
	}
	if err := e.Identity.Validate(); err != nil {
		return fmt.Errorf("invalid mark attachment execution identity: %w", err)
	}
	switch e.Identity.Kind {
	case IdentityKindInbound, IdentityKindOutbound:
	default:
		return fmt.Errorf("mark attachment execution does not support identity kind %q", e.Identity.Kind)
	}
	if err := e.Table.Validate(); err != nil {
		return fmt.Errorf("invalid mark attachment execution table: %w", err)
	}
	if err := e.Chain.Validate(); err != nil {
		return fmt.Errorf("invalid mark attachment execution chain: %w", err)
	}
	if e.Table.Family != e.Chain.Family || strings.TrimSpace(e.Table.Name) != strings.TrimSpace(e.Chain.Table) {
		return errors.New("mark attachment execution chain does not match the selected table")
	}
	if err := e.Rule.Validate(); err != nil {
		return fmt.Errorf("invalid mark attachment execution rule: %w", err)
	}
	if (e.RestoreChain == nil) != (e.RestoreRule == nil) {
		return errors.New("mark attachment execution restore chain and restore rule must both be present or both be omitted")
	}
	if e.RestoreChain != nil {
		if err := e.RestoreChain.Validate(); err != nil {
			return fmt.Errorf("invalid mark attachment execution restore chain: %w", err)
		}
		if e.RestoreChain.Family != e.Table.Family || strings.TrimSpace(e.RestoreChain.Table) != strings.TrimSpace(e.Table.Name) {
			return errors.New("mark attachment execution restore chain does not match the selected table")
		}
		if err := e.RestoreRule.Validate(); err != nil {
			return fmt.Errorf("invalid mark attachment execution restore rule: %w", err)
		}
	}
	if err := e.Filter.Validate(); err != nil {
		return fmt.Errorf("invalid mark attachment execution filter: %w", err)
	}
	if strings.TrimSpace(e.Filter.Parent) == "" {
		return errors.New("mark attachment execution filter parent is required")
	}

	return nil
}

func (e MarkAttachmentExecution) usesRestoreRule() bool {
	return e.RestoreChain != nil && e.RestoreRule != nil
}

// MarkAttachmentInput captures the minimum route-tag-aware inputs needed to
// build a reusable nftables mark to tc fw attachment backend.
type MarkAttachmentInput struct {
	Identity             TrafficIdentity        `json:"identity"`
	Scope                Scope                  `json:"scope"`
	ClassID              string                 `json:"class_id"`
	Selector             MarkAttachmentSelector `json:"selector,omitempty"`
	PacketMark           uint32                 `json:"packet_mark,omitempty"`
	TableFamily          string                 `json:"table_family,omitempty"`
	TableName            string                 `json:"table_name,omitempty"`
	ChainName            string                 `json:"chain_name,omitempty"`
	ChainHook            string                 `json:"chain_hook,omitempty"`
	ChainPriority        int                    `json:"chain_priority,omitempty"`
	ManageChainLifecycle bool                   `json:"manage_chain_lifecycle,omitempty"`
	Confidence           BindingConfidence      `json:"confidence,omitempty"`
}

func (i MarkAttachmentInput) Validate() error {
	if err := i.Identity.Validate(); err != nil {
		return fmt.Errorf("invalid mark attachment input identity: %w", err)
	}
	if err := i.Scope.Validate(); err != nil {
		return fmt.Errorf("invalid mark attachment input scope: %w", err)
	}
	rootHandle, err := rootHandleFromClassID(i.ClassID)
	if err != nil {
		return err
	}
	if err := validateClassID(strings.TrimSpace(i.ClassID), rootHandle); err != nil {
		return err
	}
	if i.Confidence != "" && !i.Confidence.Valid() {
		return fmt.Errorf("invalid mark attachment input confidence %q", i.Confidence)
	}

	return nil
}

// BuildMarkAttachmentExecution derives a reusable mark-backed attachment plan.
// It becomes ready only when a supported identity and a concrete nftables
// selector expression are both available.
func BuildMarkAttachmentExecution(input MarkAttachmentInput) (MarkAttachmentExecution, error) {
	if err := input.Validate(); err != nil {
		return MarkAttachmentExecution{}, err
	}

	execution := MarkAttachmentExecution{
		Readiness:  BindingReadinessUnavailable,
		Confidence: bindingConfidenceOrDefault(input.Confidence, BindingConfidenceMedium),
	}

	switch input.Identity.Kind {
	case IdentityKindInbound, IdentityKindOutbound:
	default:
		execution.Reason = "mark-backed attachment currently requires an inbound-tag or outbound-tag identity"
		if err := execution.Validate(); err != nil {
			return MarkAttachmentExecution{}, err
		}
		return execution, nil
	}

	if len(input.Selector.Expression) == 0 {
		execution.Reason = fmt.Sprintf("mark-backed attachment requires a runtime-assisted nftables selector expression for %s traffic", input.Identity.Kind)
		if err := execution.Validate(); err != nil {
			return MarkAttachmentExecution{}, err
		}
		return execution, nil
	}
	if err := input.Selector.Validate(); err != nil {
		return MarkAttachmentExecution{}, err
	}

	family := strings.TrimSpace(input.TableFamily)
	if family == "" {
		family = defaultMarkAttachmentTableFamily
	}
	tableName := strings.TrimSpace(input.TableName)
	if tableName == "" {
		tableName = defaultMarkAttachmentTableName
	}
	chainName := strings.TrimSpace(input.ChainName)
	if chainName == "" {
		chainName = defaultMarkAttachmentChainName(input.Identity.Kind, input.Scope.Direction)
	}
	chainHook := strings.TrimSpace(input.ChainHook)
	if chainHook == "" {
		chainHook = defaultMarkAttachmentChainHook(input.Identity.Kind)
	}
	chainPriority := input.ChainPriority
	if chainPriority == 0 {
		chainPriority = defaultMarkAttachmentPriority
	}

	mark := input.PacketMark
	if mark == 0 {
		mark = deriveMarkAttachmentMark(input.ClassID, input.Identity, input.Scope.Direction)
	}
	selectorFingerprint := fnv32a(input.Selector.key())
	comment := deriveMarkAttachmentComment(input.Identity, input.Scope.Direction, input.ClassID, mark, selectorFingerprint)
	restoreComment := deriveMarkAttachmentRestoreComment(input.Identity, input.Scope.Direction, input.ClassID, mark)
	preference := deriveMarkAttachmentPreference(input.ClassID, input.Identity, input.Scope.Direction)

	execution = MarkAttachmentExecution{
		Backend:  MarkAttachmentBackendNFTablesTCFW,
		Identity: input.Identity,
		Table: MarkAttachmentTableSpec{
			Family: family,
			Name:   tableName,
		},
		Chain: MarkAttachmentChainSpec{
			Family:   family,
			Table:    tableName,
			Name:     chainName,
			Type:     defaultMarkAttachmentChainType,
			Hook:     chainHook,
			Priority: chainPriority,
		},
		Rule: MarkAttachmentRuleSpec{
			Selector:               input.Selector,
			Comment:                comment,
			Mark:                   mark,
			PropagateConntrackMark: true,
		},
		Filter: MarkAttachmentFilterSpec{
			Parent:     input.Scope.rootHandle(),
			Protocol:   defaultMarkAttachmentProtocol,
			Preference: preference,
			Mark:       mark,
			Mask:       defaultMarkAttachmentMask,
			ClassID:    strings.TrimSpace(input.ClassID),
		},
		ManageChainLifecycle: input.ManageChainLifecycle || (!input.ManageChainLifecycle && strings.TrimSpace(input.ChainName) == ""),
		Readiness:            BindingReadinessReady,
		Confidence:           bindingConfidenceOrDefault(input.Confidence, BindingConfidenceMedium),
		Reason:               "nftables packet and conntrack marking plus tc fw classification target the selected tc class",
	}
	if input.Identity.Kind == IdentityKindInbound {
		execution.RestoreChain = &MarkAttachmentChainSpec{
			Family:   family,
			Table:    tableName,
			Name:     defaultMarkAttachmentRestoreChainName(input.Identity.Kind, input.Scope.Direction),
			Type:     defaultMarkAttachmentChainType,
			Hook:     defaultMarkAttachmentRestoreChainHook(input.Identity.Kind),
			Priority: chainPriority,
		}
		execution.RestoreRule = &MarkAttachmentRestoreRuleSpec{
			Comment: restoreComment,
		}
		execution.Reason = "nftables input marking plus output mark restoration and tc fw classification target the selected inbound class"
	} else if input.Identity.Kind == IdentityKindOutbound {
		execution.Reason = "nftables output matching on the selected outbound socket mark plus tc fw classification target the selected outbound class"
	}
	if err := execution.Validate(); err != nil {
		return MarkAttachmentExecution{}, err
	}

	return execution, nil
}

func bindingConfidenceOrDefault(value BindingConfidence, defaultValue BindingConfidence) BindingConfidence {
	if value.Valid() {
		return value
	}

	return defaultValue
}

func defaultMarkAttachmentChainName(kind IdentityKind, direction Direction) string {
	return fmt.Sprintf("raylimit_%s_%s", kind, direction)
}

func defaultMarkAttachmentChainHook(kind IdentityKind) string {
	switch kind {
	case IdentityKindInbound:
		return "input"
	case IdentityKindOutbound:
		return "output"
	default:
		return ""
	}
}

func defaultMarkAttachmentRestoreChainName(kind IdentityKind, direction Direction) string {
	return fmt.Sprintf("raylimit_%s_%s_restore", kind, direction)
}

func defaultMarkAttachmentRestoreChainHook(kind IdentityKind) string {
	switch kind {
	case IdentityKindInbound:
		return "output"
	default:
		return ""
	}
}

func deriveMarkAttachmentMark(classID string, identity TrafficIdentity, direction Direction) uint32 {
	key := strings.Join([]string{
		"mark-attachment",
		strings.TrimSpace(classID),
		string(direction),
		string(identity.Kind),
		strings.TrimSpace(identity.Value),
	}, "|")
	mark := fnv32a(key)
	if mark == 0 {
		return 1
	}

	return mark
}

func deriveMarkAttachmentPreference(classID string, identity TrafficIdentity, direction Direction) uint32 {
	key := strings.Join([]string{
		"mark-attachment-pref",
		strings.TrimSpace(classID),
		string(direction),
		string(identity.Kind),
		strings.TrimSpace(identity.Value),
	}, "|")

	return 100 + (fnv32a(key) % 32000)
}

func deriveMarkAttachmentComment(identity TrafficIdentity, direction Direction, classID string, mark uint32, selectorFingerprint uint32) string {
	return fmt.Sprintf(
		"raylimit:mark-attachment:%s:%s:%s:%08x:%08x",
		identity.Kind,
		direction,
		strings.TrimSpace(classID),
		mark,
		selectorFingerprint,
	)
}

func deriveMarkAttachmentRestoreComment(identity TrafficIdentity, direction Direction, classID string, mark uint32) string {
	return fmt.Sprintf(
		"raylimit:mark-attachment-restore:%s:%s:%s:%08x",
		identity.Kind,
		direction,
		strings.TrimSpace(classID),
		mark,
	)
}

// MarkAttachmentObservation captures whether observed nftables and tc state are
// sufficient to compare one managed mark-backed attachment plan.
type MarkAttachmentObservation struct {
	Comparable          bool `json:"comparable"`
	TablePresent        bool `json:"table_present"`
	ChainPresent        bool `json:"chain_present"`
	RuleMatched         bool `json:"rule_matched"`
	RestoreChainPresent bool `json:"restore_chain_present,omitempty"`
	RestoreRuleMatched  bool `json:"restore_rule_matched,omitempty"`
	FilterMatched       bool `json:"filter_matched"`
	Matched             bool `json:"matched"`
}

func (o MarkAttachmentObservation) Validate() error {
	if o.Matched && !o.Comparable {
		return errors.New("mark attachment observation cannot report a match without comparable state")
	}
	if o.Matched && (!o.TablePresent || !o.ChainPresent || !o.RuleMatched || !o.FilterMatched) {
		return errors.New("mark attachment observation cannot report a full match without table, chain, rule, and filter matches")
	}
	if o.Matched && o.RestoreChainPresent != o.RestoreRuleMatched {
		return errors.New("mark attachment observation cannot report a full match with only partial restore rule state")
	}

	return nil
}

// ObserveMarkAttachment compares observed nftables and tc state with one
// managed mark-backed attachment execution plan.
func ObserveMarkAttachment(tcSnapshot Snapshot, nftSnapshot NftablesSnapshot, execution MarkAttachmentExecution) (MarkAttachmentObservation, error) {
	if err := tcSnapshot.Validate(); err != nil {
		return MarkAttachmentObservation{}, err
	}
	if err := nftSnapshot.Validate(); err != nil {
		return MarkAttachmentObservation{}, err
	}
	if err := execution.Validate(); err != nil {
		return MarkAttachmentObservation{}, err
	}

	observation := MarkAttachmentObservation{}
	if execution.Readiness != BindingReadinessReady {
		if err := observation.Validate(); err != nil {
			return MarkAttachmentObservation{}, err
		}
		return observation, nil
	}

	observation.Comparable = true
	_, observation.TablePresent = nftSnapshot.Table(execution.Table)
	_, observation.ChainPresent = nftSnapshot.Chain(execution.Chain)
	observation.RuleMatched = len(nftSnapshot.MarkAttachmentRules(execution)) == 1
	if execution.usesRestoreRule() {
		_, observation.RestoreChainPresent = nftSnapshot.Chain(*execution.RestoreChain)
		observation.RestoreRuleMatched = len(nftSnapshot.MarkAttachmentRestoreRules(execution)) == 1
	} else {
		observation.RestoreChainPresent = true
		observation.RestoreRuleMatched = true
	}
	observation.FilterMatched = len(tcSnapshot.MarkAttachmentFilters(execution.Filter.Parent, execution.Filter.ClassID, execution)) == 1
	observation.Matched = observation.TablePresent &&
		observation.ChainPresent &&
		observation.RuleMatched &&
		observation.RestoreChainPresent &&
		observation.RestoreRuleMatched &&
		observation.FilterMatched

	if err := observation.Validate(); err != nil {
		return MarkAttachmentObservation{}, err
	}

	return observation, nil
}

// AppendMarkAttachmentApply appends the missing managed nftables and tc fw
// steps to an existing plan.
func AppendMarkAttachmentApply(plan Plan, tcSnapshot Snapshot, nftSnapshot NftablesSnapshot) (Plan, error) {
	if err := plan.Validate(); err != nil {
		return Plan{}, err
	}
	if plan.MarkAttachment == nil || plan.MarkAttachment.Readiness != BindingReadinessReady {
		return plan, nil
	}
	if plan.Action.Kind != limiter.ActionApply && plan.Action.Kind != limiter.ActionReconcile {
		return Plan{}, errors.New("mark attachment apply steps require an apply or reconcile plan")
	}
	if err := tcSnapshot.Validate(); err != nil {
		return Plan{}, err
	}
	if err := nftSnapshot.Validate(); err != nil {
		return Plan{}, err
	}

	observation, err := ObserveMarkAttachment(tcSnapshot, nftSnapshot, *plan.MarkAttachment)
	if err != nil {
		return Plan{}, err
	}

	next := plan
	retained := retainNonMarkAttachmentSteps(plan.Steps)
	next.NoOp = plan.NoOp
	steps := append([]Step(nil), retained...)

	if !observation.TablePresent {
		steps = append(steps, Step{
			Name: "ensure-mark-attachment-table",
			Command: Command{
				Path: defaultNftBinary,
				Args: []string{"add", "table", next.MarkAttachment.Table.Family, next.MarkAttachment.Table.Name},
			},
		})
	}
	if !observation.ChainPresent {
		steps = append(steps, Step{
			Name: "ensure-mark-attachment-chain",
			Command: Command{
				Path: defaultNftBinary,
				Args: []string{"add", "chain", next.MarkAttachment.Chain.Family, next.MarkAttachment.Chain.Table, next.MarkAttachment.Chain.Name, next.MarkAttachment.Chain.definitionArg()},
			},
		})
	}
	if plan.MarkAttachment.usesRestoreRule() && !observation.RestoreChainPresent {
		steps = append(steps, Step{
			Name: "ensure-mark-attachment-restore-chain",
			Command: Command{
				Path: defaultNftBinary,
				Args: []string{"add", "chain", next.MarkAttachment.RestoreChain.Family, next.MarkAttachment.RestoreChain.Table, next.MarkAttachment.RestoreChain.Name, next.MarkAttachment.RestoreChain.definitionArg()},
			},
		})
	}
	if !observation.RuleMatched {
		args := []string{
			"add", "rule",
			next.MarkAttachment.Chain.Family,
			next.MarkAttachment.Chain.Table,
			next.MarkAttachment.Chain.Name,
		}
		args = append(args, next.MarkAttachment.Rule.Selector.Expression...)
		args = append(args,
			"counter",
			"meta", "mark", "set", fmt.Sprintf("0x%x", next.MarkAttachment.Rule.Mark),
		)
		if next.MarkAttachment.Rule.PropagateConntrackMark {
			args = append(args, "ct", "mark", "set", fmt.Sprintf("0x%x", next.MarkAttachment.Rule.Mark))
		}
		args = append(args, "comment", next.MarkAttachment.Rule.Comment)
		steps = append(steps, Step{
			Name: "upsert-mark-attachment-rule",
			Command: Command{
				Path: defaultNftBinary,
				Args: args,
			},
		})
	}
	if plan.MarkAttachment.usesRestoreRule() && !observation.RestoreRuleMatched {
		steps = append(steps, Step{
			Name: "upsert-mark-attachment-restore-rule",
			Command: Command{
				Path: defaultNftBinary,
				Args: []string{
					"add", "rule",
					next.MarkAttachment.RestoreChain.Family,
					next.MarkAttachment.RestoreChain.Table,
					next.MarkAttachment.RestoreChain.Name,
					"ct", "mark", fmt.Sprintf("0x%x", next.MarkAttachment.Rule.Mark),
					"counter",
					"meta", "mark", "set", "ct", "mark",
					"comment", next.MarkAttachment.RestoreRule.Comment,
				},
			},
		})
	}
	if !observation.FilterMatched {
		steps = append(steps, Step{
			Name: "upsert-mark-attachment-filter",
			Command: Command{
				Path: tcCommandPath(next),
				Args: []string{
					"filter", "replace",
					"dev", next.Scope.Device,
					"parent", next.Handles.RootHandle,
					"protocol", next.MarkAttachment.Filter.Protocol,
					"pref", fmt.Sprintf("%d", next.MarkAttachment.Filter.Preference),
					"handle", next.MarkAttachment.Filter.handleArg(),
					"fw",
					"classid", next.MarkAttachment.Filter.ClassID,
				},
			},
		})
	}

	next.Steps = steps
	if len(steps) != len(retained) {
		next.NoOp = false
	}
	if err := next.Validate(); err != nil {
		return Plan{}, err
	}

	return next, nil
}

// AppendMarkAttachmentRemove prepends observed managed nftables and tc fw
// cleanup steps to an existing remove plan.
func AppendMarkAttachmentRemove(plan Plan, tcSnapshot Snapshot, nftSnapshot NftablesSnapshot) (Plan, error) {
	if err := plan.Validate(); err != nil {
		return Plan{}, err
	}
	if plan.MarkAttachment == nil || plan.MarkAttachment.Readiness != BindingReadinessReady {
		return plan, nil
	}
	if plan.Action.Kind != limiter.ActionRemove {
		return Plan{}, errors.New("mark attachment removal requires a remove plan")
	}
	if err := tcSnapshot.Validate(); err != nil {
		return Plan{}, err
	}
	if err := nftSnapshot.Validate(); err != nil {
		return Plan{}, err
	}

	next := plan
	cleanupSteps := make([]Step, 0, 3)
	observedFilters := tcSnapshot.MarkAttachmentFilters(next.MarkAttachment.Filter.Parent, next.MarkAttachment.Filter.ClassID, *next.MarkAttachment)
	for _, filter := range observedFilters {
		protocol := strings.TrimSpace(filter.Protocol)
		if protocol == "" {
			protocol = next.MarkAttachment.Filter.Protocol
		}
		handle := strings.TrimSpace(filter.Handle)
		if handle == "" {
			handle = next.MarkAttachment.Filter.handleArg()
		}
		cleanupSteps = append(cleanupSteps, Step{
			Name: fmt.Sprintf("delete-mark-attachment-filter-%d", len(cleanupSteps)+1),
			Command: Command{
				Path: tcCommandPath(next),
				Args: []string{
					"filter", "del",
					"dev", next.Scope.Device,
					"parent", next.Handles.RootHandle,
					"protocol", protocol,
					"pref", fmt.Sprintf("%d", filter.Preference),
					"handle", handle,
					"fw",
				},
			},
		})
	}

	observedRules := nftSnapshot.MarkAttachmentRules(*next.MarkAttachment)
	for _, rule := range observedRules {
		cleanupSteps = append(cleanupSteps, Step{
			Name: fmt.Sprintf("delete-mark-attachment-rule-%d", len(cleanupSteps)+1),
			Command: Command{
				Path: defaultNftBinary,
				Args: []string{
					"delete", "rule",
					rule.Family,
					rule.Table,
					rule.Chain,
					"handle", fmt.Sprintf("%d", rule.Handle),
				},
			},
		})
	}
	observedRestoreRules := nftSnapshot.MarkAttachmentRestoreRules(*next.MarkAttachment)
	for _, rule := range observedRestoreRules {
		cleanupSteps = append(cleanupSteps, Step{
			Name: fmt.Sprintf("delete-mark-attachment-restore-rule-%d", len(cleanupSteps)+1),
			Command: Command{
				Path: defaultNftBinary,
				Args: []string{
					"delete", "rule",
					rule.Family,
					rule.Table,
					rule.Chain,
					"handle", fmt.Sprintf("%d", rule.Handle),
				},
			},
		})
	}
	if next.MarkAttachment.ManageChainLifecycle && nftSnapshot.EligibleForManagedChainCleanup(next.MarkAttachment.Chain, next.MarkAttachment.Rule.Comment) {
		cleanupSteps = append(cleanupSteps, Step{
			Name: "delete-mark-attachment-chain",
			Command: Command{
				Path: defaultNftBinary,
				Args: []string{
					"delete", "chain",
					next.MarkAttachment.Chain.Family,
					next.MarkAttachment.Chain.Table,
					next.MarkAttachment.Chain.Name,
				},
			},
		})
	}
	if next.MarkAttachment.ManageChainLifecycle &&
		next.MarkAttachment.usesRestoreRule() &&
		nftSnapshot.EligibleForManagedChainCleanup(*next.MarkAttachment.RestoreChain, next.MarkAttachment.RestoreRule.Comment) {
		cleanupSteps = append(cleanupSteps, Step{
			Name: "delete-mark-attachment-restore-chain",
			Command: Command{
				Path: defaultNftBinary,
				Args: []string{
					"delete", "chain",
					next.MarkAttachment.RestoreChain.Family,
					next.MarkAttachment.RestoreChain.Table,
					next.MarkAttachment.RestoreChain.Name,
				},
			},
		})
	}

	retained := retainNonMarkAttachmentSteps(plan.Steps)
	next.Steps = append(cleanupSteps, retained...)
	if !hasStepNamed(next.Steps, "delete-root-qdisc") &&
		tcSnapshot.EligibleForRootQDiscCleanupAfterMarkAttachmentRemoval(next.Handles.RootHandle, next.Handles.ClassID, *next.MarkAttachment) {
		var err error
		next, err = AppendRootQDiscCleanup(next)
		if err != nil {
			return Plan{}, err
		}
	}

	if err := next.Validate(); err != nil {
		return Plan{}, err
	}

	return next, nil
}

func retainNonMarkAttachmentSteps(steps []Step) []Step {
	retained := make([]Step, 0, len(steps))
	for _, step := range steps {
		name := strings.TrimSpace(step.Name)
		if strings.HasPrefix(name, "ensure-mark-attachment-") ||
			strings.HasPrefix(name, "upsert-mark-attachment-") ||
			strings.HasPrefix(name, "delete-mark-attachment-") {
			continue
		}
		retained = append(retained, step)
	}

	return retained
}

func hasStepNamed(steps []Step, name string) bool {
	for _, step := range steps {
		if strings.TrimSpace(step.Name) == strings.TrimSpace(name) {
			return true
		}
	}

	return false
}

// NftablesTableState captures one observed nftables table.
type NftablesTableState struct {
	Family string `json:"family"`
	Name   string `json:"name"`
	Handle uint64 `json:"handle,omitempty"`
}

func (s NftablesTableState) Validate() error {
	if !validNftablesFamily(s.Family) {
		return fmt.Errorf("invalid nftables table family %q", s.Family)
	}
	if strings.TrimSpace(s.Name) == "" {
		return errors.New("nftables table name is required")
	}

	return nil
}

// NftablesChainState captures one observed nftables chain.
type NftablesChainState struct {
	Family   string `json:"family"`
	Table    string `json:"table"`
	Name     string `json:"name"`
	Handle   uint64 `json:"handle,omitempty"`
	Type     string `json:"type,omitempty"`
	Hook     string `json:"hook,omitempty"`
	Priority int    `json:"priority,omitempty"`
}

func (s NftablesChainState) Validate() error {
	if !validNftablesFamily(s.Family) {
		return fmt.Errorf("invalid nftables chain family %q", s.Family)
	}
	if strings.TrimSpace(s.Table) == "" {
		return errors.New("nftables chain table is required")
	}
	if strings.TrimSpace(s.Name) == "" {
		return errors.New("nftables chain name is required")
	}

	return nil
}

// NftablesRuleState captures one observed nftables rule.
type NftablesRuleState struct {
	Family  string `json:"family"`
	Table   string `json:"table"`
	Chain   string `json:"chain"`
	Handle  uint64 `json:"handle,omitempty"`
	Comment string `json:"comment,omitempty"`
}

func (s NftablesRuleState) Validate() error {
	if !validNftablesFamily(s.Family) {
		return fmt.Errorf("invalid nftables rule family %q", s.Family)
	}
	if strings.TrimSpace(s.Table) == "" {
		return errors.New("nftables rule table is required")
	}
	if strings.TrimSpace(s.Chain) == "" {
		return errors.New("nftables rule chain is required")
	}

	return nil
}

// NftablesSnapshot captures the currently observed nftables ruleset state that
// RayLimit needs for conservative managed-state comparison.
type NftablesSnapshot struct {
	Tables []NftablesTableState `json:"tables,omitempty"`
	Chains []NftablesChainState `json:"chains,omitempty"`
	Rules  []NftablesRuleState  `json:"rules,omitempty"`
}

func (s NftablesSnapshot) Validate() error {
	for index, table := range s.Tables {
		if err := table.Validate(); err != nil {
			return fmt.Errorf("invalid nftables table at index %d: %w", index, err)
		}
	}
	for index, chain := range s.Chains {
		if err := chain.Validate(); err != nil {
			return fmt.Errorf("invalid nftables chain at index %d: %w", index, err)
		}
	}
	for index, rule := range s.Rules {
		if err := rule.Validate(); err != nil {
			return fmt.Errorf("invalid nftables rule at index %d: %w", index, err)
		}
	}

	return nil
}

func (s NftablesSnapshot) Table(spec MarkAttachmentTableSpec) (NftablesTableState, bool) {
	for _, table := range s.Tables {
		if table.Family == spec.Family && strings.TrimSpace(table.Name) == strings.TrimSpace(spec.Name) {
			return table, true
		}
	}

	return NftablesTableState{}, false
}

func (s NftablesSnapshot) Chain(spec MarkAttachmentChainSpec) (NftablesChainState, bool) {
	for _, chain := range s.Chains {
		if chain.Family != spec.Family ||
			strings.TrimSpace(chain.Table) != strings.TrimSpace(spec.Table) ||
			strings.TrimSpace(chain.Name) != strings.TrimSpace(spec.Name) {
			continue
		}
		if strings.TrimSpace(chain.Type) != "" && strings.TrimSpace(spec.Type) != "" && strings.TrimSpace(chain.Type) != strings.TrimSpace(spec.Type) {
			continue
		}
		if strings.TrimSpace(chain.Hook) != "" && strings.TrimSpace(spec.Hook) != "" && strings.TrimSpace(chain.Hook) != strings.TrimSpace(spec.Hook) {
			continue
		}
		if chain.Priority != 0 && spec.Priority != 0 && chain.Priority != spec.Priority {
			continue
		}
		return chain, true
	}

	return NftablesChainState{}, false
}

func (s NftablesSnapshot) MarkAttachmentRules(execution MarkAttachmentExecution) []NftablesRuleState {
	if execution.Readiness != BindingReadinessReady {
		return nil
	}

	rules := make([]NftablesRuleState, 0, 1)
	for _, rule := range s.Rules {
		if rule.Family != execution.Chain.Family ||
			strings.TrimSpace(rule.Table) != strings.TrimSpace(execution.Chain.Table) ||
			strings.TrimSpace(rule.Chain) != strings.TrimSpace(execution.Chain.Name) ||
			strings.TrimSpace(rule.Comment) != strings.TrimSpace(execution.Rule.Comment) {
			continue
		}
		rules = append(rules, rule)
	}
	sort.Slice(rules, func(i, j int) bool {
		return rules[i].Handle < rules[j].Handle
	})

	return rules
}

func (s NftablesSnapshot) MarkAttachmentRestoreRules(execution MarkAttachmentExecution) []NftablesRuleState {
	if execution.Readiness != BindingReadinessReady || !execution.usesRestoreRule() {
		return nil
	}

	rules := make([]NftablesRuleState, 0, 1)
	for _, rule := range s.Rules {
		if rule.Family != execution.RestoreChain.Family ||
			strings.TrimSpace(rule.Table) != strings.TrimSpace(execution.RestoreChain.Table) ||
			strings.TrimSpace(rule.Chain) != strings.TrimSpace(execution.RestoreChain.Name) ||
			strings.TrimSpace(rule.Comment) != strings.TrimSpace(execution.RestoreRule.Comment) {
			continue
		}
		rules = append(rules, rule)
	}
	sort.Slice(rules, func(i, j int) bool {
		return rules[i].Handle < rules[j].Handle
	})

	return rules
}

// HasManagedMarkAttachment reports whether the observed nftables ruleset still
// contains a RayLimit-managed mark-backed rule for the selected identity kind,
// direction, and class id.
func (s NftablesSnapshot) HasManagedMarkAttachment(kind IdentityKind, direction Direction, classID string) bool {
	class := strings.TrimSpace(classID)
	if !kind.Valid() || !direction.Valid() || class == "" {
		return false
	}

	rulePrefix := fmt.Sprintf("raylimit:mark-attachment:%s:%s:%s:", kind, direction, class)
	restorePrefix := fmt.Sprintf("raylimit:mark-attachment-restore:%s:%s:%s:", kind, direction, class)

	for _, rule := range s.Rules {
		comment := strings.TrimSpace(rule.Comment)
		if strings.HasPrefix(comment, rulePrefix) || strings.HasPrefix(comment, restorePrefix) {
			return true
		}
	}

	return false
}

func (s NftablesSnapshot) EligibleForManagedChainCleanup(spec MarkAttachmentChainSpec, managedComment string) bool {
	if strings.TrimSpace(managedComment) == "" {
		return false
	}
	if _, ok := s.Chain(spec); !ok {
		return false
	}

	for _, rule := range s.Rules {
		if rule.Family != spec.Family ||
			strings.TrimSpace(rule.Table) != strings.TrimSpace(spec.Table) ||
			strings.TrimSpace(rule.Chain) != strings.TrimSpace(spec.Name) {
			continue
		}
		if strings.TrimSpace(rule.Comment) != strings.TrimSpace(managedComment) {
			return false
		}
	}

	return true
}

func (s NftablesSnapshot) EligibleForManagedTableCleanup(spec MarkAttachmentTableSpec, managedChains ...MarkAttachmentChainSpec) bool {
	if _, ok := s.Table(spec); !ok {
		return false
	}

	allowedChains := make(map[string]struct{}, len(managedChains))
	for _, chain := range managedChains {
		if chain.Family != spec.Family || strings.TrimSpace(chain.Table) != strings.TrimSpace(spec.Name) {
			return false
		}
		allowedChains[strings.TrimSpace(chain.Name)] = struct{}{}
	}

	for _, chain := range s.Chains {
		if chain.Family != spec.Family || strings.TrimSpace(chain.Table) != strings.TrimSpace(spec.Name) {
			continue
		}
		if _, ok := allowedChains[strings.TrimSpace(chain.Name)]; !ok {
			return false
		}
	}

	return true
}

// NftablesInspector reads nftables ruleset state without mutating it.
type NftablesInspector struct {
	Runner Runner
	Binary string
}

// Inspect executes one read-only nft command and parses the result into a
// minimal snapshot.
func (i NftablesInspector) Inspect(ctx context.Context) (NftablesSnapshot, []Result, error) {
	step := Step{
		Name: "show-nftables-ruleset",
		Command: Command{
			Path: i.binary(),
			Args: []string{"-a", "-j", "list", "ruleset"},
		},
	}

	runner := i.runner()
	result, err := runner.Run(ctx, step.Command)
	result.Step = step.Name
	if err != nil {
		if result.Error == "" {
			result.Error = err.Error()
		}
		return NftablesSnapshot{}, []Result{result}, err
	}

	snapshot, parseErr := ParseNftablesSnapshot(result.Stdout)
	if parseErr != nil {
		return NftablesSnapshot{}, []Result{result}, parseErr
	}

	return snapshot, []Result{result}, nil
}

func (i NftablesInspector) runner() Runner {
	if i.Runner != nil {
		return i.Runner
	}

	return SystemRunner{}
}

func (i NftablesInspector) binary() string {
	if strings.TrimSpace(i.Binary) == "" {
		return defaultNftBinary
	}

	return strings.TrimSpace(i.Binary)
}

// ParseNftablesSnapshot parses `nft -a -j list ruleset` output into the
// minimal managed-state snapshot RayLimit needs for conservative comparison.
func ParseNftablesSnapshot(stdout string) (NftablesSnapshot, error) {
	payload := strings.TrimSpace(stdout)
	if payload == "" {
		return NftablesSnapshot{}, nil
	}

	var document struct {
		NFTables []map[string]any `json:"nftables"`
	}
	if err := json.Unmarshal([]byte(payload), &document); err != nil {
		return NftablesSnapshot{}, err
	}

	snapshot := NftablesSnapshot{}
	for _, entry := range document.NFTables {
		switch {
		case hasObject(entry, "metainfo"):
			continue
		case hasObject(entry, "table"):
			object, _ := entry["table"].(map[string]any)
			snapshot.Tables = append(snapshot.Tables, NftablesTableState{
				Family: stringField(object, "family"),
				Name:   stringField(object, "name"),
				Handle: firstUint64Field(object, "handle"),
			})
		case hasObject(entry, "chain"):
			object, _ := entry["chain"].(map[string]any)
			snapshot.Chains = append(snapshot.Chains, NftablesChainState{
				Family:   stringField(object, "family"),
				Table:    stringField(object, "table"),
				Name:     stringField(object, "name"),
				Handle:   firstUint64Field(object, "handle"),
				Type:     stringField(object, "type"),
				Hook:     stringField(object, "hook"),
				Priority: firstIntField(object, "prio", "priority"),
			})
		case hasObject(entry, "rule"):
			object, _ := entry["rule"].(map[string]any)
			snapshot.Rules = append(snapshot.Rules, NftablesRuleState{
				Family:  stringField(object, "family"),
				Table:   stringField(object, "table"),
				Chain:   stringField(object, "chain"),
				Handle:  firstUint64Field(object, "handle"),
				Comment: stringField(object, "comment"),
			})
		}
	}

	if err := snapshot.Validate(); err != nil {
		return NftablesSnapshot{}, err
	}

	return snapshot, nil
}

func hasObject(entry map[string]any, key string) bool {
	_, ok := entry[key]
	return ok
}

func validNftablesFamily(value string) bool {
	switch strings.TrimSpace(value) {
	case "ip", "ip6", "inet":
		return true
	default:
		return false
	}
}

func validNftablesHook(value string) bool {
	switch strings.TrimSpace(value) {
	case "prerouting", "input", "forward", "output", "postrouting":
		return true
	default:
		return false
	}
}

func firstUint64Field(entry map[string]any, keys ...string) uint64 {
	for _, key := range keys {
		if value, ok := parseUint64(entry[key]); ok {
			return value
		}
	}

	return 0
}

func firstIntField(entry map[string]any, keys ...string) int {
	for _, key := range keys {
		if value, ok := parseSignedIntegerScalar(entry[key]); ok {
			return int(value)
		}
	}

	return 0
}

func parseUint64(value any) (uint64, bool) {
	switch typed := value.(type) {
	case float64:
		if typed < 0 || typed != float64(uint64(typed)) {
			return 0, false
		}
		return uint64(typed), true
	case string:
		parsed, err := strconv.ParseUint(strings.TrimSpace(typed), 0, 64)
		if err != nil {
			return 0, false
		}
		return parsed, true
	case json.Number:
		parsed, err := strconv.ParseUint(typed.String(), 10, 64)
		if err != nil {
			return 0, false
		}
		return parsed, true
	default:
		return 0, false
	}
}

func parseSignedIntegerScalar(value any) (int64, bool) {
	switch typed := value.(type) {
	case float64:
		if typed != float64(int64(typed)) {
			return 0, false
		}
		return int64(typed), true
	case string:
		return parseSignedInteger(strings.TrimSpace(typed))
	case json.Number:
		parsed, err := typed.Int64()
		if err != nil {
			return 0, false
		}
		return parsed, true
	default:
		return 0, false
	}
}
