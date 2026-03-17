package tc

import (
	"errors"
	"fmt"
	"sort"
	"strconv"
	"strings"
)

// GarbageCollectionOutcomeKind identifies the next stale-cleanup action for one
// managed owner after cheap-first reconcile classification.
type GarbageCollectionOutcomeKind string

const (
	GarbageCollectionOutcomeNoChange     GarbageCollectionOutcomeKind = "no_change"
	GarbageCollectionOutcomeCleanupDelta GarbageCollectionOutcomeKind = "cleanup_delta"
	GarbageCollectionOutcomeDefer        GarbageCollectionOutcomeKind = "defer"
)

func (k GarbageCollectionOutcomeKind) Valid() bool {
	switch k {
	case GarbageCollectionOutcomeNoChange,
		GarbageCollectionOutcomeCleanupDelta,
		GarbageCollectionOutcomeDefer:
		return true
	default:
		return false
	}
}

// GarbageCollectionInput carries the cheap-first reconcile decision together
// with the current observed backend state the GC planner can act on.
type GarbageCollectionInput struct {
	Reconcile        PeriodicReconcileResult `json:"reconcile"`
	Snapshot         Snapshot                `json:"snapshot"`
	NftablesSnapshot NftablesSnapshot        `json:"nftables_snapshot"`
}

func (i GarbageCollectionInput) Validate() error {
	if err := i.Reconcile.Validate(); err != nil {
		return fmt.Errorf("invalid reconcile result: %w", err)
	}
	if err := i.Snapshot.Validate(); err != nil {
		return fmt.Errorf("invalid tc snapshot: %w", err)
	}
	if err := i.NftablesSnapshot.Validate(); err != nil {
		return fmt.Errorf("invalid nftables snapshot: %w", err)
	}

	return nil
}

// GarbageCollectionPlan captures the safe stale-object cleanup delta for one
// managed owner.
type GarbageCollectionPlan struct {
	Kind     GarbageCollectionOutcomeKind `json:"kind"`
	OwnerKey string                       `json:"owner_key,omitempty"`
	Cleanup  []StaleManagedObject         `json:"cleanup,omitempty"`
	Deferred []StaleManagedObject         `json:"deferred,omitempty"`
	Steps    []Step                       `json:"steps,omitempty"`
	Reason   string                       `json:"reason"`
}

func (p GarbageCollectionPlan) Validate() error {
	if !p.Kind.Valid() {
		return fmt.Errorf("invalid garbage-collection outcome kind %q", p.Kind)
	}
	for index, object := range p.Cleanup {
		if err := object.Validate(); err != nil {
			return fmt.Errorf("invalid cleanup object at index %d: %w", index, err)
		}
	}
	for index, object := range p.Deferred {
		if err := object.Validate(); err != nil {
			return fmt.Errorf("invalid deferred object at index %d: %w", index, err)
		}
	}
	for index, step := range p.Steps {
		if err := step.Validate(); err != nil {
			return fmt.Errorf("invalid garbage-collection step at index %d: %w", index, err)
		}
	}
	if strings.TrimSpace(p.Reason) == "" {
		return errors.New("garbage-collection reason is required")
	}

	switch p.Kind {
	case GarbageCollectionOutcomeNoChange:
		if len(p.Cleanup) != 0 || len(p.Deferred) != 0 || len(p.Steps) != 0 {
			return errors.New("no_change garbage-collection plan cannot include cleanup, deferred objects, or steps")
		}
	case GarbageCollectionOutcomeCleanupDelta:
		if len(p.Cleanup) == 0 || len(p.Steps) == 0 {
			return errors.New("cleanup_delta garbage-collection plan requires cleanup objects and steps")
		}
	case GarbageCollectionOutcomeDefer:
		if len(p.Steps) != 0 {
			return errors.New("defer garbage-collection plan cannot include cleanup steps")
		}
	}

	return nil
}

// GarbageCollector turns stale managed-object ownership into an explicit,
// owner-aware cleanup delta without rebuilding desired state.
type GarbageCollector struct{}

func (GarbageCollector) Plan(input GarbageCollectionInput) (GarbageCollectionPlan, error) {
	if err := input.Validate(); err != nil {
		return GarbageCollectionPlan{}, err
	}

	stale := append([]StaleManagedObject(nil), input.Reconcile.Inventory.Stale...)
	sortStaleManagedObjects(stale)

	plan := GarbageCollectionPlan{
		OwnerKey: input.Reconcile.OwnerKey,
	}

	switch input.Reconcile.Kind {
	case ReconcileOutcomeNoChange:
		plan.Kind = GarbageCollectionOutcomeNoChange
		plan.Reason = "no stale managed state requires cleanup"
	case ReconcileOutcomeApplyDelta, ReconcileOutcomeBlockedMissingEvidence:
		plan.Kind = GarbageCollectionOutcomeDefer
		plan.Deferred = stale
		plan.Reason = "desired managed-state delta still requires apply or recreate work; stale cleanup is deferred to avoid mixing garbage collection with owner repair"
	case ReconcileOutcomeDefer:
		plan.Kind = GarbageCollectionOutcomeDefer
		plan.Deferred = stale
		plan.Reason = "stale managed state remains, but the current reconcile result still defers mutation"
	case ReconcileOutcomeCleanupStale:
		candidates := cleanupEligibleStaleObjects(stale)
		if len(candidates) == 0 {
			plan.Kind = GarbageCollectionOutcomeDefer
			plan.Deferred = stale
			plan.Reason = "stale managed state remains, but none of it is cleanup-eligible yet"
			break
		}

		steps, cleaned, unresolved, err := buildGarbageCollectionSteps(candidates, input.Snapshot, input.NftablesSnapshot)
		if err != nil {
			return GarbageCollectionPlan{}, err
		}
		plan.Cleanup = cleaned
		plan.Deferred = appendNonCleanedStale(stale, cleaned, unresolved)
		plan.Steps = steps

		switch {
		case len(plan.Steps) == 0 && len(plan.Deferred) == 0:
			plan.Kind = GarbageCollectionOutcomeNoChange
			plan.Reason = "cleanup-eligible stale managed objects are no longer present in observed backend state"
		case len(plan.Steps) == 0:
			plan.Kind = GarbageCollectionOutcomeDefer
			plan.Reason = "stale managed state remains, but no safe observed cleanup delta can be derived from the current backend state"
		default:
			plan.Kind = GarbageCollectionOutcomeCleanupDelta
			if len(plan.Deferred) == 0 {
				plan.Reason = "cleanup-eligible stale managed objects were reduced to a minimal observed-state garbage-collection delta"
			} else {
				plan.Reason = "cleanup-eligible stale managed objects were reduced to a minimal observed-state garbage-collection delta while unresolved stale objects were deferred"
			}
		}
	default:
		return GarbageCollectionPlan{}, fmt.Errorf("unsupported reconcile outcome %q", input.Reconcile.Kind)
	}

	sortStaleManagedObjects(plan.Cleanup)
	sortStaleManagedObjects(plan.Deferred)
	if err := plan.Validate(); err != nil {
		return GarbageCollectionPlan{}, err
	}

	return plan, nil
}

type garbageCollectionStepBuilder struct {
	steps        []Step
	seen         map[string]struct{}
	nameCounters map[string]int
}

func newGarbageCollectionStepBuilder() *garbageCollectionStepBuilder {
	return &garbageCollectionStepBuilder{
		seen:         make(map[string]struct{}),
		nameCounters: make(map[string]int),
	}
}

func (b *garbageCollectionStepBuilder) appendStep(prefix string, command Command) bool {
	key := strings.TrimSpace(command.Path) + "\x00" + strings.Join(command.Args, "\x00")
	if _, ok := b.seen[key]; ok {
		return false
	}
	b.seen[key] = struct{}{}
	b.nameCounters[prefix]++
	b.steps = append(b.steps, Step{
		Name: fmt.Sprintf("%s-%d", prefix, b.nameCounters[prefix]),
		Command: Command{
			Path: command.Path,
			Args: append([]string(nil), command.Args...),
		},
	})
	return true
}

func buildGarbageCollectionSteps(candidates []StaleManagedObject, snapshot Snapshot, nftSnapshot NftablesSnapshot) ([]Step, []StaleManagedObject, []StaleManagedObject, error) {
	builder := newGarbageCollectionStepBuilder()
	cleaned := make([]StaleManagedObject, 0, len(candidates))
	unresolved := make([]StaleManagedObject, 0)

	order := []ManagedObjectKind{
		ManagedObjectDirectAttachmentFilter,
		ManagedObjectMarkAttachmentFilter,
		ManagedObjectUUIDAggregateAttachmentFilter,
		ManagedObjectClass,
		ManagedObjectUUIDAggregateClass,
		ManagedObjectMarkAttachmentRule,
		ManagedObjectMarkAttachmentRestoreRule,
		ManagedObjectMarkAttachmentChain,
		ManagedObjectMarkAttachmentRestoreChain,
		ManagedObjectMarkAttachmentTable,
		ManagedObjectRootQDisc,
	}

	for _, kind := range order {
		for _, object := range staleManagedObjectsByKind(candidates, kind) {
			added, err := appendGarbageCollectionStepsForObject(builder, object, snapshot, nftSnapshot)
			if err != nil {
				return nil, nil, nil, err
			}
			switch {
			case added:
				cleaned = append(cleaned, object)
			case object.CleanupEligible:
				unresolved = append(unresolved, object)
			}
		}
	}

	return builder.steps, cleaned, unresolved, nil
}

func appendGarbageCollectionStepsForObject(builder *garbageCollectionStepBuilder, object StaleManagedObject, snapshot Snapshot, nftSnapshot NftablesSnapshot) (bool, error) {
	switch object.Object.Kind {
	case ManagedObjectDirectAttachmentFilter:
		return appendDirectAttachmentGarbageCollectionSteps(builder, object.Object, snapshot)
	case ManagedObjectMarkAttachmentFilter:
		return appendMarkAttachmentFilterGarbageCollectionSteps(builder, object.Object, snapshot)
	case ManagedObjectUUIDAggregateAttachmentFilter:
		return appendUUIDAggregateGarbageCollectionSteps(builder, object.Object, snapshot)
	case ManagedObjectClass, ManagedObjectUUIDAggregateClass:
		return appendClassGarbageCollectionStep(builder, object.Object, snapshot), nil
	case ManagedObjectMarkAttachmentRule, ManagedObjectMarkAttachmentRestoreRule:
		return appendMarkAttachmentRuleGarbageCollectionSteps(builder, object.Object, nftSnapshot)
	case ManagedObjectMarkAttachmentChain, ManagedObjectMarkAttachmentRestoreChain:
		return appendMarkAttachmentChainGarbageCollectionStep(builder, object.Object, nftSnapshot)
	case ManagedObjectMarkAttachmentTable:
		return appendMarkAttachmentTableGarbageCollectionStep(builder, object.Object, nftSnapshot)
	case ManagedObjectRootQDisc:
		return appendRootQDiscGarbageCollectionStep(builder, object.Object, snapshot), nil
	default:
		return false, nil
	}
}

func appendDirectAttachmentGarbageCollectionSteps(builder *garbageCollectionStepBuilder, object ManagedObject, snapshot Snapshot) (bool, error) {
	rootHandle, classID, protocol, preference, err := parseDirectAttachmentManagedObjectID(object.ID)
	if err != nil {
		return false, err
	}

	for _, filter := range snapshot.Filters {
		if strings.TrimSpace(filter.Kind) != "u32" ||
			strings.TrimSpace(filter.Parent) != rootHandle ||
			strings.TrimSpace(filter.FlowID) != classID ||
			strings.ToLower(strings.TrimSpace(filter.Protocol)) != protocol ||
			filter.Preference != preference {
			continue
		}
		return builder.appendStep("delete-stale-direct-attachment", Command{
			Path: defaultBinary,
			Args: []string{
				"filter", "del",
				"dev", object.Device,
				"parent", rootHandle,
				"protocol", protocol,
				"pref", fmt.Sprintf("%d", preference),
				"u32",
			},
		}), nil
	}

	return false, nil
}

func appendMarkAttachmentFilterGarbageCollectionSteps(builder *garbageCollectionStepBuilder, object ManagedObject, snapshot Snapshot) (bool, error) {
	parent, classID, preference, handleArg, err := parseMarkAttachmentFilterManagedObjectID(object.ID)
	if err != nil {
		return false, err
	}

	added := false
	for _, filter := range snapshot.Filters {
		if strings.TrimSpace(filter.Kind) != "fw" ||
			strings.TrimSpace(filter.Parent) != parent ||
			strings.TrimSpace(filter.FlowID) != classID ||
			filter.Preference != preference {
			continue
		}
		if handleArg != "" && strings.TrimSpace(filter.Handle) != "" && strings.TrimSpace(filter.Handle) != handleArg {
			continue
		}
		handle := strings.TrimSpace(filter.Handle)
		if handle == "" {
			handle = handleArg
		}
		if handle == "" {
			continue
		}
		protocol := strings.TrimSpace(filter.Protocol)
		if protocol == "" {
			protocol = defaultMarkAttachmentProtocol
		}
		added = builder.appendStep("delete-stale-mark-attachment-filter", Command{
			Path: defaultBinary,
			Args: []string{
				"filter", "del",
				"dev", object.Device,
				"parent", parent,
				"protocol", protocol,
				"pref", fmt.Sprintf("%d", filter.Preference),
				"handle", handle,
				"fw",
			},
		}) || added
	}

	return added, nil
}

func appendUUIDAggregateGarbageCollectionSteps(builder *garbageCollectionStepBuilder, object ManagedObject, snapshot Snapshot) (bool, error) {
	rootHandle, classID, preference, err := parseUUIDAggregateAttachmentManagedObjectID(object.ID)
	if err != nil {
		return false, err
	}

	added := false
	for _, filter := range snapshot.UUIDAggregateAttachmentFilters(rootHandle, classID) {
		if filter.Preference != preference {
			continue
		}
		protocol := strings.TrimSpace(filter.Protocol)
		if protocol == "" {
			protocol = "ip"
		}
		added = builder.appendStep("delete-stale-aggregate-attachment", Command{
			Path: defaultBinary,
			Args: []string{
				"filter", "del",
				"dev", object.Device,
				"parent", rootHandle,
				"protocol", protocol,
				"pref", fmt.Sprintf("%d", filter.Preference),
				"u32",
			},
		}) || added
	}

	return added, nil
}

func appendClassGarbageCollectionStep(builder *garbageCollectionStepBuilder, object ManagedObject, snapshot Snapshot) bool {
	if _, ok := snapshot.Class(object.ID); !ok {
		return false
	}

	return builder.appendStep("delete-stale-class", Command{
		Path: defaultBinary,
		Args: []string{"class", "del", "dev", object.Device, "classid", object.ID},
	})
}

func appendMarkAttachmentRuleGarbageCollectionSteps(builder *garbageCollectionStepBuilder, object ManagedObject, nftSnapshot NftablesSnapshot) (bool, error) {
	family, table, chain, comment, err := parseMarkAttachmentRuleManagedObjectID(object.ID)
	if err != nil {
		return false, err
	}

	added := false
	for _, rule := range nftSnapshot.Rules {
		if rule.Family != family ||
			strings.TrimSpace(rule.Table) != table ||
			strings.TrimSpace(rule.Chain) != chain ||
			strings.TrimSpace(rule.Comment) != comment {
			continue
		}
		added = builder.appendStep("delete-stale-mark-attachment-rule", Command{
			Path: defaultNftBinary,
			Args: []string{"delete", "rule", family, table, chain, "handle", fmt.Sprintf("%d", rule.Handle)},
		}) || added
	}

	return added, nil
}

func appendMarkAttachmentChainGarbageCollectionStep(builder *garbageCollectionStepBuilder, object ManagedObject, nftSnapshot NftablesSnapshot) (bool, error) {
	family, table, name, err := parseMarkAttachmentChainManagedObjectID(object.ID)
	if err != nil {
		return false, err
	}
	for _, chain := range nftSnapshot.Chains {
		if chain.Family == family &&
			strings.TrimSpace(chain.Table) == table &&
			strings.TrimSpace(chain.Name) == name {
			return builder.appendStep("delete-stale-mark-attachment-chain", Command{
				Path: defaultNftBinary,
				Args: []string{"delete", "chain", family, table, name},
			}), nil
		}
	}

	return false, nil
}

func appendMarkAttachmentTableGarbageCollectionStep(builder *garbageCollectionStepBuilder, object ManagedObject, nftSnapshot NftablesSnapshot) (bool, error) {
	family, name, err := parseMarkAttachmentTableManagedObjectID(object.ID)
	if err != nil {
		return false, err
	}
	if _, ok := nftSnapshot.Table(MarkAttachmentTableSpec{Family: family, Name: name}); !ok {
		return false, nil
	}

	return builder.appendStep("delete-stale-mark-attachment-table", Command{
		Path: defaultNftBinary,
		Args: []string{"delete", "table", family, name},
	}), nil
}

func appendRootQDiscGarbageCollectionStep(builder *garbageCollectionStepBuilder, object ManagedObject, snapshot Snapshot) bool {
	if !snapshotHasManagedRootQDisc(snapshot, object.RootHandle) {
		return false
	}

	return builder.appendStep("delete-stale-root-qdisc", Command{
		Path: defaultBinary,
		Args: []string{"qdisc", "del", "dev", object.Device, "root"},
	})
}

func appendNonCleanedStale(stale []StaleManagedObject, cleaned []StaleManagedObject, unresolved []StaleManagedObject) []StaleManagedObject {
	cleanedSet := make(map[string]struct{}, len(cleaned))
	for _, object := range cleaned {
		cleanedSet[object.Object.fingerprint()] = struct{}{}
	}
	unresolvedSet := make(map[string]StaleManagedObject, len(unresolved))
	for _, object := range unresolved {
		unresolvedSet[object.Object.fingerprint()] = object
	}

	deferred := make([]StaleManagedObject, 0, len(stale))
	for _, object := range stale {
		if _, ok := cleanedSet[object.Object.fingerprint()]; ok {
			continue
		}
		if unresolvedObject, ok := unresolvedSet[object.Object.fingerprint()]; ok {
			deferred = append(deferred, unresolvedObject)
			continue
		}
		deferred = append(deferred, object)
	}

	return deferred
}

func staleManagedObjectsByKind(stale []StaleManagedObject, kind ManagedObjectKind) []StaleManagedObject {
	matches := make([]StaleManagedObject, 0)
	for _, object := range stale {
		if object.Object.Kind == kind {
			matches = append(matches, object)
		}
	}
	sortStaleManagedObjects(matches)

	return matches
}

func sortStaleManagedObjects(objects []StaleManagedObject) {
	sort.Slice(objects, func(i, j int) bool {
		return objects[i].Object.fingerprint() < objects[j].Object.fingerprint()
	})
}

func parseDirectAttachmentManagedObjectID(id string) (string, string, string, uint32, error) {
	parts := strings.Split(strings.TrimSpace(id), "|")
	if len(parts) != 4 {
		return "", "", "", 0, fmt.Errorf("invalid direct attachment managed object id %q", id)
	}
	preference, err := parseManagedPreference(parts[3], id)
	if err != nil {
		return "", "", "", 0, err
	}

	return strings.TrimSpace(parts[0]), strings.TrimSpace(parts[1]), strings.ToLower(strings.TrimSpace(parts[2])), preference, nil
}

func parseUUIDAggregateAttachmentManagedObjectID(id string) (string, string, uint32, error) {
	parts := strings.Split(strings.TrimSpace(id), "|")
	if len(parts) != 3 {
		return "", "", 0, fmt.Errorf("invalid uuid aggregate attachment managed object id %q", id)
	}
	preference, err := parseManagedPreference(parts[2], id)
	if err != nil {
		return "", "", 0, err
	}

	return strings.TrimSpace(parts[0]), strings.TrimSpace(parts[1]), preference, nil
}

func parseMarkAttachmentTableManagedObjectID(id string) (string, string, error) {
	parts := strings.Split(strings.TrimSpace(id), "|")
	if len(parts) != 2 {
		return "", "", fmt.Errorf("invalid mark attachment table managed object id %q", id)
	}

	return strings.TrimSpace(parts[0]), strings.TrimSpace(parts[1]), nil
}

func parseMarkAttachmentChainManagedObjectID(id string) (string, string, string, error) {
	parts := strings.Split(strings.TrimSpace(id), "|")
	if len(parts) != 3 {
		return "", "", "", fmt.Errorf("invalid mark attachment chain managed object id %q", id)
	}

	return strings.TrimSpace(parts[0]), strings.TrimSpace(parts[1]), strings.TrimSpace(parts[2]), nil
}

func parseMarkAttachmentRuleManagedObjectID(id string) (string, string, string, string, error) {
	parts := strings.Split(strings.TrimSpace(id), "|")
	if len(parts) != 4 {
		return "", "", "", "", fmt.Errorf("invalid mark attachment rule managed object id %q", id)
	}

	return strings.TrimSpace(parts[0]), strings.TrimSpace(parts[1]), strings.TrimSpace(parts[2]), strings.TrimSpace(parts[3]), nil
}

func parseMarkAttachmentFilterManagedObjectID(id string) (string, string, uint32, string, error) {
	parts := strings.Split(strings.TrimSpace(id), "|")
	if len(parts) != 4 {
		return "", "", 0, "", fmt.Errorf("invalid mark attachment filter managed object id %q", id)
	}
	preference, err := parseManagedPreference(parts[2], id)
	if err != nil {
		return "", "", 0, "", err
	}

	return strings.TrimSpace(parts[0]), strings.TrimSpace(parts[1]), preference, strings.TrimSpace(parts[3]), nil
}

func parseManagedPreference(value string, id string) (uint32, error) {
	parsed, err := strconv.ParseUint(strings.TrimSpace(value), 10, 32)
	if err != nil {
		return 0, fmt.Errorf("invalid managed preference %q in %q: %w", value, id, err)
	}

	return uint32(parsed), nil
}
