package tc

import (
	"errors"
	"fmt"
	"sort"
	"strings"

	"github.com/PdYrust/RayLimit/internal/discovery"
	"github.com/PdYrust/RayLimit/internal/limiter"
	"github.com/PdYrust/RayLimit/internal/policy"
)

// ManagedObjectKind identifies one backend object RayLimit can deterministically
// claim and later reconcile against observed state.
type ManagedObjectKind string

const (
	ManagedObjectRootQDisc                     ManagedObjectKind = "root_qdisc"
	ManagedObjectClass                         ManagedObjectKind = "class"
	ManagedObjectDirectAttachmentFilter        ManagedObjectKind = "direct_attachment_filter"
	ManagedObjectMarkAttachmentTable           ManagedObjectKind = "mark_attachment_table"
	ManagedObjectMarkAttachmentChain           ManagedObjectKind = "mark_attachment_chain"
	ManagedObjectMarkAttachmentRestoreChain    ManagedObjectKind = "mark_attachment_restore_chain"
	ManagedObjectMarkAttachmentRule            ManagedObjectKind = "mark_attachment_rule"
	ManagedObjectMarkAttachmentRestoreRule     ManagedObjectKind = "mark_attachment_restore_rule"
	ManagedObjectMarkAttachmentFilter          ManagedObjectKind = "mark_attachment_filter"
	ManagedObjectUUIDAggregateClass            ManagedObjectKind = "uuid_aggregate_class"
	ManagedObjectUUIDAggregateAttachmentFilter ManagedObjectKind = "uuid_aggregate_attachment_filter"
)

func (k ManagedObjectKind) Valid() bool {
	switch k {
	case ManagedObjectRootQDisc,
		ManagedObjectClass,
		ManagedObjectDirectAttachmentFilter,
		ManagedObjectMarkAttachmentTable,
		ManagedObjectMarkAttachmentChain,
		ManagedObjectMarkAttachmentRestoreChain,
		ManagedObjectMarkAttachmentRule,
		ManagedObjectMarkAttachmentRestoreRule,
		ManagedObjectMarkAttachmentFilter,
		ManagedObjectUUIDAggregateClass,
		ManagedObjectUUIDAggregateAttachmentFilter:
		return true
	default:
		return false
	}
}

// ManagedObject captures one deterministic backend object RayLimit considers
// owned for one desired or observed enforcement scope.
type ManagedObject struct {
	Kind                           ManagedObjectKind `json:"kind"`
	Device                         string            `json:"device"`
	RootHandle                     string            `json:"root_handle,omitempty"`
	ID                             string            `json:"id"`
	RetainRequiresRuntimeEvidence  bool              `json:"retain_requires_runtime_evidence,omitempty"`
	CleanupRequiresRuntimeEvidence bool              `json:"cleanup_requires_runtime_evidence,omitempty"`
	CleanupEligible                bool              `json:"cleanup_eligible,omitempty"`
}

func (o ManagedObject) Validate() error {
	if !o.Kind.Valid() {
		return fmt.Errorf("invalid managed object kind %q", o.Kind)
	}
	if err := validateDevice(o.Device); err != nil {
		return fmt.Errorf("invalid managed object device: %w", err)
	}
	if strings.TrimSpace(o.RootHandle) != "" {
		if err := validateHandleMajor(o.RootHandle); err != nil {
			return fmt.Errorf("invalid managed object root handle: %w", err)
		}
	}
	if strings.TrimSpace(o.ID) == "" {
		return errors.New("managed object id is required")
	}

	return nil
}

func (o ManagedObject) fingerprint() string {
	return strings.Join([]string{
		string(o.Kind),
		strings.TrimSpace(o.Device),
		strings.TrimSpace(o.RootHandle),
		strings.TrimSpace(o.ID),
	}, "|")
}

// ManagedStateSet captures the desired or observed managed backend objects for
// one logical owner.
type ManagedStateSet struct {
	OwnerKey string          `json:"owner_key,omitempty"`
	Objects  []ManagedObject `json:"objects,omitempty"`
}

func (s ManagedStateSet) Validate() error {
	seen := make(map[string]struct{}, len(s.Objects))
	for index, object := range s.Objects {
		if err := object.Validate(); err != nil {
			return fmt.Errorf("invalid managed object at index %d: %w", index, err)
		}
		key := object.fingerprint()
		if _, ok := seen[key]; ok {
			return fmt.Errorf("duplicate managed object %q", key)
		}
		seen[key] = struct{}{}
	}

	return nil
}

// StaleManagedObject captures one observed owned object that no longer has a
// desired counterpart together with the current cleanup gate.
type StaleManagedObject struct {
	Object          ManagedObject `json:"object"`
	CleanupEligible bool          `json:"cleanup_eligible"`
	CleanupReason   string        `json:"cleanup_reason,omitempty"`
}

func (s StaleManagedObject) Validate() error {
	if err := s.Object.Validate(); err != nil {
		return err
	}
	if strings.TrimSpace(s.CleanupReason) == "" {
		return errors.New("stale managed object cleanup reason is required")
	}

	return nil
}

// ManagedStateInventory compares desired and observed owned backend objects and
// makes stale ownership explicit for later reconcile loops.
type ManagedStateInventory struct {
	OwnerKey string               `json:"owner_key,omitempty"`
	Desired  []ManagedObject      `json:"desired,omitempty"`
	Observed []ManagedObject      `json:"observed,omitempty"`
	Stale    []StaleManagedObject `json:"stale,omitempty"`
}

func (i ManagedStateInventory) Validate() error {
	desired := ManagedStateSet{OwnerKey: i.OwnerKey, Objects: i.Desired}
	if err := desired.Validate(); err != nil {
		return fmt.Errorf("invalid desired managed state: %w", err)
	}
	observed := ManagedStateSet{OwnerKey: i.OwnerKey, Objects: i.Observed}
	if err := observed.Validate(); err != nil {
		return fmt.Errorf("invalid observed managed state: %w", err)
	}
	for index, stale := range i.Stale {
		if err := stale.Validate(); err != nil {
			return fmt.Errorf("invalid stale managed object at index %d: %w", index, err)
		}
	}

	return nil
}

// DesiredManagedState derives the backend objects RayLimit intends to keep
// after one non-UUID plan succeeds.
func DesiredManagedState(plan Plan) (ManagedStateSet, error) {
	if err := plan.Validate(); err != nil {
		return ManagedStateSet{}, err
	}

	state := ManagedStateSet{
		OwnerKey: managedOwnerKeyForSubject(plan.Action.Subject),
	}
	if plan.Action.Kind == limiter.ActionRemove || plan.Action.Kind == limiter.ActionInspect {
		return state, nil
	}

	retainRequiresRuntimeEvidence := managedRetentionRequiresRuntimeEvidence(plan.Action.Subject.Kind)
	state.Objects = append(state.Objects,
		managedRootQDiscObject(plan.Scope, retainRequiresRuntimeEvidence, false),
		managedClassObject(plan.Scope, plan.Handles.ClassID, retainRequiresRuntimeEvidence, false),
	)
	for _, rule := range plan.AttachmentExecution.Rules {
		state.Objects = append(state.Objects, managedDirectAttachmentObject(plan.Scope, plan.Handles.ClassID, rule, retainRequiresRuntimeEvidence))
	}
	if plan.MarkAttachment != nil && plan.MarkAttachment.Readiness == BindingReadinessReady {
		state.Objects = append(state.Objects, managedMarkAttachmentObjects(plan.Scope, *plan.MarkAttachment, retainRequiresRuntimeEvidence, false)...)
	}
	sortManagedObjects(state.Objects)
	if err := state.Validate(); err != nil {
		return ManagedStateSet{}, err
	}

	return state, nil
}

// ObservedManagedState derives the currently observed owned backend objects for
// one non-UUID plan.
func ObservedManagedState(tcSnapshot Snapshot, nftSnapshot NftablesSnapshot, plan Plan) (ManagedStateSet, error) {
	if err := tcSnapshot.Validate(); err != nil {
		return ManagedStateSet{}, err
	}
	if err := nftSnapshot.Validate(); err != nil {
		return ManagedStateSet{}, err
	}
	if err := plan.Validate(); err != nil {
		return ManagedStateSet{}, err
	}

	retainRequiresRuntimeEvidence := managedRetentionRequiresRuntimeEvidence(plan.Action.Subject.Kind)
	state := ManagedStateSet{
		OwnerKey: managedOwnerKeyForSubject(plan.Action.Subject),
	}
	rootCleanupEligible := false
	switch {
	case plan.MarkAttachment != nil && plan.MarkAttachment.Readiness == BindingReadinessReady:
		rootCleanupEligible = tcSnapshot.EligibleForRootQDiscCleanupAfterMarkAttachmentRemoval(plan.Handles.RootHandle, plan.Handles.ClassID, *plan.MarkAttachment)
	case plan.AttachmentExecution.Readiness == BindingReadinessReady:
		rootCleanupEligible = tcSnapshot.EligibleForRootQDiscCleanupAfterDirectAttachmentRemoval(plan.Handles.RootHandle, plan.Handles.ClassID, plan.AttachmentExecution)
	default:
		rootCleanupEligible = tcSnapshot.EligibleForRootQDiscCleanup(plan.Handles.RootHandle, plan.Handles.ClassID)
	}
	if snapshotHasManagedRootQDisc(tcSnapshot, plan.Handles.RootHandle) {
		state.Objects = append(state.Objects, managedRootQDiscObject(plan.Scope, retainRequiresRuntimeEvidence, rootCleanupEligible))
	}
	if _, ok := tcSnapshot.Class(plan.Handles.ClassID); ok {
		state.Objects = append(state.Objects, managedClassObject(plan.Scope, plan.Handles.ClassID, retainRequiresRuntimeEvidence, false))
	}
	for _, filter := range tcSnapshot.DirectAttachmentFilters(plan.Handles.RootHandle, plan.Handles.ClassID, plan.AttachmentExecution) {
		state.Objects = append(state.Objects, observedDirectAttachmentObject(plan.Scope, filter, retainRequiresRuntimeEvidence))
	}
	if plan.MarkAttachment != nil && plan.MarkAttachment.Readiness == BindingReadinessReady {
		state.Objects = append(state.Objects, observedMarkAttachmentObjects(tcSnapshot, nftSnapshot, plan.Scope, *plan.MarkAttachment, retainRequiresRuntimeEvidence)...)
	}
	sortManagedObjects(state.Objects)
	if err := state.Validate(); err != nil {
		return ManagedStateSet{}, err
	}

	return state, nil
}

// DesiredUUIDAggregateManagedState derives the backend objects RayLimit intends
// to keep after one shared UUID aggregate plan succeeds.
func DesiredUUIDAggregateManagedState(plan UUIDAggregatePlan) (ManagedStateSet, error) {
	if err := plan.Validate(); err != nil {
		return ManagedStateSet{}, err
	}

	state := ManagedStateSet{
		OwnerKey: strings.TrimSpace(plan.Membership.Subject.Key()),
	}
	if plan.Operation == UUIDAggregateOperationRemove || plan.NoOp {
		return state, nil
	}

	state.Objects = append(state.Objects,
		managedRootQDiscObject(plan.Scope, true, false),
		managedUUIDAggregateClassObject(plan.Scope, plan.Handles.ClassID, true, false),
	)
	for _, rule := range plan.AttachmentExecution.Rules {
		state.Objects = append(state.Objects, managedUUIDAggregateAttachmentObject(plan.Scope, rule, true))
	}
	for _, execution := range plan.AttachmentExecution.MarkAttachments {
		state.Objects = append(state.Objects, managedMarkAttachmentObjects(plan.Scope, execution, true, false)...)
	}
	sortManagedObjects(state.Objects)
	if err := state.Validate(); err != nil {
		return ManagedStateSet{}, err
	}

	return state, nil
}

// ObservedUUIDAggregateManagedState derives the currently observed owned backend
// objects for one shared UUID aggregate plan.
func ObservedUUIDAggregateManagedState(snapshot Snapshot, nftSnapshot NftablesSnapshot, plan UUIDAggregatePlan) (ManagedStateSet, error) {
	if err := snapshot.Validate(); err != nil {
		return ManagedStateSet{}, err
	}
	if err := nftSnapshot.Validate(); err != nil {
		return ManagedStateSet{}, err
	}
	if err := plan.Validate(); err != nil {
		return ManagedStateSet{}, err
	}

	rootCleanupEligible := snapshot.EligibleForRootQDiscCleanup(plan.Handles.RootHandle, plan.Handles.ClassID)
	if !rootCleanupEligible {
		rootCleanupEligible = snapshot.EligibleForRootQDiscCleanupAfterUUIDAggregateAttachmentRemoval(plan.Handles.RootHandle, plan.Handles.ClassID)
	}
	if !rootCleanupEligible {
		rootCleanupEligible = eligibleForRootQDiscCleanupAfterUUIDAggregateMarkAttachmentRemoval(snapshot, plan.Handles.RootHandle, plan.Handles.ClassID)
	}
	state := ManagedStateSet{
		OwnerKey: strings.TrimSpace(plan.Membership.Subject.Key()),
	}
	if snapshotHasManagedRootQDisc(snapshot, plan.Handles.RootHandle) {
		state.Objects = append(state.Objects, managedRootQDiscObject(plan.Scope, true, rootCleanupEligible))
	}
	if _, ok := snapshot.Class(plan.Handles.ClassID); ok {
		state.Objects = append(state.Objects, managedUUIDAggregateClassObject(plan.Scope, plan.Handles.ClassID, true, false))
	}
	for _, filter := range snapshot.UUIDAggregateAttachmentFilters(plan.Handles.RootHandle, plan.Handles.ClassID) {
		state.Objects = append(state.Objects, observedUUIDAggregateAttachmentObject(plan.Scope, filter, true))
	}
	for _, execution := range plan.AttachmentExecution.MarkAttachments {
		state.Objects = append(state.Objects, observedMarkAttachmentObjects(snapshot, nftSnapshot, plan.Scope, execution, true)...)
	}
	sortManagedObjects(state.Objects)
	if err := state.Validate(); err != nil {
		return ManagedStateSet{}, err
	}

	return state, nil
}

// ClassifyManagedState compares desired and observed managed objects and marks
// observed-only objects as stale with explicit cleanup gates.
func ClassifyManagedState(desired ManagedStateSet, observed ManagedStateSet) (ManagedStateInventory, error) {
	if err := desired.Validate(); err != nil {
		return ManagedStateInventory{}, err
	}
	if err := observed.Validate(); err != nil {
		return ManagedStateInventory{}, err
	}
	if strings.TrimSpace(desired.OwnerKey) != "" &&
		strings.TrimSpace(observed.OwnerKey) != "" &&
		strings.TrimSpace(desired.OwnerKey) != strings.TrimSpace(observed.OwnerKey) {
		return ManagedStateInventory{}, errors.New("desired and observed managed state sets do not describe the same owner")
	}

	ownerKey := strings.TrimSpace(desired.OwnerKey)
	if ownerKey == "" {
		ownerKey = strings.TrimSpace(observed.OwnerKey)
	}
	inventory := ManagedStateInventory{
		OwnerKey: ownerKey,
		Desired:  append([]ManagedObject(nil), desired.Objects...),
		Observed: append([]ManagedObject(nil), observed.Objects...),
	}

	desiredObjects := make(map[string]struct{}, len(desired.Objects))
	for _, object := range desired.Objects {
		desiredObjects[object.fingerprint()] = struct{}{}
	}

	for _, object := range observed.Objects {
		if _, ok := desiredObjects[object.fingerprint()]; ok {
			continue
		}

		stale := StaleManagedObject{
			Object:          object,
			CleanupEligible: !object.CleanupRequiresRuntimeEvidence,
			CleanupReason:   "managed object is observed without a desired counterpart and can be removed from observed owned state",
		}
		switch object.Kind {
		case ManagedObjectRootQDisc:
			stale.CleanupEligible = object.CleanupEligible
			if stale.CleanupEligible {
				stale.CleanupReason = "managed root qdisc is observed without a desired counterpart and observed owned state allows safe cleanup"
			} else {
				stale.CleanupReason = "managed root qdisc is observed without a desired counterpart, but observed owned state does not yet allow safe cleanup"
			}
		case ManagedObjectMarkAttachmentTable:
			stale.CleanupEligible = object.CleanupEligible
			if stale.CleanupEligible {
				stale.CleanupReason = "managed nftables table is observed without a desired counterpart and only managed chains remain in that table"
			} else {
				stale.CleanupReason = "managed nftables table is observed without a desired counterpart, but unmanaged or unrelated chains still remain in that table"
			}
		case ManagedObjectMarkAttachmentChain, ManagedObjectMarkAttachmentRestoreChain:
			stale.CleanupEligible = object.CleanupEligible
			if stale.CleanupEligible {
				stale.CleanupReason = "managed nftables chain is observed without a desired counterpart and only managed rules remain in that chain"
			} else {
				stale.CleanupReason = "managed nftables chain is observed without a desired counterpart, but unmanaged or unrelated rules still remain in that chain"
			}
		default:
			if object.CleanupRequiresRuntimeEvidence {
				stale.CleanupEligible = false
				stale.CleanupReason = "managed object is observed without a desired counterpart, but cleanup still requires live runtime evidence"
			}
		}
		inventory.Stale = append(inventory.Stale, stale)
	}

	sortManagedObjects(inventory.Desired)
	sortManagedObjects(inventory.Observed)
	sort.Slice(inventory.Stale, func(i, j int) bool {
		return inventory.Stale[i].Object.fingerprint() < inventory.Stale[j].Object.fingerprint()
	})
	if err := inventory.Validate(); err != nil {
		return ManagedStateInventory{}, err
	}

	return inventory, nil
}

func managedOwnerKeyForSubject(subject limiter.Subject) string {
	runtimeKey := managedRuntimeOwnerKey(subject.Binding.Runtime)
	switch subject.Kind {
	case policy.TargetKindConnection:
		return runtimeKey + "|connection|" + strings.TrimSpace(subject.Binding.SessionID)
	case policy.TargetKindUUID:
		return runtimeKey + "|uuid|" + strings.TrimSpace(subject.Value)
	case policy.TargetKindIP:
		return runtimeKey + "|ip|" + strings.TrimSpace(subject.Value)
	case policy.TargetKindInbound:
		return runtimeKey + "|inbound|" + strings.TrimSpace(subject.Value)
	case policy.TargetKindOutbound:
		return runtimeKey + "|outbound|" + strings.TrimSpace(subject.Value)
	default:
		return runtimeKey + "|" + string(subject.Kind) + "|" + strings.TrimSpace(subject.Value)
	}
}

func managedRuntimeOwnerKey(runtime discovery.SessionRuntime) string {
	return strings.Join([]string{
		string(runtime.Source),
		strings.TrimSpace(runtime.Provider),
		strings.TrimSpace(runtime.Name),
		fmt.Sprintf("%d", runtime.HostPID),
		strings.TrimSpace(runtime.ContainerID),
	}, "|")
}

func managedRetentionRequiresRuntimeEvidence(kind policy.TargetKind) bool {
	switch kind {
	case policy.TargetKindConnection, policy.TargetKindInbound, policy.TargetKindOutbound, policy.TargetKindUUID:
		return true
	default:
		return false
	}
}

func managedRootQDiscObject(scope Scope, retainRequiresRuntimeEvidence bool, cleanupEligible bool) ManagedObject {
	return ManagedObject{
		Kind:                          ManagedObjectRootQDisc,
		Device:                        strings.TrimSpace(scope.Device),
		RootHandle:                    scope.rootHandle(),
		ID:                            strings.TrimSpace(scope.rootHandle()),
		RetainRequiresRuntimeEvidence: retainRequiresRuntimeEvidence,
		CleanupEligible:               cleanupEligible,
	}
}

func managedClassObject(scope Scope, classID string, retainRequiresRuntimeEvidence bool, cleanupEligible bool) ManagedObject {
	return ManagedObject{
		Kind:                          ManagedObjectClass,
		Device:                        strings.TrimSpace(scope.Device),
		RootHandle:                    scope.rootHandle(),
		ID:                            strings.TrimSpace(classID),
		RetainRequiresRuntimeEvidence: retainRequiresRuntimeEvidence,
		CleanupEligible:               cleanupEligible,
	}
}

func managedUUIDAggregateClassObject(scope Scope, classID string, retainRequiresRuntimeEvidence bool, cleanupEligible bool) ManagedObject {
	return ManagedObject{
		Kind:                          ManagedObjectUUIDAggregateClass,
		Device:                        strings.TrimSpace(scope.Device),
		RootHandle:                    scope.rootHandle(),
		ID:                            strings.TrimSpace(classID),
		RetainRequiresRuntimeEvidence: retainRequiresRuntimeEvidence,
		CleanupEligible:               cleanupEligible,
	}
}

func managedDirectAttachmentObject(scope Scope, classID string, rule DirectAttachmentRule, retainRequiresRuntimeEvidence bool) ManagedObject {
	return ManagedObject{
		Kind:                          ManagedObjectDirectAttachmentFilter,
		Device:                        strings.TrimSpace(scope.Device),
		RootHandle:                    scope.rootHandle(),
		ID:                            directAttachmentManagedObjectID(scope.rootHandle(), classID, rule.protocolToken(), rule.Preference),
		RetainRequiresRuntimeEvidence: retainRequiresRuntimeEvidence,
	}
}

func observedDirectAttachmentObject(scope Scope, filter FilterState, retainRequiresRuntimeEvidence bool) ManagedObject {
	return ManagedObject{
		Kind:                          ManagedObjectDirectAttachmentFilter,
		Device:                        strings.TrimSpace(scope.Device),
		RootHandle:                    scope.rootHandle(),
		ID:                            directAttachmentManagedObjectID(scope.rootHandle(), filter.FlowID, filter.Protocol, filter.Preference),
		RetainRequiresRuntimeEvidence: retainRequiresRuntimeEvidence,
	}
}

func managedUUIDAggregateAttachmentObject(scope Scope, rule UUIDAggregateAttachmentRule, retainRequiresRuntimeEvidence bool) ManagedObject {
	return ManagedObject{
		Kind:                          ManagedObjectUUIDAggregateAttachmentFilter,
		Device:                        strings.TrimSpace(scope.Device),
		RootHandle:                    scope.rootHandle(),
		ID:                            uuidAggregateAttachmentManagedObjectID(scope.rootHandle(), rule.AggregateClassID, rule.Preference),
		RetainRequiresRuntimeEvidence: retainRequiresRuntimeEvidence,
	}
}

func observedUUIDAggregateAttachmentObject(scope Scope, filter FilterState, retainRequiresRuntimeEvidence bool) ManagedObject {
	return ManagedObject{
		Kind:                          ManagedObjectUUIDAggregateAttachmentFilter,
		Device:                        strings.TrimSpace(scope.Device),
		RootHandle:                    scope.rootHandle(),
		ID:                            uuidAggregateAttachmentManagedObjectID(scope.rootHandle(), filter.FlowID, filter.Preference),
		RetainRequiresRuntimeEvidence: retainRequiresRuntimeEvidence,
	}
}

func managedMarkAttachmentObjects(scope Scope, execution MarkAttachmentExecution, retainRequiresRuntimeEvidence bool, observed bool) []ManagedObject {
	objects := []ManagedObject{
		{
			Kind:                          ManagedObjectMarkAttachmentTable,
			Device:                        strings.TrimSpace(scope.Device),
			RootHandle:                    scope.rootHandle(),
			ID:                            markAttachmentTableManagedObjectID(execution.Table),
			RetainRequiresRuntimeEvidence: retainRequiresRuntimeEvidence,
		},
		{
			Kind:                          ManagedObjectMarkAttachmentChain,
			Device:                        strings.TrimSpace(scope.Device),
			RootHandle:                    scope.rootHandle(),
			ID:                            markAttachmentChainManagedObjectID(execution.Chain),
			RetainRequiresRuntimeEvidence: retainRequiresRuntimeEvidence,
		},
		{
			Kind:                          ManagedObjectMarkAttachmentRule,
			Device:                        strings.TrimSpace(scope.Device),
			RootHandle:                    scope.rootHandle(),
			ID:                            markAttachmentRuleManagedObjectID(execution.Chain.Family, execution.Chain.Table, execution.Chain.Name, execution.Rule.Comment),
			RetainRequiresRuntimeEvidence: retainRequiresRuntimeEvidence,
		},
		{
			Kind:                          ManagedObjectMarkAttachmentFilter,
			Device:                        strings.TrimSpace(scope.Device),
			RootHandle:                    scope.rootHandle(),
			ID:                            markAttachmentFilterManagedObjectID(execution.Filter),
			RetainRequiresRuntimeEvidence: retainRequiresRuntimeEvidence,
		},
	}
	if execution.usesRestoreRule() {
		objects = append(objects,
			ManagedObject{
				Kind:                          ManagedObjectMarkAttachmentRestoreChain,
				Device:                        strings.TrimSpace(scope.Device),
				RootHandle:                    scope.rootHandle(),
				ID:                            markAttachmentChainManagedObjectID(*execution.RestoreChain),
				RetainRequiresRuntimeEvidence: retainRequiresRuntimeEvidence,
			},
			ManagedObject{
				Kind:                          ManagedObjectMarkAttachmentRestoreRule,
				Device:                        strings.TrimSpace(scope.Device),
				RootHandle:                    scope.rootHandle(),
				ID:                            markAttachmentRuleManagedObjectID(execution.RestoreChain.Family, execution.RestoreChain.Table, execution.RestoreChain.Name, execution.RestoreRule.Comment),
				RetainRequiresRuntimeEvidence: retainRequiresRuntimeEvidence,
			},
		)
	}
	if !observed {
		return objects
	}

	return objects
}

func observedMarkAttachmentObjects(tcSnapshot Snapshot, nftSnapshot NftablesSnapshot, scope Scope, execution MarkAttachmentExecution, retainRequiresRuntimeEvidence bool) []ManagedObject {
	objects := make([]ManagedObject, 0, 6)
	if _, ok := nftSnapshot.Table(execution.Table); ok {
		managedChains := []MarkAttachmentChainSpec{execution.Chain}
		if execution.usesRestoreRule() {
			managedChains = append(managedChains, *execution.RestoreChain)
		}
		objects = append(objects, ManagedObject{
			Kind:                          ManagedObjectMarkAttachmentTable,
			Device:                        strings.TrimSpace(scope.Device),
			RootHandle:                    scope.rootHandle(),
			ID:                            markAttachmentTableManagedObjectID(execution.Table),
			RetainRequiresRuntimeEvidence: retainRequiresRuntimeEvidence,
			CleanupEligible:               nftSnapshot.EligibleForManagedTableCleanup(execution.Table, managedChains...),
		})
	}
	if _, ok := nftSnapshot.Chain(execution.Chain); ok {
		objects = append(objects, ManagedObject{
			Kind:                          ManagedObjectMarkAttachmentChain,
			Device:                        strings.TrimSpace(scope.Device),
			RootHandle:                    scope.rootHandle(),
			ID:                            markAttachmentChainManagedObjectID(execution.Chain),
			RetainRequiresRuntimeEvidence: retainRequiresRuntimeEvidence,
			CleanupEligible:               nftSnapshot.EligibleForManagedChainCleanup(execution.Chain, execution.Rule.Comment),
		})
	}
	for _, rule := range nftSnapshot.MarkAttachmentRules(execution) {
		objects = append(objects, ManagedObject{
			Kind:                          ManagedObjectMarkAttachmentRule,
			Device:                        strings.TrimSpace(scope.Device),
			RootHandle:                    scope.rootHandle(),
			ID:                            markAttachmentRuleManagedObjectID(rule.Family, rule.Table, rule.Chain, rule.Comment),
			RetainRequiresRuntimeEvidence: retainRequiresRuntimeEvidence,
		})
	}
	if execution.usesRestoreRule() {
		if _, ok := nftSnapshot.Chain(*execution.RestoreChain); ok {
			objects = append(objects, ManagedObject{
				Kind:                          ManagedObjectMarkAttachmentRestoreChain,
				Device:                        strings.TrimSpace(scope.Device),
				RootHandle:                    scope.rootHandle(),
				ID:                            markAttachmentChainManagedObjectID(*execution.RestoreChain),
				RetainRequiresRuntimeEvidence: retainRequiresRuntimeEvidence,
				CleanupEligible:               nftSnapshot.EligibleForManagedChainCleanup(*execution.RestoreChain, execution.RestoreRule.Comment),
			})
		}
		for _, rule := range nftSnapshot.MarkAttachmentRestoreRules(execution) {
			objects = append(objects, ManagedObject{
				Kind:                          ManagedObjectMarkAttachmentRestoreRule,
				Device:                        strings.TrimSpace(scope.Device),
				RootHandle:                    scope.rootHandle(),
				ID:                            markAttachmentRuleManagedObjectID(rule.Family, rule.Table, rule.Chain, rule.Comment),
				RetainRequiresRuntimeEvidence: retainRequiresRuntimeEvidence,
			})
		}
	}
	for range tcSnapshot.MarkAttachmentFilters(execution.Filter.Parent, execution.Filter.ClassID, execution) {
		objects = append(objects, ManagedObject{
			Kind:                          ManagedObjectMarkAttachmentFilter,
			Device:                        strings.TrimSpace(scope.Device),
			RootHandle:                    scope.rootHandle(),
			ID:                            markAttachmentFilterManagedObjectID(execution.Filter),
			RetainRequiresRuntimeEvidence: retainRequiresRuntimeEvidence,
		})
		break
	}

	return objects
}

func snapshotHasManagedRootQDisc(snapshot Snapshot, rootHandle string) bool {
	for _, qdisc := range snapshot.QDiscs {
		if strings.TrimSpace(qdisc.Kind) != "htb" {
			continue
		}
		if strings.TrimSpace(qdisc.Handle) != strings.TrimSpace(rootHandle) {
			continue
		}
		if strings.TrimSpace(qdisc.Parent) != "root" {
			continue
		}

		return true
	}

	return false
}

func directAttachmentManagedObjectID(rootHandle, classID, protocol string, preference uint32) string {
	return strings.Join([]string{
		strings.TrimSpace(rootHandle),
		strings.TrimSpace(classID),
		strings.ToLower(strings.TrimSpace(protocol)),
		fmt.Sprintf("%d", preference),
	}, "|")
}

func uuidAggregateAttachmentManagedObjectID(rootHandle, classID string, preference uint32) string {
	return strings.Join([]string{
		strings.TrimSpace(rootHandle),
		strings.TrimSpace(classID),
		fmt.Sprintf("%d", preference),
	}, "|")
}

func markAttachmentTableManagedObjectID(spec MarkAttachmentTableSpec) string {
	return strings.Join([]string{
		strings.TrimSpace(spec.Family),
		strings.TrimSpace(spec.Name),
	}, "|")
}

func markAttachmentChainManagedObjectID(spec MarkAttachmentChainSpec) string {
	return strings.Join([]string{
		strings.TrimSpace(spec.Family),
		strings.TrimSpace(spec.Table),
		strings.TrimSpace(spec.Name),
	}, "|")
}

func markAttachmentRuleManagedObjectID(family, table, chain, comment string) string {
	return strings.Join([]string{
		strings.TrimSpace(family),
		strings.TrimSpace(table),
		strings.TrimSpace(chain),
		strings.TrimSpace(comment),
	}, "|")
}

func markAttachmentFilterManagedObjectID(spec MarkAttachmentFilterSpec) string {
	return strings.Join([]string{
		strings.TrimSpace(spec.Parent),
		strings.TrimSpace(spec.ClassID),
		strconvFormatUint(uint64(spec.Preference)),
		spec.handleArg(),
	}, "|")
}

func sortManagedObjects(objects []ManagedObject) {
	sort.Slice(objects, func(i, j int) bool {
		return objects[i].fingerprint() < objects[j].fingerprint()
	})
}

func strconvFormatUint(value uint64) string {
	return fmt.Sprintf("%d", value)
}
