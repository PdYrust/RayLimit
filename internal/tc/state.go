package tc

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"sort"
	"strconv"
	"strings"

	"github.com/PdYrust/RayLimit/internal/limiter"
	"github.com/PdYrust/RayLimit/internal/policy"
)

// InspectRequest identifies the device whose tc state should be read.
type InspectRequest struct {
	Device string `json:"device"`
}

// Validate checks that the inspection request is internally consistent.
func (r InspectRequest) Validate() error {
	return validateDevice(r.Device)
}

// Snapshot captures the current read-only tc state for a device.
type Snapshot struct {
	Device  string        `json:"device"`
	QDiscs  []QDiscState  `json:"qdiscs,omitempty"`
	Classes []ClassState  `json:"classes,omitempty"`
	Filters []FilterState `json:"filters,omitempty"`
}

// Validate checks that the snapshot is internally consistent.
func (s Snapshot) Validate() error {
	if err := validateDevice(s.Device); err != nil {
		return err
	}

	for index, qdisc := range s.QDiscs {
		if err := qdisc.Validate(); err != nil {
			return fmt.Errorf("invalid qdisc at index %d: %w", index, err)
		}
	}
	for index, class := range s.Classes {
		if err := class.Validate(); err != nil {
			return fmt.Errorf("invalid class at index %d: %w", index, err)
		}
	}
	for index, filter := range s.Filters {
		if err := filter.Validate(); err != nil {
			return fmt.Errorf("invalid filter at index %d: %w", index, err)
		}
	}

	return nil
}

// Class looks up one observed class by class ID.
func (s Snapshot) Class(classID string) (ClassState, bool) {
	normalized := strings.TrimSpace(classID)
	for _, class := range s.Classes {
		if strings.TrimSpace(class.ClassID) == normalized {
			return class, true
		}
	}

	return ClassState{}, false
}

// EligibleForRootQDiscCleanup reports whether removing the selected class would
// leave behind only the RayLimit-managed root qdisc state for this scope.
func (s Snapshot) EligibleForRootQDiscCleanup(rootHandle string, classID string) bool {
	if err := validateHandleMajor(rootHandle); err != nil {
		return false
	}
	if err := validateClassID(classID, rootHandle); err != nil {
		return false
	}
	if len(s.Filters) != 0 {
		return false
	}
	if len(s.QDiscs) != 1 || len(s.Classes) != 1 {
		return false
	}

	qdisc := s.QDiscs[0]
	if strings.TrimSpace(qdisc.Kind) != "htb" {
		return false
	}
	if strings.TrimSpace(qdisc.Handle) != strings.TrimSpace(rootHandle) {
		return false
	}
	if strings.TrimSpace(qdisc.Parent) != "root" {
		return false
	}

	class := s.Classes[0]
	if strings.TrimSpace(class.ClassID) != strings.TrimSpace(classID) {
		return false
	}
	if strings.TrimSpace(class.Parent) != strings.TrimSpace(rootHandle) {
		return false
	}

	return true
}

// EligibleForRootQDiscCleanupAfterManagedObjectRemoval reports whether removing
// the selected observed managed objects would leave only the RayLimit-managed
// root qdisc state for this scope.
func (s Snapshot) EligibleForRootQDiscCleanupAfterManagedObjectRemoval(rootHandle string, objects []ManagedObject) bool {
	if err := validateHandleMajor(rootHandle); err != nil {
		return false
	}
	if len(objects) == 0 {
		return false
	}
	if len(s.QDiscs) != 1 {
		return false
	}

	qdisc := s.QDiscs[0]
	if strings.TrimSpace(qdisc.Kind) != "htb" {
		return false
	}
	if strings.TrimSpace(qdisc.Handle) != strings.TrimSpace(rootHandle) {
		return false
	}
	if strings.TrimSpace(qdisc.Parent) != "root" {
		return false
	}

	observedRoot := false
	ignoredClasses := make(map[string]struct{}, len(objects))
	ignoredDirectFilters := make(map[string]struct{}, len(objects))
	for _, object := range objects {
		if err := object.Validate(); err != nil {
			return false
		}
		if strings.TrimSpace(object.RootHandle) != strings.TrimSpace(rootHandle) {
			continue
		}

		switch object.Kind {
		case ManagedObjectRootQDisc:
			observedRoot = true
		case ManagedObjectClass:
			ignoredClasses[strings.TrimSpace(object.ID)] = struct{}{}
		case ManagedObjectDirectAttachmentFilter:
			ignoredDirectFilters[strings.TrimSpace(object.ID)] = struct{}{}
		}
	}
	if !observedRoot {
		return false
	}

	for _, class := range s.Classes {
		if strings.TrimSpace(class.Parent) != strings.TrimSpace(rootHandle) {
			return false
		}
		if _, ok := ignoredClasses[strings.TrimSpace(class.ClassID)]; ok {
			continue
		}
		return false
	}

	for _, filter := range s.Filters {
		if strings.TrimSpace(filter.Parent) != strings.TrimSpace(rootHandle) {
			return false
		}
		if _, ok := ignoredDirectFilters[filterDirectAttachmentManagedObjectID(filter, rootHandle)]; ok {
			continue
		}
		return false
	}

	return true
}

func filterDirectAttachmentManagedObjectID(filter FilterState, rootHandle string) string {
	return directAttachmentManagedObjectID(
		rootHandle,
		filter.Kind,
		filter.Protocol,
		filter.Preference,
		filter.FlowID,
	)
}

// QDiscState captures a minimal observed qdisc.
type QDiscState struct {
	Kind   string `json:"kind"`
	Handle string `json:"handle,omitempty"`
	Parent string `json:"parent,omitempty"`
}

// Validate checks that the qdisc state is internally consistent.
func (s QDiscState) Validate() error {
	if strings.TrimSpace(s.Kind) == "" {
		return errors.New("qdisc kind is required")
	}
	if err := validateOptionalHandle(s.Handle); err != nil {
		return fmt.Errorf("invalid qdisc handle: %w", err)
	}
	if err := validateParent(s.Parent); err != nil {
		return fmt.Errorf("invalid qdisc parent: %w", err)
	}

	return nil
}

// ClassState captures a minimal observed class suitable for later reconciliation.
type ClassState struct {
	Kind               string `json:"kind"`
	ClassID            string `json:"class_id"`
	Parent             string `json:"parent,omitempty"`
	RateBytesPerSecond int64  `json:"rate_bytes_per_second,omitempty"`
	CeilBytesPerSecond int64  `json:"ceil_bytes_per_second,omitempty"`
}

// Validate checks that the class state is internally consistent.
func (s ClassState) Validate() error {
	if strings.TrimSpace(s.Kind) == "" {
		return errors.New("class kind is required")
	}
	rootHandle, err := rootHandleFromClassID(s.ClassID)
	if err != nil {
		return err
	}
	if err := validateClassID(strings.TrimSpace(s.ClassID), rootHandle); err != nil {
		return err
	}
	if err := validateParent(s.Parent); err != nil {
		return fmt.Errorf("invalid class parent: %w", err)
	}
	if s.RateBytesPerSecond < 0 {
		return errors.New("class rate must be greater than or equal to zero")
	}
	if s.CeilBytesPerSecond < 0 {
		return errors.New("class ceil must be greater than or equal to zero")
	}

	return nil
}

// AppliedState converts one observed class into limiter applied state for a known subject and direction.
func (s ClassState) AppliedState(subject limiter.Subject, direction Direction) (limiter.AppliedState, error) {
	if err := s.Validate(); err != nil {
		return limiter.AppliedState{}, err
	}
	if err := subject.Validate(); err != nil {
		return limiter.AppliedState{}, err
	}
	if !direction.Valid() {
		return limiter.AppliedState{}, fmt.Errorf("invalid direction %q", direction)
	}

	rate := s.RateBytesPerSecond
	if rate == 0 {
		rate = s.CeilBytesPerSecond
	}
	if rate == 0 {
		return limiter.AppliedState{}, errors.New("observed class does not expose a parsable rate")
	}

	limits := policy.LimitPolicy{}
	switch direction {
	case DirectionUpload:
		limits.Upload = &policy.RateLimit{BytesPerSecond: rate}
	case DirectionDownload:
		limits.Download = &policy.RateLimit{BytesPerSecond: rate}
	}

	applied := limiter.AppliedState{
		Mode:      limiter.DesiredModeLimit,
		Subject:   subject,
		Limits:    limits,
		Driver:    driverName,
		Reference: strings.TrimSpace(s.ClassID),
	}
	if err := applied.Validate(); err != nil {
		return limiter.AppliedState{}, err
	}

	return applied, nil
}

// FilterState captures a minimal observed filter.
type FilterState struct {
	Kind       string `json:"kind"`
	Parent     string `json:"parent,omitempty"`
	Protocol   string `json:"protocol,omitempty"`
	Preference uint32 `json:"preference,omitempty"`
	Handle     string `json:"handle,omitempty"`
	FlowID     string `json:"flow_id,omitempty"`
}

// Validate checks that the filter state is internally consistent.
func (s FilterState) Validate() error {
	if strings.TrimSpace(s.Kind) == "" {
		return errors.New("filter kind is required")
	}
	if err := validateParent(s.Parent); err != nil {
		return fmt.Errorf("invalid filter parent: %w", err)
	}
	if err := validateFilterHandle(s.Handle); err != nil {
		return fmt.Errorf("invalid filter handle: %w", err)
	}

	return nil
}

// DirectAttachmentFilters returns observed u32 filters that match the expected
// direct attachment execution rules for one direct limiter subject.
func (s Snapshot) DirectAttachmentFilters(rootHandle string, classID string, execution DirectAttachmentExecution) []FilterState {
	return directAttachmentFilters(s.Filters, rootHandle, classID, execution)
}

// MarkAttachmentFilters returns observed fw filters that match one managed
// mark-backed attachment execution.
func (s Snapshot) MarkAttachmentFilters(rootHandle string, classID string, execution MarkAttachmentExecution) []FilterState {
	if err := validateHandleMajor(rootHandle); err != nil {
		return nil
	}
	if err := validateClassID(classID, rootHandle); err != nil {
		return nil
	}
	if execution.Readiness != BindingReadinessReady {
		return nil
	}

	filters := make([]FilterState, 0, len(s.Filters))
	for _, filter := range s.Filters {
		if strings.TrimSpace(filter.Kind) != "fw" {
			continue
		}
		if strings.TrimSpace(filter.Parent) != strings.TrimSpace(rootHandle) {
			continue
		}
		if filter.Preference != execution.Filter.Preference {
			continue
		}
		if strings.TrimSpace(filter.FlowID) != strings.TrimSpace(classID) {
			continue
		}
		observedMark, observedMask, ok := parseTCFilterHandle(strings.TrimSpace(filter.Handle))
		if !ok {
			continue
		}
		if observedMark != execution.Filter.Mark || observedMask != execution.Filter.Mask {
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

// HasFWClassFilter reports whether the observed state already includes at least
// one fw filter for the selected root handle and class id.
func (s Snapshot) HasFWClassFilter(rootHandle string, classID string) bool {
	if err := validateHandleMajor(rootHandle); err != nil {
		return false
	}
	if err := validateClassID(classID, rootHandle); err != nil {
		return false
	}

	for _, filter := range s.Filters {
		if strings.TrimSpace(filter.Kind) != "fw" {
			continue
		}
		if strings.TrimSpace(filter.Parent) != strings.TrimSpace(rootHandle) {
			continue
		}
		if strings.TrimSpace(filter.FlowID) != strings.TrimSpace(classID) {
			continue
		}

		return true
	}

	return false
}

// EligibleForRootQDiscCleanupAfterDirectAttachmentRemoval reports whether
// removing the selected class together with the currently expected direct
// attachment filters would leave only the RayLimit-managed root qdisc state.
func (s Snapshot) EligibleForRootQDiscCleanupAfterDirectAttachmentRemoval(rootHandle string, classID string, execution DirectAttachmentExecution) bool {
	if err := validateHandleMajor(rootHandle); err != nil {
		return false
	}
	if err := validateClassID(classID, rootHandle); err != nil {
		return false
	}
	if execution.Readiness != BindingReadinessReady {
		return false
	}
	if len(s.QDiscs) != 1 || len(s.Classes) > 1 {
		return false
	}

	if len(execution.rulePreferences()) == 0 {
		return false
	}
	ignoredKeys := execution.filterExpectationKeys()

	for _, filter := range s.Filters {
		if strings.TrimSpace(filter.Parent) == strings.TrimSpace(rootHandle) {
			if _, ok := ignoredKeys[directAttachmentFilterKey(filter)]; ok {
				continue
			}
		}
		return false
	}

	qdisc := s.QDiscs[0]
	if strings.TrimSpace(qdisc.Kind) != "htb" {
		return false
	}
	if strings.TrimSpace(qdisc.Handle) != strings.TrimSpace(rootHandle) {
		return false
	}
	if strings.TrimSpace(qdisc.Parent) != "root" {
		return false
	}

	if len(s.Classes) == 1 {
		class := s.Classes[0]
		if strings.TrimSpace(class.ClassID) != strings.TrimSpace(classID) {
			return false
		}
		if strings.TrimSpace(class.Parent) != strings.TrimSpace(rootHandle) {
			return false
		}
	}

	return true
}

// EligibleForRootQDiscCleanupAfterMarkAttachmentRemoval reports whether
// removing the selected class together with the currently observed managed fw
// filters would leave only the RayLimit-managed root qdisc state.
func (s Snapshot) EligibleForRootQDiscCleanupAfterMarkAttachmentRemoval(rootHandle string, classID string, execution MarkAttachmentExecution) bool {
	if err := validateHandleMajor(rootHandle); err != nil {
		return false
	}
	if err := validateClassID(classID, rootHandle); err != nil {
		return false
	}
	if execution.Readiness != BindingReadinessReady {
		return false
	}
	if len(s.QDiscs) != 1 || len(s.Classes) > 1 {
		return false
	}

	managedFilters := s.MarkAttachmentFilters(rootHandle, classID, execution)
	if len(managedFilters) == 0 {
		return false
	}
	ignored := make(map[string]struct{}, len(managedFilters))
	for _, filter := range managedFilters {
		ignored[markAttachmentFilterKey(filter)] = struct{}{}
	}

	for _, filter := range s.Filters {
		if strings.TrimSpace(filter.Kind) == "fw" &&
			strings.TrimSpace(filter.Parent) == strings.TrimSpace(rootHandle) &&
			strings.TrimSpace(filter.FlowID) == strings.TrimSpace(classID) {
			if _, ok := ignored[markAttachmentFilterKey(filter)]; ok {
				continue
			}
		}
		return false
	}

	qdisc := s.QDiscs[0]
	if strings.TrimSpace(qdisc.Kind) != "htb" {
		return false
	}
	if strings.TrimSpace(qdisc.Handle) != strings.TrimSpace(rootHandle) {
		return false
	}
	if strings.TrimSpace(qdisc.Parent) != "root" {
		return false
	}

	if len(s.Classes) == 1 {
		class := s.Classes[0]
		if strings.TrimSpace(class.ClassID) != strings.TrimSpace(classID) {
			return false
		}
		if strings.TrimSpace(class.Parent) != strings.TrimSpace(rootHandle) {
			return false
		}
	}

	return true
}

// Inspector reads tc state from the local host without mutating it.
type Inspector struct {
	Runner Runner
}

// Inspect executes read-only tc commands and parses their output into a snapshot.
func (i Inspector) Inspect(ctx context.Context, req InspectRequest) (Snapshot, []Result, error) {
	if err := req.Validate(); err != nil {
		return Snapshot{}, nil, err
	}

	steps := buildInspectSteps(defaultBinary, strings.TrimSpace(req.Device))
	runner := i.runner()
	results := make([]Result, 0, len(steps))
	for _, step := range steps {
		result, err := runner.Run(ctx, step.Command)
		result.Step = step.Name
		if err != nil {
			if result.Error == "" {
				result.Error = err.Error()
			}
			results = append(results, result)
			return Snapshot{Device: strings.TrimSpace(req.Device)}, results, err
		}
		results = append(results, result)
	}

	snapshot, err := ParseSnapshot(req.Device, results)
	if err != nil {
		return Snapshot{}, results, err
	}

	return snapshot, results, nil
}

func (i Inspector) runner() Runner {
	if i.Runner != nil {
		return i.Runner
	}

	return SystemRunner{}
}

// ParseSnapshot converts successful tc read results into a structured snapshot.
func ParseSnapshot(device string, results []Result) (Snapshot, error) {
	snapshot := Snapshot{
		Device: strings.TrimSpace(device),
	}
	if err := validateDevice(snapshot.Device); err != nil {
		return Snapshot{}, err
	}

	for _, result := range results {
		if result.Error != "" {
			return Snapshot{}, fmt.Errorf("inspect step %q failed: %s", result.Step, result.Error)
		}

		switch result.Step {
		case "show-qdisc":
			qdiscs, err := parseQDiscStates(result.Stdout)
			if err != nil {
				return Snapshot{}, fmt.Errorf("parse qdisc state: %w", err)
			}
			snapshot.QDiscs = qdiscs
		case "show-class":
			classes, err := parseClassStates(result.Stdout)
			if err != nil {
				return Snapshot{}, fmt.Errorf("parse class state: %w", err)
			}
			snapshot.Classes = classes
		case "show-filter":
			filters, err := parseFilterStates(result.Stdout)
			if err != nil {
				return Snapshot{}, fmt.Errorf("parse filter state: %w", err)
			}
			snapshot.Filters = filters
		}
	}

	if err := snapshot.Validate(); err != nil {
		return Snapshot{}, err
	}

	return snapshot, nil
}

func parseQDiscStates(stdout string) ([]QDiscState, error) {
	entries, err := parseEntries(stdout)
	if err != nil {
		return nil, err
	}

	states := make([]QDiscState, 0, len(entries))
	for _, entry := range entries {
		states = append(states, QDiscState{
			Kind:   stringField(entry, "kind"),
			Handle: stringField(entry, "handle"),
			Parent: firstStringField(entry, "parent", "root"),
		})
	}

	return states, nil
}

func parseClassStates(stdout string) ([]ClassState, error) {
	entries, err := parseEntries(stdout)
	if err != nil {
		return nil, err
	}

	states := make([]ClassState, 0, len(entries))
	for _, entry := range entries {
		states = append(states, ClassState{
			Kind:               firstStringField(entry, "kind", "class"),
			ClassID:            firstStringField(entry, "classid", "handle"),
			Parent:             stringField(entry, "parent"),
			RateBytesPerSecond: firstRateBytesPerSecond(entry, "rate"),
			CeilBytesPerSecond: firstRateBytesPerSecond(entry, "ceil"),
		})
	}

	return states, nil
}

func parseFilterStates(stdout string) ([]FilterState, error) {
	entries, err := parseEntries(stdout)
	if err != nil {
		return nil, err
	}

	states := make([]FilterState, 0, len(entries))
	for _, entry := range entries {
		states = append(states, FilterState{
			Kind:       stringField(entry, "kind"),
			Parent:     stringField(entry, "parent"),
			Protocol:   stringField(entry, "protocol"),
			Preference: firstUint32Field(entry, "pref", "preference"),
			Handle:     firstScalarStringField(entry, "handle"),
			FlowID:     firstNestedStringField(entry, "flowid", "classid"),
		})
	}

	return states, nil
}

func parseEntries(stdout string) ([]map[string]any, error) {
	payload := strings.TrimSpace(stdout)
	if payload == "" {
		return nil, nil
	}

	var entries []map[string]any
	if err := json.Unmarshal([]byte(payload), &entries); err != nil {
		return nil, err
	}

	return entries, nil
}

func stringField(entry map[string]any, key string) string {
	value, ok := entry[key]
	if !ok {
		return ""
	}

	stringValue, ok := value.(string)
	if !ok {
		return ""
	}

	return strings.TrimSpace(stringValue)
}

func firstStringField(entry map[string]any, keys ...string) string {
	for _, key := range keys {
		if value := stringField(entry, key); value != "" {
			return value
		}
	}

	return ""
}

func scalarStringField(entry map[string]any, key string) string {
	value, ok := entry[key]
	if !ok {
		return ""
	}

	switch typed := value.(type) {
	case string:
		return strings.TrimSpace(typed)
	case float64:
		if typed == float64(int64(typed)) {
			return strconv.FormatInt(int64(typed), 10)
		}
	case json.Number:
		return strings.TrimSpace(typed.String())
	}

	return ""
}

func firstScalarStringField(entry map[string]any, keys ...string) string {
	for _, key := range keys {
		if value := scalarStringField(entry, key); value != "" {
			return value
		}
	}

	options, ok := entry["options"].(map[string]any)
	if !ok {
		return ""
	}
	for _, key := range keys {
		if value := scalarStringField(options, key); value != "" {
			return value
		}
	}

	return ""
}

func firstNestedStringField(entry map[string]any, keys ...string) string {
	if value := firstStringField(entry, keys...); value != "" {
		return value
	}

	options, ok := entry["options"].(map[string]any)
	if !ok {
		return ""
	}

	return firstStringField(options, keys...)
}

func firstRateBytesPerSecond(entry map[string]any, key string) int64 {
	candidates := []any{entry[key], entry[key+"64"]}
	if options, ok := entry["options"].(map[string]any); ok {
		candidates = append(candidates, options[key], options[key+"64"])
	}

	for _, candidate := range candidates {
		if value, ok := parseBytesPerSecond(candidate); ok {
			return value
		}
	}

	return 0
}

func firstUint32Field(entry map[string]any, keys ...string) uint32 {
	candidates := make([]any, 0, len(keys)*2)
	for _, key := range keys {
		candidates = append(candidates, entry[key])
	}
	if options, ok := entry["options"].(map[string]any); ok {
		for _, key := range keys {
			candidates = append(candidates, options[key])
		}
	}

	for _, candidate := range candidates {
		if value, ok := parseUint32(candidate); ok {
			return value
		}
	}

	return 0
}

func parseBytesPerSecond(value any) (int64, bool) {
	switch typed := value.(type) {
	case string:
		return parseBytesPerSecondString(typed)
	case float64, json.Number:
		return parseInteger(typed)
	case map[string]any:
		if nested, ok := typed["bps"]; ok {
			return parseInteger(nested)
		}
		if nested, ok := typed["rate64"]; ok {
			return parseBytesPerSecond(nested)
		}
		if nested, ok := typed["rate"]; ok {
			return parseBytesPerSecond(nested)
		}
	}

	return 0, false
}

func parseBytesPerSecondString(value string) (int64, bool) {
	normalized := strings.ReplaceAll(strings.ToLower(strings.TrimSpace(value)), " ", "")
	if normalized == "" {
		return 0, false
	}

	type unitScale struct {
		suffix     string
		multiplier float64
		bits       bool
	}

	units := []unitScale{
		{suffix: "tibps", multiplier: float64(1 << 40), bits: false},
		{suffix: "gibps", multiplier: float64(1 << 30), bits: false},
		{suffix: "mibps", multiplier: float64(1 << 20), bits: false},
		{suffix: "kibps", multiplier: float64(1 << 10), bits: false},
		{suffix: "tbps", multiplier: 1_000_000_000_000, bits: false},
		{suffix: "gbps", multiplier: 1_000_000_000, bits: false},
		{suffix: "mbps", multiplier: 1_000_000, bits: false},
		{suffix: "kbps", multiplier: 1_000, bits: false},
		{suffix: "bps", multiplier: 1, bits: false},
		{suffix: "tibit", multiplier: float64(1 << 40), bits: true},
		{suffix: "gibit", multiplier: float64(1 << 30), bits: true},
		{suffix: "mibit", multiplier: float64(1 << 20), bits: true},
		{suffix: "kibit", multiplier: float64(1 << 10), bits: true},
		{suffix: "tbit", multiplier: 1_000_000_000_000, bits: true},
		{suffix: "gbit", multiplier: 1_000_000_000, bits: true},
		{suffix: "mbit", multiplier: 1_000_000, bits: true},
		{suffix: "kbit", multiplier: 1_000, bits: true},
		{suffix: "bit", multiplier: 1, bits: true},
	}

	for _, unit := range units {
		if !strings.HasSuffix(normalized, unit.suffix) {
			continue
		}
		return scaleBytesPerSecond(strings.TrimSuffix(normalized, unit.suffix), unit.multiplier, unit.bits)
	}

	return scaleBytesPerSecond(normalized, 1, true)
}

func scaleBytesPerSecond(value string, multiplier float64, bits bool) (int64, bool) {
	parsed, err := strconv.ParseFloat(strings.TrimSpace(value), 64)
	if err != nil || parsed < 0 {
		return 0, false
	}

	scaled := parsed * multiplier
	if bits {
		scaled /= 8
	}
	if math.IsNaN(scaled) || math.IsInf(scaled, 0) || scaled < 0 {
		return 0, false
	}

	rounded := math.Round(scaled)
	if math.Abs(scaled-rounded) > 1e-6 {
		return 0, false
	}
	if rounded > float64(math.MaxInt64) {
		return 0, false
	}

	return int64(rounded), true
}

func parseInteger(value any) (int64, bool) {
	switch typed := value.(type) {
	case float64:
		if typed < 0 || typed != float64(int64(typed)) {
			return 0, false
		}
		return int64(typed), true
	default:
		return 0, false
	}
}

func parseUint32(value any) (uint32, bool) {
	switch typed := value.(type) {
	case float64:
		if typed < 0 || typed > float64(^uint32(0)) || typed != float64(uint32(typed)) {
			return 0, false
		}
		return uint32(typed), true
	case string:
		parsed, ok := parseSignedInteger(strings.TrimSpace(typed))
		if !ok || parsed < 0 || parsed > int64(^uint32(0)) {
			return 0, false
		}
		return uint32(parsed), true
	case json.Number:
		parsed, err := typed.Int64()
		if err != nil || parsed < 0 || parsed > int64(^uint32(0)) {
			return 0, false
		}
		return uint32(parsed), true
	default:
		return 0, false
	}
}

func parseSignedInteger(value string) (int64, bool) {
	if value == "" {
		return 0, false
	}

	parsed, err := json.Number(value).Int64()
	if err != nil {
		return 0, false
	}

	return parsed, true
}

func validateOptionalHandle(handle string) error {
	handle = strings.TrimSpace(handle)
	if handle == "" {
		return nil
	}

	return validateHandleMajor(handle)
}

func validateFilterHandle(handle string) error {
	handle = strings.TrimSpace(handle)
	if handle == "" {
		return nil
	}
	if strings.ContainsAny(handle, " \t\r\n") {
		return fmt.Errorf("invalid filter handle %q", handle)
	}

	return nil
}

func parseTCFilterHandle(value string) (uint32, uint32, bool) {
	value = strings.TrimSpace(value)
	if value == "" {
		return 0, 0, false
	}

	handlePart := value
	maskPart := ""
	if before, after, ok := strings.Cut(value, "/"); ok {
		handlePart = before
		maskPart = after
	}

	handle, err := strconv.ParseUint(strings.TrimSpace(handlePart), 0, 32)
	if err != nil || handle == 0 {
		return 0, 0, false
	}
	mask := uint64(^uint32(0))
	if strings.TrimSpace(maskPart) != "" {
		mask, err = strconv.ParseUint(strings.TrimSpace(maskPart), 0, 32)
		if err != nil || mask == 0 {
			return 0, 0, false
		}
	}

	return uint32(handle), uint32(mask), true
}

func markAttachmentFilterKey(filter FilterState) string {
	handle, mask, _ := parseTCFilterHandle(strings.TrimSpace(filter.Handle))
	return strings.Join([]string{
		strings.TrimSpace(filter.Kind),
		strings.TrimSpace(filter.Parent),
		fmt.Sprintf("%d", filter.Preference),
		strings.TrimSpace(filter.FlowID),
		fmt.Sprintf("0x%x", handle),
		fmt.Sprintf("0x%x", mask),
	}, "|")
}

func validateParent(parent string) error {
	parent = strings.TrimSpace(parent)
	if parent == "" || parent == "root" {
		return nil
	}
	if strings.HasSuffix(parent, ":") {
		return validateHandleMajor(parent)
	}

	rootHandle, err := rootHandleFromClassID(parent)
	if err != nil {
		return err
	}

	return validateClassID(parent, rootHandle)
}

func rootHandleFromClassID(classID string) (string, error) {
	classID = strings.TrimSpace(classID)
	parts := strings.Split(classID, ":")
	if len(parts) != 2 || parts[0] == "" {
		return "", fmt.Errorf("invalid class id %q", classID)
	}

	return parts[0] + ":", nil
}
