package tc

import (
	"errors"
	"fmt"
	"hash/fnv"
	"strings"

	"github.com/PdYrust/RayLimit/internal/ipaddr"
	"github.com/PdYrust/RayLimit/internal/limiter"
	"github.com/PdYrust/RayLimit/internal/policy"
)

const (
	defaultBinary     = "tc"
	defaultNftBinary  = "nft"
	defaultRootHandle = "1:"
	driverName        = "tc"
)

// Direction identifies which side of a limit policy a tc plan applies to.
type Direction string

const (
	DirectionUpload   Direction = "upload"
	DirectionDownload Direction = "download"
)

func (d Direction) Valid() bool {
	switch d {
	case DirectionUpload, DirectionDownload:
		return true
	default:
		return false
	}
}

// Scope identifies the Linux interface and direction a tc plan operates on.
type Scope struct {
	Device     string    `json:"device"`
	Direction  Direction `json:"direction"`
	RootHandle string    `json:"root_handle,omitempty"`
}

// Validate checks that a planning scope is internally consistent.
func (s Scope) Validate() error {
	if err := validateDevice(s.Device); err != nil {
		return err
	}
	if !s.Direction.Valid() {
		return fmt.Errorf("invalid scope direction %q", s.Direction)
	}
	if err := validateHandleMajor(s.rootHandle()); err != nil {
		return fmt.Errorf("invalid root handle: %w", err)
	}

	return nil
}

func (s Scope) rootHandle() string {
	handle := strings.TrimSpace(s.RootHandle)
	if handle == "" {
		return defaultRootHandle
	}

	return handle
}

// Command is a validated shell-safe backend invocation.
type Command struct {
	Path string   `json:"path"`
	Args []string `json:"args,omitempty"`
}

// Validate checks that a command is internally consistent.
func (c Command) Validate() error {
	if strings.TrimSpace(c.Path) == "" {
		return errors.New("command path is required")
	}
	for index, arg := range c.Args {
		if strings.TrimSpace(arg) == "" {
			return fmt.Errorf("command argument at index %d is blank", index)
		}
	}

	return nil
}

// Step identifies one planned backend command.
type Step struct {
	Name    string  `json:"name"`
	Command Command `json:"command"`
}

// Validate checks that a plan step is internally consistent.
func (s Step) Validate() error {
	if strings.TrimSpace(s.Name) == "" {
		return errors.New("step name is required")
	}
	if err := s.Command.Validate(); err != nil {
		return fmt.Errorf("invalid step command: %w", err)
	}

	return nil
}

// Handles contains deterministic tc identifiers for a subject on a scope.
type Handles struct {
	RootHandle string `json:"root_handle"`
	ClassID    string `json:"class_id"`
}

// Validate checks that handle identifiers are internally consistent.
func (h Handles) Validate() error {
	if err := validateHandleMajor(h.RootHandle); err != nil {
		return fmt.Errorf("invalid root handle: %w", err)
	}
	if err := validateClassID(h.ClassID, h.RootHandle); err != nil {
		return fmt.Errorf("invalid class id: %w", err)
	}

	return nil
}

// Plan captures the backend commands required to satisfy a limiter action on a scope.
type Plan struct {
	Action              limiter.Action            `json:"action"`
	Scope               Scope                     `json:"scope"`
	Binding             Binding                   `json:"binding"`
	Handles             Handles                   `json:"handles"`
	AttachmentExecution DirectAttachmentExecution `json:"attachment_execution"`
	MarkAttachment      *MarkAttachmentExecution  `json:"mark_attachment,omitempty"`
	Steps               []Step                    `json:"steps,omitempty"`
	NoOp                bool                      `json:"no_op,omitempty"`
}

// Validate checks that a tc plan is internally consistent.
func (p Plan) Validate() error {
	if err := p.Action.Validate(); err != nil {
		return fmt.Errorf("invalid plan action: %w", err)
	}
	if err := p.Scope.Validate(); err != nil {
		return fmt.Errorf("invalid plan scope: %w", err)
	}
	if err := p.Binding.Validate(); err != nil {
		return fmt.Errorf("invalid plan binding: %w", err)
	}
	if !p.Binding.EffectiveSubject.Equal(p.Action.Subject) {
		return errors.New("plan binding effective subject does not match the action subject")
	}
	if err := p.Handles.Validate(); err != nil {
		return fmt.Errorf("invalid plan handles: %w", err)
	}
	if err := p.AttachmentExecution.Validate(); err != nil {
		return fmt.Errorf("invalid plan attachment execution: %w", err)
	}
	if p.MarkAttachment != nil {
		if err := p.MarkAttachment.Validate(); err != nil {
			return fmt.Errorf("invalid plan mark attachment: %w", err)
		}
		if strings.TrimSpace(p.MarkAttachment.Filter.ClassID) != strings.TrimSpace(p.Handles.ClassID) {
			return errors.New("plan mark attachment filter does not match the plan class id")
		}
		if strings.TrimSpace(p.MarkAttachment.Filter.Parent) != strings.TrimSpace(p.Handles.RootHandle) {
			return errors.New("plan mark attachment filter does not match the plan root handle")
		}
		if p.Binding.Identity != nil {
			if p.MarkAttachment.Identity.Kind != p.Binding.Identity.Kind || strings.TrimSpace(p.MarkAttachment.Identity.Value) != strings.TrimSpace(p.Binding.Identity.Value) {
				return errors.New("plan mark attachment identity does not match the plan binding identity")
			}
		}
	}
	for index, rule := range p.AttachmentExecution.Rules {
		if rule.Disposition != DirectAttachmentDispositionClassify {
			continue
		}
		if strings.TrimSpace(rule.ClassID) != strings.TrimSpace(p.Handles.ClassID) {
			return fmt.Errorf("attachment execution rule at index %d does not match the plan class id", index)
		}
	}
	for index, step := range p.Steps {
		if err := step.Validate(); err != nil {
			return fmt.Errorf("invalid step at index %d: %w", index, err)
		}
	}

	return nil
}

// Planner turns limiter actions into backend command plans without executing them.
type Planner struct {
	Binary string
}

// Plan builds a backend plan for the given limiter action and interface scope.
func (p Planner) Plan(action limiter.Action, scope Scope) (Plan, error) {
	if err := action.Validate(); err != nil {
		return Plan{}, fmt.Errorf("invalid limiter action: %w", err)
	}
	if err := scope.Validate(); err != nil {
		return Plan{}, err
	}

	binding, err := BindSubject(action.Subject)
	if err != nil {
		return Plan{}, err
	}

	plan := Plan{
		Action:  action,
		Scope:   scope,
		Binding: binding,
		Handles: Handles{
			RootHandle: scope.rootHandle(),
			ClassID:    deriveClassID(action.Subject, scope.Direction, scope.rootHandle()),
		},
	}

	if err := plan.Handles.Validate(); err != nil {
		return Plan{}, err
	}
	mode := attachmentModeForAction(action)
	attachmentExecution, err := BuildDirectAttachmentExecution(binding, scope, mode, attachmentClassID(mode, plan.Handles))
	if err != nil {
		return Plan{}, err
	}
	plan.AttachmentExecution = attachmentExecution

	switch action.Kind {
	case limiter.ActionApply:
		plan.Steps, err = p.applySteps(plan, *action.Desired)
	case limiter.ActionRemove:
		plan.Steps, err = p.removeSteps(plan)
	case limiter.ActionInspect:
		plan.Steps = p.inspectSteps(plan)
	case limiter.ActionReconcile:
		plan.Steps, plan.NoOp, err = p.reconcileSteps(plan, *action.Desired, action.Applied)
	default:
		err = fmt.Errorf("unsupported limiter action %q", action.Kind)
	}
	if err != nil {
		return Plan{}, err
	}

	if err := plan.Validate(); err != nil {
		return Plan{}, err
	}

	return plan, nil
}

func (p Planner) applySteps(plan Plan, desired limiter.DesiredState) ([]Step, error) {
	steps := []Step{
		p.step("ensure-root-qdisc", "qdisc", "replace", "dev", plan.Scope.Device, "root", "handle", plan.Handles.RootHandle, "htb"),
	}
	if desired.Mode == limiter.DesiredModeLimit {
		rate, err := rateForDirection(desired.Limits, plan.Scope.Direction)
		if err != nil {
			return nil, err
		}
		steps = append(steps,
			p.step("upsert-class", "class", "replace", "dev", plan.Scope.Device, "parent", plan.Handles.RootHandle, "classid", plan.Handles.ClassID, "htb", "rate", rate, "ceil", rate),
		)
	}
	if plan.AttachmentExecution.Readiness == BindingReadinessReady {
		steps = append(steps, p.directAttachmentApplySteps(plan)...)
	}

	return steps, nil
}

func (p Planner) removeSteps(plan Plan) ([]Step, error) {
	tcStates, err := tcAppliedStates(plan.Action.Applied)
	if err != nil {
		return nil, err
	}

	ids, err := p.removeClassIDs(tcStates, plan.Handles)
	if err != nil {
		return nil, err
	}
	executions, err := p.removeAttachmentExecutions(plan, tcStates)
	if err != nil {
		return nil, err
	}
	steps := make([]Step, 0, len(ids))
	nextAttachmentIndex := 1
	for _, execution := range executions {
		executionSteps := p.directAttachmentRemoveSteps(plan.Scope, plan.Handles.RootHandle, execution, nextAttachmentIndex)
		steps = append(steps, executionSteps...)
		nextAttachmentIndex += len(executionSteps)
	}
	for _, classID := range ids {
		steps = append(steps, p.step("delete-class", "class", "del", "dev", plan.Scope.Device, "classid", classID))
	}

	return steps, nil
}

func (p Planner) inspectSteps(plan Plan) []Step {
	return buildInspectSteps(p.binary(), plan.Scope.Device)
}

func (p Planner) reconcileSteps(plan Plan, desired limiter.DesiredState, applied []limiter.AppliedState) ([]Step, bool, error) {
	tcStates, err := tcAppliedStates(applied)
	if err != nil {
		return nil, false, err
	}

	for _, state := range tcStates {
		if state.MatchesDesired(desired) {
			return nil, true, nil
		}
	}

	steps := make([]Step, 0, len(tcStates)+2)
	if len(tcStates) > 0 {
		removePlan := plan
		removePlan.Action.Applied = tcStates
		removeSteps, err := p.removeSteps(removePlan)
		if err != nil {
			return nil, false, err
		}
		steps = append(steps, removeSteps...)
	}

	applySteps, err := p.applySteps(plan, desired)
	if err != nil {
		return nil, false, err
	}
	steps = append(steps, applySteps...)

	return steps, false, nil
}

func (p Planner) step(name string, args ...string) Step {
	return Step{
		Name: name,
		Command: Command{
			Path: p.binary(),
			Args: args,
		},
	}
}

func attachmentModeForAction(action limiter.Action) limiter.DesiredMode {
	if action.Desired != nil && action.Desired.Mode.Valid() {
		return action.Desired.Mode
	}

	return limiter.DesiredModeLimit
}

func attachmentClassID(mode limiter.DesiredMode, handles Handles) string {
	if mode == limiter.DesiredModeUnlimited {
		return ""
	}

	return handles.ClassID
}

func (p Planner) binary() string {
	if strings.TrimSpace(p.Binary) == "" {
		return defaultBinary
	}

	return strings.TrimSpace(p.Binary)
}

func tcCommandPath(plan Plan) string {
	for _, step := range plan.Steps {
		if isTCCommand(step.Command) && strings.TrimSpace(step.Command.Path) != "" {
			return strings.TrimSpace(step.Command.Path)
		}
	}

	return defaultBinary
}

func isTCCommand(command Command) bool {
	if strings.TrimSpace(command.Path) == "" || len(command.Args) == 0 {
		return false
	}

	switch strings.TrimSpace(command.Args[0]) {
	case "qdisc", "class", "filter", "-j":
		return true
	default:
		return false
	}
}

func (p Planner) removeClassIDs(applied []limiter.AppliedState, handles Handles) ([]string, error) {
	if len(applied) == 0 {
		return []string{handles.ClassID}, nil
	}

	seen := make(map[string]struct{}, len(applied))
	ids := make([]string, 0, len(applied))
	for _, state := range applied {
		if state.Mode != limiter.DesiredModeLimit {
			continue
		}
		classID := strings.TrimSpace(state.Reference)
		if classID == "" {
			classID = handles.ClassID
		}
		if err := validateClassID(classID, handles.RootHandle); err != nil {
			return nil, err
		}
		if _, exists := seen[classID]; exists {
			continue
		}
		seen[classID] = struct{}{}
		ids = append(ids, classID)
	}

	return ids, nil
}

func (p Planner) removeAttachmentExecutions(plan Plan, applied []limiter.AppliedState) ([]DirectAttachmentExecution, error) {
	modes := possibleRemovalModes(plan.Action.Subject, applied)
	if len(modes) == 0 {
		return nil, nil
	}

	executions := make([]DirectAttachmentExecution, 0, len(modes))
	for _, mode := range modes {
		execution, err := BuildDirectAttachmentExecution(plan.Binding, plan.Scope, mode, attachmentClassID(mode, plan.Handles))
		if err != nil {
			return nil, err
		}
		if execution.Readiness != BindingReadinessReady {
			continue
		}
		executions = append(executions, execution)
	}

	return executions, nil
}

func possibleRemovalModes(subject limiter.Subject, applied []limiter.AppliedState) []limiter.DesiredMode {
	if subject.Kind == policy.TargetKindIP && !subject.All {
		return []limiter.DesiredMode{
			limiter.DesiredModeUnlimited,
			limiter.DesiredModeLimit,
		}
	}

	if len(applied) != 0 {
		seen := make(map[limiter.DesiredMode]struct{}, len(applied))
		modes := make([]limiter.DesiredMode, 0, len(applied))
		for _, state := range applied {
			if !state.Mode.Valid() {
				continue
			}
			if _, ok := seen[state.Mode]; ok {
				continue
			}
			seen[state.Mode] = struct{}{}
			modes = append(modes, state.Mode)
		}
		return modes
	}

	return []limiter.DesiredMode{limiter.DesiredModeLimit}
}

// AppendRootQDiscCleanup adds a conservative root-qdisc delete step to a remove plan.
func AppendRootQDiscCleanup(plan Plan) (Plan, error) {
	if err := plan.Validate(); err != nil {
		return Plan{}, err
	}
	if plan.Action.Kind != limiter.ActionRemove {
		return Plan{}, errors.New("root qdisc cleanup requires a remove plan")
	}

	plan.Steps = append(plan.Steps, Step{
		Name: "delete-root-qdisc",
		Command: Command{
			Path: tcCommandPath(plan),
			Args: []string{"qdisc", "del", "dev", plan.Scope.Device, "root"},
		},
	})
	if err := plan.Validate(); err != nil {
		return Plan{}, err
	}

	return plan, nil
}

func tcAppliedStates(applied []limiter.AppliedState) ([]limiter.AppliedState, error) {
	if len(applied) == 0 {
		return nil, nil
	}

	states := make([]limiter.AppliedState, 0, len(applied))
	for index, state := range applied {
		if strings.TrimSpace(state.Driver) != driverName {
			return nil, fmt.Errorf("applied state at index %d uses unsupported driver %q", index, state.Driver)
		}
		states = append(states, state)
	}

	return states, nil
}

func rateForDirection(limits policy.LimitPolicy, direction Direction) (string, error) {
	var rate *policy.RateLimit
	switch direction {
	case DirectionUpload:
		rate = limits.Upload
	case DirectionDownload:
		rate = limits.Download
	default:
		return "", fmt.Errorf("invalid scope direction %q", direction)
	}

	if rate == nil {
		return "", fmt.Errorf("no %s limit is defined for the desired state", direction)
	}

	return fmt.Sprintf("%dbps", rate.BytesPerSecond), nil
}

func deriveClassID(subject limiter.Subject, direction Direction, rootHandle string) string {
	return deriveDeterministicClassID(subjectKey(subject, direction), rootHandle)
}

func deriveDeterministicClassID(key string, rootHandle string) string {
	major := strings.TrimSuffix(rootHandle, ":")
	hash := fnv.New32a()
	_, _ = hash.Write([]byte(key))
	minor := 2 + (hash.Sum32() % 0xfffd)

	return fmt.Sprintf("%s:%x", major, minor)
}

func subjectKey(subject limiter.Subject, direction Direction) string {
	value := strings.TrimSpace(subject.Value)
	if subject.Kind == policy.TargetKindIP && subject.All {
		value = "all"
	} else if subject.Kind == policy.TargetKindIP {
		if normalized, err := ipaddr.Normalize(value); err == nil {
			value = normalized
		}
	}

	parts := []string{
		string(direction),
		string(subject.Kind),
		strings.ToLower(value),
		string(subject.Binding.Runtime.Source),
		strings.TrimSpace(subject.Binding.Runtime.Provider),
		strings.TrimSpace(subject.Binding.Runtime.Name),
		fmt.Sprintf("%d", subject.Binding.Runtime.HostPID),
		strings.TrimSpace(subject.Binding.Runtime.ContainerID),
	}

	return strings.Join(parts, "|")
}

func validateHandleMajor(handle string) error {
	handle = strings.TrimSpace(handle)
	if handle == "" {
		return errors.New("handle is required")
	}
	if !strings.HasSuffix(handle, ":") || strings.Count(handle, ":") != 1 {
		return fmt.Errorf("invalid major handle %q", handle)
	}

	major := strings.TrimSuffix(handle, ":")
	if major == "" {
		return fmt.Errorf("invalid major handle %q", handle)
	}

	for _, runeValue := range major {
		if !isHexRune(runeValue) {
			return fmt.Errorf("invalid major handle %q", handle)
		}
	}

	return nil
}

func validateClassID(classID string, rootHandle string) error {
	classID = strings.TrimSpace(classID)
	if classID == "" {
		return errors.New("class id is required")
	}

	parts := strings.Split(classID, ":")
	if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
		return fmt.Errorf("invalid class id %q", classID)
	}
	for _, part := range parts {
		for _, runeValue := range part {
			if !isHexRune(runeValue) {
				return fmt.Errorf("invalid class id %q", classID)
			}
		}
	}
	if parts[0] != strings.TrimSuffix(strings.TrimSpace(rootHandle), ":") {
		return fmt.Errorf("class id %q does not match root handle %q", classID, rootHandle)
	}

	return nil
}

func isHexRune(value rune) bool {
	switch {
	case value >= '0' && value <= '9':
		return true
	case value >= 'a' && value <= 'f':
		return true
	case value >= 'A' && value <= 'F':
		return true
	default:
		return false
	}
}

func validateDevice(device string) error {
	if strings.TrimSpace(device) == "" {
		return errors.New("device is required")
	}
	if strings.ContainsAny(device, " \t\r\n") {
		return fmt.Errorf("invalid device %q", device)
	}

	return nil
}

func (p Planner) directAttachmentApplySteps(plan Plan) []Step {
	steps := make([]Step, 0, len(plan.AttachmentExecution.Rules))
	for index, rule := range plan.AttachmentExecution.Rules {
		switch rule.Classifier {
		case DirectAttachmentClassifierMatchAll:
			steps = append(steps, p.step(
				fmt.Sprintf("upsert-direct-attachment-%d", index+1),
				"filter", "replace",
				"dev", plan.Scope.Device,
				"parent", plan.Handles.RootHandle,
				"pref", fmt.Sprintf("%d", rule.Preference),
				"matchall",
				"classid", rule.ClassID,
			))
		case DirectAttachmentClassifierU32:
			protocol := rule.protocolToken()
			matchFamily := rule.matchFamilyToken()
			prefixLength := rule.prefixLength()
			args := []string{
				"filter", "replace",
				"dev", plan.Scope.Device,
				"parent", plan.Handles.RootHandle,
				"protocol", protocol,
				"pref", fmt.Sprintf("%d", rule.Preference),
				"u32",
				"match", matchFamily, rule.MatchField.u32Token(), fmt.Sprintf("%s/%d", rule.Identity.Value, prefixLength),
			}
			if rule.Disposition == DirectAttachmentDispositionClassify {
				args = append(args, "flowid", rule.ClassID)
			} else {
				args = append(args, "action", "pass")
			}
			steps = append(steps, p.step(fmt.Sprintf("upsert-direct-attachment-%d", index+1), args...))
		}
	}

	return steps
}

func (p Planner) directAttachmentRemoveSteps(scope Scope, rootHandle string, execution DirectAttachmentExecution, startIndex int) []Step {
	steps := make([]Step, 0, len(execution.Rules))
	for index, rule := range execution.Rules {
		name := fmt.Sprintf("delete-direct-attachment-%d", startIndex+index)
		switch rule.Classifier {
		case DirectAttachmentClassifierMatchAll:
			steps = append(steps, p.step(
				name,
				"filter", "del",
				"dev", scope.Device,
				"parent", rootHandle,
				"pref", fmt.Sprintf("%d", rule.Preference),
				"matchall",
			))
		case DirectAttachmentClassifierU32:
			steps = append(steps, p.step(
				name,
				"filter", "del",
				"dev", scope.Device,
				"parent", rootHandle,
				"protocol", rule.protocolToken(),
				"pref", fmt.Sprintf("%d", rule.Preference),
				"u32",
			))
		}
	}

	return steps
}

func buildInspectSteps(binary string, device string) []Step {
	return []Step{
		{
			Name: "show-qdisc",
			Command: Command{
				Path: binary,
				Args: []string{"-j", "qdisc", "show", "dev", device},
			},
		},
		{
			Name: "show-class",
			Command: Command{
				Path: binary,
				Args: []string{"-j", "class", "show", "dev", device},
			},
		},
		{
			Name: "show-filter",
			Command: Command{
				Path: binary,
				Args: []string{"-j", "filter", "show", "dev", device},
			},
		},
	}
}
