package tc

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os/exec"
	"strings"
	"time"

	"github.com/PdYrust/RayLimit/internal/privilege"
)

// Result captures the outcome of a single tc command.
type Result struct {
	Step     string  `json:"step,omitempty"`
	Command  Command `json:"command"`
	Stdout   string  `json:"stdout,omitempty"`
	Stderr   string  `json:"stderr,omitempty"`
	ExitCode int     `json:"exit_code,omitempty"`
	Skipped  bool    `json:"skipped,omitempty"`
	Error    string  `json:"error,omitempty"`
}

// Runner executes a validated tc command.
type Runner interface {
	Run(context.Context, Command) (Result, error)
}

// PermissionError reports that tc execution was attempted without sufficient
// privilege. tc write operations require either root or the CAP_NET_ADMIN
// capability, so the message explains both remediation paths.
type PermissionError struct {
	Status privilege.Status
}

func (e PermissionError) Error() string {
	return fmt.Sprintf(
		"tc execution requires elevated privilege (effective uid %d): run RayLimit as root, or grant the CAP_NET_ADMIN capability (for example systemd AmbientCapabilities=CAP_NET_ADMIN)",
		e.Status.EUID,
	)
}

// AlreadyExistsError reports that a tc object creation failed because the object
// already exists, or because the subtree it targets is busy. The executor
// recovers from this for idempotent apply steps by re-inspecting the device and
// treating a matching managed object as success rather than tearing the tree
// down. It is detectable with errors.As.
type AlreadyExistsError struct {
	Command Command
	Stderr  string
}

func (e AlreadyExistsError) Error() string {
	detail := strings.TrimSpace(e.Stderr)
	if detail == "" {
		detail = "object already exists"
	}

	return fmt.Sprintf("tc command %s reported an existing object: %s", e.Command.Path, detail)
}

// defaultStepTimeout bounds how long a single tc/nft command may run before its
// context is cancelled, so a hung backend cannot stall the CLI.
const defaultStepTimeout = 10 * time.Second

// privilegeProbeTimeout bounds the read-only privilege probe so a hung tc cannot
// block the CLI; on timeout the executor falls back to the euid-0 decision.
const privilegeProbeTimeout = 2 * time.Second

// Executor runs or skips a tc plan depending on dry-run mode.
type Executor struct {
	Runner Runner
	DryRun bool

	// StepTimeout bounds each individual command's execution. When zero, the
	// executor uses defaultStepTimeout. It applies only to real execution;
	// dry-run never execs and therefore never times out.
	StepTimeout time.Duration

	// SkipPrivilegeCheck bypasses both the euid-0 fast-path and the privilege
	// probe. It is an operator escape hatch for environments where capability
	// access cannot be detected by the probe; the real tc command still fails
	// with EPERM if privilege is genuinely missing.
	SkipPrivilegeCheck bool

	// PrivilegeProbe, when set, reports whether the process can perform
	// privileged tc operations (root or CAP_NET_ADMIN) by attempting a
	// read-only probe. It returns nil when privilege is sufficient. It is only
	// consulted for non-root processes and should cache its result.
	PrivilegeProbe func(ctx context.Context) error

	privilegeStatus func() privilege.Status
}

// NewExecutor constructs a tc executor with optional runner injection and privilege override.
func NewExecutor(runner Runner, dryRun bool, privilegeStatus func() privilege.Status) Executor {
	return Executor{
		Runner:          runner,
		DryRun:          dryRun,
		privilegeStatus: privilegeStatus,
	}
}

// Execute validates a plan and either runs each step or returns skipped dry-run results.
func (e Executor) Execute(ctx context.Context, plan Plan) ([]Result, error) {
	if err := plan.Validate(); err != nil {
		return nil, err
	}

	return e.executeSteps(ctx, plan.Steps)
}

func (e Executor) executeSteps(ctx context.Context, steps []Step) ([]Result, error) {
	results := make([]Result, 0, len(steps))
	if e.DryRun {
		for _, step := range steps {
			results = append(results, Result{
				Step:    step.Name,
				Command: step.Command,
				Skipped: true,
			})
		}
		return results, nil
	}

	if err := e.validatePrivilege(ctx); err != nil {
		return nil, err
	}

	runner := e.runner()
	for _, step := range steps {
		result, err := e.runWithTimeout(ctx, runner, step.Command)
		result.Step = step.Name
		if err != nil {
			recovered, ok, recErr := e.recoverExistingObject(ctx, runner, step, result, err)
			recovered.Step = step.Name
			if ok {
				results = append(results, recovered)
				continue
			}
			if recovered.Error == "" {
				recovered.Error = recErr.Error()
			}
			results = append(results, recovered)
			return results, recErr
		}
		results = append(results, result)
	}

	return results, nil
}

// stepTimeout returns the configured per-step execution timeout, or the default
// when unset.
func (e Executor) stepTimeout() time.Duration {
	if e.StepTimeout > 0 {
		return e.StepTimeout
	}

	return defaultStepTimeout
}

// runWithTimeout runs one command under a fresh per-step timeout so a single
// hung command cannot stall the whole plan. Each call gets an independent
// deadline, so one step's timeout does not consume another step's budget.
func (e Executor) runWithTimeout(ctx context.Context, runner Runner, command Command) (Result, error) {
	stepCtx, cancel := context.WithTimeout(ctx, e.stepTimeout())
	defer cancel()

	return runner.Run(stepCtx, command)
}

// recoverExistingObject attempts to treat an idempotent apply step that failed
// with an already-exists or busy error as a success. It re-inspects the device
// and only reports success when the expected managed object is actually present
// (strict verification). A foreign root qdisc occupying the handle is taken over
// with an explicit replace rather than left in place.
func (e Executor) recoverExistingObject(ctx context.Context, runner Runner, step Step, result Result, runErr error) (Result, bool, error) {
	if !isIdempotentApplyStep(step.Name) {
		return result, false, runErr
	}
	if !commandIndicatesObjectPresent(result, runErr) {
		return result, false, runErr
	}

	device, ok := commandArgAfter(step.Command, "dev")
	if !ok {
		return result, false, runErr
	}
	binary := strings.TrimSpace(step.Command.Path)
	if binary == "" {
		binary = defaultBinary
	}

	snapshot, err := e.reinspectDevice(ctx, runner, binary, device)
	if err != nil {
		// Cannot verify the existing object; surface the original error.
		return result, false, runErr
	}

	switch {
	case step.Name == stepEnsureRootQDisc:
		handle, ok := commandArgAfter(step.Command, "handle")
		if !ok {
			return result, false, runErr
		}
		if snapshotHasManagedRootQDisc(snapshot, handle) {
			// The managed htb root already exists; the add was redundant and the
			// existing subtree (sibling classes and filters) is preserved.
			result.Skipped = true
			result.Error = ""
			return result, true, nil
		}
		if _, foreign := snapshotForeignRootQDisc(snapshot, handle); foreign {
			replaceResult, replaceErr := e.runWithTimeout(ctx, runner, Command{
				Path: binary,
				Args: []string{"qdisc", "replace", "dev", device, "root", "handle", handle, "htb"},
			})
			replaceResult.Step = step.Name
			if replaceErr != nil {
				return result, false, runErr
			}
			return replaceResult, true, nil
		}
		return result, false, runErr
	case step.Name == stepUpsertClass:
		classID, ok := commandArgAfter(step.Command, "classid")
		if ok {
			if _, exists := snapshot.Class(classID); exists {
				result.Skipped = true
				result.Error = ""
				return result, true, nil
			}
		}
		return result, false, runErr
	case strings.HasPrefix(step.Name, stepUpsertDirectAttachPrefix):
		// Direct-attachment filters are applied with "replace", so any observed
		// filter on the device is treated as the present object.
		if len(snapshot.Filters) > 0 {
			result.Skipped = true
			result.Error = ""
			return result, true, nil
		}
		return result, false, runErr
	default:
		return result, false, runErr
	}
}

// reinspectDevice reads the current tc state for a device using the provided
// runner and tc binary, bounding each read with the executor's per-step timeout.
func (e Executor) reinspectDevice(ctx context.Context, runner Runner, binary string, device string) (Snapshot, error) {
	steps := buildInspectSteps(binary, device)
	results := make([]Result, 0, len(steps))
	for _, step := range steps {
		result, err := e.runWithTimeout(ctx, runner, step.Command)
		result.Step = step.Name
		if err != nil {
			return Snapshot{}, err
		}
		results = append(results, result)
	}

	return ParseSnapshot(device, results)
}

func isIdempotentApplyStep(name string) bool {
	name = strings.TrimSpace(name)

	return name == stepEnsureRootQDisc ||
		name == stepUpsertClass ||
		strings.HasPrefix(name, stepUpsertDirectAttachPrefix)
}

// commandIndicatesObjectPresent reports whether a failed tc command indicates
// the targeted object already exists or its subtree is busy.
func commandIndicatesObjectPresent(result Result, err error) bool {
	var existsErr AlreadyExistsError
	if errors.As(err, &existsErr) {
		return true
	}

	stderr := strings.ToLower(result.Stderr)
	for _, marker := range []string{
		"file exists",
		"exclusivity flag on",
		"device or resource busy",
	} {
		if strings.Contains(stderr, marker) {
			return true
		}
	}

	return false
}

// commandArgAfter returns the argument value immediately following the given
// key in a command's argument list.
func commandArgAfter(command Command, key string) (string, bool) {
	for index := 0; index+1 < len(command.Args); index++ {
		if command.Args[index] == key {
			return strings.TrimSpace(command.Args[index+1]), true
		}
	}

	return "", false
}

// validatePrivilege gates real tc execution. Precedence:
//  1. SkipPrivilegeCheck — operator escape hatch, bypasses all checks.
//  2. euid 0 — root fast-path, always sufficient, never probes.
//  3. PrivilegeProbe — a read-only probe that detects CAP_NET_ADMIN access the
//     euid check misses. Success allows execution; any failure (EPERM, hang,
//     or missing tc) falls back to the euid decision, which has already failed
//     here, yielding a PermissionError that explains both remediation paths.
func (e Executor) validatePrivilege(ctx context.Context) error {
	if e.SkipPrivilegeCheck {
		return nil
	}

	status := e.currentPrivilege()
	if status.IsRoot {
		return nil
	}

	if e.PrivilegeProbe != nil {
		if err := e.PrivilegeProbe(ctx); err == nil {
			return nil
		}
	}

	return PermissionError{Status: status}
}

func (e Executor) currentPrivilege() privilege.Status {
	if e.privilegeStatus != nil {
		return e.privilegeStatus()
	}

	return privilege.Current()
}

func (e Executor) runner() Runner {
	if e.Runner != nil {
		return e.Runner
	}

	return SystemRunner{}
}

// ProbePrivilege runs a read-only `tc qdisc show dev lo` to determine whether
// the current process can reach tc/netlink (root or CAP_NET_ADMIN). It is
// read-only and side-effect-free, and is bounded by privilegeProbeTimeout so a
// hung tc cannot block the caller. It returns nil when the probe succeeds and a
// wrapped error otherwise (the caller treats any error as "not sufficient" and
// falls back to the euid-0 decision).
func ProbePrivilege(ctx context.Context, runner Runner, binary string) error {
	if runner == nil {
		runner = SystemRunner{}
	}
	if strings.TrimSpace(binary) == "" {
		binary = defaultBinary
	}

	probeCtx, cancel := context.WithTimeout(ctx, privilegeProbeTimeout)
	defer cancel()

	result, err := runner.Run(probeCtx, Command{
		Path: binary,
		Args: []string{"qdisc", "show", "dev", "lo"},
	})
	if err != nil {
		return fmt.Errorf("tc privilege probe failed: %w", err)
	}
	if strings.TrimSpace(result.Error) != "" {
		return fmt.Errorf("tc privilege probe reported an error: %s", strings.TrimSpace(result.Error))
	}

	return nil
}

// SystemRunner executes tc commands via os/exec.
type SystemRunner struct{}

// Run executes one validated tc command.
func (SystemRunner) Run(ctx context.Context, command Command) (Result, error) {
	if err := command.Validate(); err != nil {
		return Result{}, err
	}

	cmd := exec.CommandContext(ctx, command.Path, command.Args...)
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	err := cmd.Run()
	result := Result{
		Command: command,
		Stdout:  stdout.String(),
		Stderr:  stderr.String(),
	}

	if err == nil {
		return result, nil
	}

	var exitError *exec.ExitError
	if errors.As(err, &exitError) {
		result.ExitCode = exitError.ExitCode()
		result.Error = err.Error()
		if commandIndicatesObjectPresent(result, nil) {
			existsErr := AlreadyExistsError{Command: command, Stderr: result.Stderr}
			result.Error = existsErr.Error()
			return result, existsErr
		}
		return result, err
	}

	runErr := fmt.Errorf("run %s failed: %w", command.Path, err)
	result.Error = runErr.Error()

	return result, runErr
}
