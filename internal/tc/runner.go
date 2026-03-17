package tc

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os/exec"

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

// PermissionError reports that tc execution was attempted without sufficient privilege.
type PermissionError struct {
	Status privilege.Status
}

func (e PermissionError) Error() string {
	return fmt.Sprintf("tc execution requires root privileges (effective uid %d)", e.Status.EUID)
}

// Executor runs or skips a tc plan depending on dry-run mode.
type Executor struct {
	Runner Runner
	DryRun bool

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

// ExecuteUUIDAggregate validates a shared UUID aggregate plan and either runs
// each step or returns skipped dry-run results.
func (e Executor) ExecuteUUIDAggregate(ctx context.Context, plan UUIDAggregatePlan) ([]Result, error) {
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

	if err := e.validatePrivilege(); err != nil {
		return nil, err
	}

	runner := e.runner()
	for _, step := range steps {
		result, err := runner.Run(ctx, step.Command)
		result.Step = step.Name
		if err != nil {
			if result.Error == "" {
				result.Error = err.Error()
			}
			results = append(results, result)
			return results, err
		}
		results = append(results, result)
	}

	return results, nil
}

func (e Executor) validatePrivilege() error {
	status := e.currentPrivilege()
	if status.IsRoot {
		return nil
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
		return result, err
	}

	runErr := fmt.Errorf("run %s failed: %w", command.Path, err)
	result.Error = runErr.Error()

	return result, runErr
}
