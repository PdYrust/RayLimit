package tc

import (
	"context"
	"errors"
	"testing"

	"github.com/PdYrust/RayLimit/internal/limiter"
	"github.com/PdYrust/RayLimit/internal/policy"
	"github.com/PdYrust/RayLimit/internal/privilege"
)

type fakeRunner struct {
	commands []Command
	result   Result
	err      error
}

func (r *fakeRunner) Run(_ context.Context, command Command) (Result, error) {
	r.commands = append(r.commands, command)

	result := r.result
	result.Command = command

	return result, r.err
}

func testPlan(t *testing.T) Plan {
	t.Helper()

	desired := testDesiredState(t, policy.TargetKindConnection, 2048, 0)
	action := limiter.Action{
		Kind:    limiter.ActionInspect,
		Subject: desired.Subject,
	}

	plan, err := (Planner{}).Plan(action, Scope{
		Device:    "eth0",
		Direction: DirectionUpload,
	})
	if err != nil {
		t.Fatalf("expected inspect plan to succeed, got %v", err)
	}

	return plan
}

func TestExecutorExecuteDryRunSkipsRunner(t *testing.T) {
	plan := testPlan(t)
	runner := &fakeRunner{}

	results, err := (Executor{
		Runner: runner,
		DryRun: true,
		privilegeStatus: func() privilege.Status {
			return privilege.Status{EUID: 1000}
		},
	}).Execute(context.Background(), plan)
	if err != nil {
		t.Fatalf("expected dry-run execution to succeed, got %v", err)
	}

	if len(runner.commands) != 0 {
		t.Fatalf("expected dry-run execution to avoid runner calls, got %#v", runner.commands)
	}
	if len(results) != len(plan.Steps) {
		t.Fatalf("expected one result per planned step, got %#v", results)
	}
	for _, result := range results {
		if !result.Skipped {
			t.Fatalf("expected dry-run results to be marked skipped, got %#v", results)
		}
	}
}

func TestExecutorExecuteUsesRunnerSequentially(t *testing.T) {
	plan := testPlan(t)
	runner := &fakeRunner{}

	results, err := (Executor{
		Runner: runner,
		privilegeStatus: func() privilege.Status {
			return privilege.Status{EUID: 0, IsRoot: true}
		},
	}).Execute(context.Background(), plan)
	if err != nil {
		t.Fatalf("expected execution to succeed, got %v", err)
	}

	if len(runner.commands) != len(plan.Steps) {
		t.Fatalf("expected runner to receive every step, got %#v", runner.commands)
	}
	if len(results) != len(plan.Steps) {
		t.Fatalf("expected one result per executed step, got %#v", results)
	}
	if results[0].Step != plan.Steps[0].Name || results[len(results)-1].Step != plan.Steps[len(plan.Steps)-1].Name {
		t.Fatalf("expected execution results to preserve step names, got %#v", results)
	}
}

func TestExecutorExecuteRejectsNonRootExecution(t *testing.T) {
	plan := testPlan(t)
	runner := &fakeRunner{}

	_, err := (Executor{
		Runner: runner,
		privilegeStatus: func() privilege.Status {
			return privilege.Status{EUID: 1000}
		},
	}).Execute(context.Background(), plan)
	if err == nil {
		t.Fatal("expected non-root execution to fail")
	}

	var permissionError PermissionError
	if !errors.As(err, &permissionError) {
		t.Fatalf("expected permission error, got %v", err)
	}
	if len(runner.commands) != 0 {
		t.Fatalf("expected privilege failure to avoid runner calls, got %#v", runner.commands)
	}
}

func TestExecutorExecuteReportsRunnerFailure(t *testing.T) {
	plan := testPlan(t)
	runner := &fakeRunner{
		result: Result{
			Stdout:   "partial output",
			Stderr:   "permission denied",
			ExitCode: 1,
		},
		err: errors.New("command failed"),
	}

	results, err := (Executor{
		Runner: runner,
		privilegeStatus: func() privilege.Status {
			return privilege.Status{EUID: 0, IsRoot: true}
		},
	}).Execute(context.Background(), plan)
	if err == nil {
		t.Fatal("expected runner failure to be returned")
	}

	if len(results) != 1 {
		t.Fatalf("expected execution to stop at the first failing step, got %#v", results)
	}
	if results[0].Error != "command failed" {
		t.Fatalf("expected failing result to include the error string, got %#v", results[0])
	}
	if results[0].Step != plan.Steps[0].Name {
		t.Fatalf("expected failing result to keep the step name, got %#v", results[0])
	}
}

func TestExecutorExecuteRejectsInvalidPlan(t *testing.T) {
	_, err := (Executor{}).Execute(context.Background(), Plan{})
	if err == nil {
		t.Fatal("expected invalid plan to fail execution")
	}
}
