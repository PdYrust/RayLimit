package tc

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/PdYrust/RayLimit/internal/limiter"
	"github.com/PdYrust/RayLimit/internal/policy"
	"github.com/PdYrust/RayLimit/internal/privilege"
)

func applyPlan(t *testing.T, kind policy.TargetKind, direction Direction, upload int64, download int64) Plan {
	t.Helper()

	desired := testDesiredState(t, kind, upload, download)
	action := limiter.Action{
		Kind:    limiter.ActionApply,
		Subject: desired.Subject,
		Desired: &desired,
	}
	plan, err := (Planner{}).Plan(action, Scope{Device: "eth0", Direction: direction})
	if err != nil {
		t.Fatalf("expected apply plan to succeed, got %v", err)
	}

	return plan
}

func stepNames(steps []Step) []string {
	names := make([]string, 0, len(steps))
	for _, step := range steps {
		names = append(names, step.Name)
	}

	return names
}

func containsStepNamed(steps []Step, name string) bool {
	for _, step := range steps {
		if step.Name == name {
			return true
		}
	}

	return false
}

// TestAppendIdempotentApplyPreservesRootForDownloadAfterUpload covers the
// headline bug: applying the download limit after the upload apply already
// created the managed root qdisc must not re-issue (and therefore not destroy)
// the root, so the upload class and filter survive.
func TestAppendIdempotentApplyPreservesRootForDownloadAfterUpload(t *testing.T) {
	plan := applyPlan(t, policy.TargetKindOutbound, DirectionDownload, 0, 4096)

	snapshot := Snapshot{
		Device: "eth0",
		QDiscs: []QDiscState{{Kind: "htb", Handle: plan.Handles.RootHandle, Parent: "root"}},
		Classes: []ClassState{{
			Kind:               "htb",
			ClassID:            "1:5",
			Parent:             plan.Handles.RootHandle,
			RateBytesPerSecond: 2048,
			CeilBytesPerSecond: 2048,
		}},
	}

	updated, err := AppendIdempotentApply(plan, snapshot)
	if err != nil {
		t.Fatalf("expected idempotent apply rewrite to succeed, got %v", err)
	}

	if containsStepNamed(updated.Steps, stepEnsureRootQDisc) {
		t.Fatalf("expected the managed root qdisc step to be skipped, got %#v", stepNames(updated.Steps))
	}
	if containsStepNamed(updated.Steps, stepReplaceForeignRootQDisc) {
		t.Fatalf("expected no destructive root replacement, got %#v", stepNames(updated.Steps))
	}
	if !containsStepNamed(updated.Steps, stepUpsertClass) {
		t.Fatalf("expected the download class to still be applied, got %#v", stepNames(updated.Steps))
	}
	for _, step := range updated.Steps {
		args := strings.Join(step.Command.Args, " ")
		if strings.Contains(args, "qdisc del") || strings.Contains(args, "qdisc replace") {
			t.Fatalf("expected the existing upload tree to be preserved, got destructive step %q", args)
		}
	}
}

func TestAppendIdempotentApplyReplacesForeignRootQDisc(t *testing.T) {
	plan := applyPlan(t, policy.TargetKindOutbound, DirectionUpload, 2048, 0)

	snapshot := Snapshot{
		Device: "eth0",
		QDiscs: []QDiscState{{Kind: "pfifo_fast", Handle: "8001:", Parent: "root"}},
	}

	updated, err := AppendIdempotentApply(plan, snapshot)
	if err != nil {
		t.Fatalf("expected idempotent apply rewrite to succeed, got %v", err)
	}

	if !containsStepNamed(updated.Steps, stepReplaceForeignRootQDisc) {
		t.Fatalf("expected a foreign root delete step, got %#v", stepNames(updated.Steps))
	}
	if !containsStepNamed(updated.Steps, stepEnsureRootQDisc) {
		t.Fatalf("expected the managed root add step to remain, got %#v", stepNames(updated.Steps))
	}

	var delIndex, addIndex int
	for index, step := range updated.Steps {
		switch step.Name {
		case stepReplaceForeignRootQDisc:
			delIndex = index
			if got := strings.Join(step.Command.Args, " "); got != "qdisc del dev eth0 root" {
				t.Fatalf("unexpected foreign root delete args %q", got)
			}
		case stepEnsureRootQDisc:
			addIndex = index
			if step.Command.Args[1] != "add" {
				t.Fatalf("expected managed root to be added, got %#v", step.Command.Args)
			}
		}
	}
	if delIndex > addIndex {
		t.Fatalf("expected the foreign root delete to precede the managed add, got %#v", stepNames(updated.Steps))
	}
}

func TestAppendIdempotentApplyKeepsFromScratchPlanForEmptyDevice(t *testing.T) {
	plan := applyPlan(t, policy.TargetKindOutbound, DirectionUpload, 2048, 0)
	originalNames := stepNames(plan.Steps)

	updated, err := AppendIdempotentApply(plan, Snapshot{Device: "eth0"})
	if err != nil {
		t.Fatalf("expected idempotent apply rewrite to succeed, got %v", err)
	}

	if got := stepNames(updated.Steps); strings.Join(got, ",") != strings.Join(originalNames, ",") {
		t.Fatalf("expected the from-scratch plan to be preserved on an empty device, got %#v", got)
	}
	if !containsStepNamed(updated.Steps, stepEnsureRootQDisc) {
		t.Fatalf("expected the root qdisc add to remain for an empty device, got %#v", stepNames(updated.Steps))
	}
}

func TestAppendIdempotentApplySkipsMatchingClass(t *testing.T) {
	plan := applyPlan(t, policy.TargetKindOutbound, DirectionUpload, 2048, 0)

	snapshot := Snapshot{
		Device: "eth0",
		QDiscs: []QDiscState{{Kind: "htb", Handle: plan.Handles.RootHandle, Parent: "root"}},
		Classes: []ClassState{{
			Kind:               "htb",
			ClassID:            plan.Handles.ClassID,
			Parent:             plan.Handles.RootHandle,
			RateBytesPerSecond: 2048,
			CeilBytesPerSecond: 2048,
		}},
	}

	updated, err := AppendIdempotentApply(plan, snapshot)
	if err != nil {
		t.Fatalf("expected idempotent apply rewrite to succeed, got %v", err)
	}

	if len(updated.Steps) != 0 {
		t.Fatalf("expected a fully satisfied plan to drop all steps, got %#v", stepNames(updated.Steps))
	}
	if !updated.NoOp {
		t.Fatal("expected a fully satisfied plan to be marked no-op")
	}
}

func TestAppendIdempotentApplyZeroSnapshotReturnsUnchanged(t *testing.T) {
	plan := applyPlan(t, policy.TargetKindOutbound, DirectionUpload, 2048, 0)
	originalNames := stepNames(plan.Steps)

	updated, err := AppendIdempotentApply(plan, Snapshot{})
	if err != nil {
		t.Fatalf("expected idempotent apply rewrite to succeed, got %v", err)
	}

	if got := stepNames(updated.Steps); strings.Join(got, ",") != strings.Join(originalNames, ",") {
		t.Fatalf("expected a zero snapshot to leave the plan unchanged, got %#v", got)
	}
}

func TestAppendIdempotentApplyRejectsNonApplyPlan(t *testing.T) {
	plan := testPlan(t) // inspect plan

	_, err := AppendIdempotentApply(plan, Snapshot{Device: "eth0"})
	if err == nil {
		t.Fatal("expected idempotent apply rewrite to reject a non-apply plan")
	}
}

// scriptedRunner answers commands based on their argument signature so executor
// recovery paths that re-inspect the device can be exercised deterministically.
type scriptedRunner struct {
	commands []Command
	handler  func(Command) (Result, error)
}

func (r *scriptedRunner) Run(_ context.Context, command Command) (Result, error) {
	r.commands = append(r.commands, command)
	result, err := r.handler(command)
	result.Command = command

	return result, err
}

func (r *scriptedRunner) issued(predicate func(Command) bool) bool {
	for _, command := range r.commands {
		if predicate(command) {
			return true
		}
	}

	return false
}

func rootExecutor(runner Runner) Executor {
	return Executor{
		Runner: runner,
		privilegeStatus: func() privilege.Status {
			return privilege.Status{EUID: 0, IsRoot: true}
		},
	}
}

func commandHasArgs(command Command, args ...string) bool {
	joined := strings.Join(command.Args, " ")

	return strings.Contains(joined, strings.Join(args, " "))
}

// TestExecutorRecoversFromBusyRootQDisc covers the execution-time backstop: when
// the root qdisc add fails because the managed tree is busy, re-inspection
// confirms the managed htb root already exists and the step is treated as a
// success without tearing the tree down.
func TestExecutorRecoversFromBusyRootQDisc(t *testing.T) {
	plan := applyPlan(t, policy.TargetKindOutbound, DirectionDownload, 0, 4096)

	runner := &scriptedRunner{}
	runner.handler = func(command Command) (Result, error) {
		switch {
		case commandHasArgs(command, "qdisc", "add", "dev", "eth0", "root"):
			return Result{Stderr: "RTNETLINK answers: Device or resource busy", ExitCode: 2}, errors.New("exit status 2")
		case commandHasArgs(command, "-j", "qdisc", "show", "dev", "eth0"):
			return Result{Stdout: "qdisc htb 1: root refcnt 2 r2q 10 default 0\n"}, nil
		case commandHasArgs(command, "-j", "class", "show", "dev", "eth0"):
			return Result{Stdout: ""}, nil
		case commandHasArgs(command, "-j", "filter", "show", "dev", "eth0"):
			return Result{Stdout: ""}, nil
		default:
			return Result{}, nil
		}
	}

	results, err := rootExecutor(runner).Execute(context.Background(), plan)
	if err != nil {
		t.Fatalf("expected busy root qdisc to be recovered, got %v", err)
	}

	if results[0].Step != stepEnsureRootQDisc || !results[0].Skipped {
		t.Fatalf("expected the root qdisc step to be recovered as skipped, got %#v", results[0])
	}
	if runner.issued(func(command Command) bool { return commandHasArgs(command, "qdisc", "del") }) {
		t.Fatal("expected recovery to avoid deleting the existing managed tree")
	}
	if runner.issued(func(command Command) bool { return commandHasArgs(command, "qdisc", "replace") }) {
		t.Fatal("expected recovery to avoid replacing the existing managed root")
	}
}

func TestExecutorTakesOverForeignRootQDisc(t *testing.T) {
	plan := applyPlan(t, policy.TargetKindOutbound, DirectionUpload, 2048, 0)

	runner := &scriptedRunner{}
	runner.handler = func(command Command) (Result, error) {
		switch {
		case commandHasArgs(command, "qdisc", "add", "dev", "eth0", "root"):
			return Result{Stderr: "RTNETLINK answers: File exists", ExitCode: 2}, errors.New("exit status 2")
		case commandHasArgs(command, "-j", "qdisc", "show", "dev", "eth0"):
			return Result{Stdout: "qdisc pfifo_fast 8001: root refcnt 2 bands 3\n"}, nil
		case commandHasArgs(command, "-j", "class", "show", "dev", "eth0"):
			return Result{Stdout: ""}, nil
		case commandHasArgs(command, "-j", "filter", "show", "dev", "eth0"):
			return Result{Stdout: ""}, nil
		default:
			return Result{}, nil
		}
	}

	results, err := rootExecutor(runner).Execute(context.Background(), plan)
	if err != nil {
		t.Fatalf("expected foreign root takeover to succeed, got %v", err)
	}

	if !runner.issued(func(command Command) bool {
		return commandHasArgs(command, "qdisc", "replace", "dev", "eth0", "root", "handle", plan.Handles.RootHandle, "htb")
	}) {
		t.Fatalf("expected recovery to replace the foreign root qdisc, got %#v", runner.commands)
	}
	if results[0].Step != stepEnsureRootQDisc {
		t.Fatalf("expected the recovered result to retain the root step name, got %#v", results[0])
	}
}

func TestExecutorSurfacesUnrecoverableExistingObject(t *testing.T) {
	plan := applyPlan(t, policy.TargetKindOutbound, DirectionUpload, 2048, 0)

	runner := &scriptedRunner{}
	runner.handler = func(command Command) (Result, error) {
		switch {
		case commandHasArgs(command, "qdisc", "add", "dev", "eth0", "root"):
			return Result{Stderr: "RTNETLINK answers: File exists", ExitCode: 2}, errors.New("exit status 2")
		default:
			// Re-inspection reports no qdisc at all, so the existing-object claim
			// cannot be verified and the original error must surface.
			return Result{Stdout: ""}, nil
		}
	}

	_, err := rootExecutor(runner).Execute(context.Background(), plan)
	if err == nil {
		t.Fatal("expected an unverifiable existing-object error to surface")
	}
}
