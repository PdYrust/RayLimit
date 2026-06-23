package tc

import (
	"context"
	"strings"
	"testing"

	"github.com/PdYrust/RayLimit/internal/limiter"
	"github.com/PdYrust/RayLimit/internal/policy"
)

// classTrackingRunner records the tc class identifiers that an executed plan
// creates so the final managed state can be asserted. It is seeded with any
// classes that already exist before execution.
type classTrackingRunner struct {
	classes  map[string]bool
	commands []Command
}

func newClassTrackingRunner(existing ...string) *classTrackingRunner {
	runner := &classTrackingRunner{classes: make(map[string]bool)}
	for _, id := range existing {
		runner.classes[id] = true
	}
	return runner
}

func (r *classTrackingRunner) Run(_ context.Context, command Command) (Result, error) {
	r.commands = append(r.commands, command)
	joined := strings.Join(command.Args, " ")
	if strings.Contains(joined, "class replace") {
		if id, ok := commandArgAfter(command, "classid"); ok {
			r.classes[id] = true
		}
	}
	return Result{Command: command}, nil
}

func (r *classTrackingRunner) issued(predicate func(Command) bool) bool {
	for _, command := range r.commands {
		if predicate(command) {
			return true
		}
	}
	return false
}

// Scenario 4: applying the upload limit then the download limit on the same
// device must leave both classes in place. The second (download) apply is
// idempotent on the managed root qdisc and only adds the download class; the
// existing upload class is preserved with no destructive command.
func TestUploadThenDownloadApplyKeepsBothClasses(t *testing.T) {
	uploadPlan := applyPlan(t, policy.TargetKindOutbound, DirectionUpload, 2048, 0)
	firstApply, err := AppendIdempotentApply(uploadPlan, Snapshot{Device: "eth0"})
	if err != nil {
		t.Fatalf("expected first (upload) idempotent apply to succeed, got %v", err)
	}
	if !containsStepNamed(firstApply.Steps, stepEnsureRootQDisc) || !containsStepNamed(firstApply.Steps, stepUpsertClass) {
		t.Fatalf("expected the from-scratch upload apply to create the root and class, got %#v", stepNames(firstApply.Steps))
	}
	uploadClass := uploadPlan.Handles.ClassID

	// After the upload apply the device carries the managed root and the upload
	// class. The download apply observes that state.
	afterUpload := Snapshot{
		Device:  "eth0",
		QDiscs:  []QDiscState{{Kind: "htb", Handle: uploadPlan.Handles.RootHandle, Parent: "root"}},
		Classes: []ClassState{{Kind: "htb", ClassID: uploadClass, Parent: uploadPlan.Handles.RootHandle, RateBytesPerSecond: 2048, CeilBytesPerSecond: 2048}},
	}

	downloadPlan := applyPlan(t, policy.TargetKindOutbound, DirectionDownload, 0, 4096)
	downloadClass := downloadPlan.Handles.ClassID
	if uploadClass == downloadClass {
		t.Fatalf("expected distinct upload and download class ids, both were %q", uploadClass)
	}

	secondApply, err := AppendIdempotentApply(downloadPlan, afterUpload)
	if err != nil {
		t.Fatalf("expected second (download) idempotent apply to succeed, got %v", err)
	}
	if containsStepNamed(secondApply.Steps, stepEnsureRootQDisc) {
		t.Fatalf("expected the download apply to skip the existing managed root, got %#v", stepNames(secondApply.Steps))
	}
	if !containsStepNamed(secondApply.Steps, stepUpsertClass) {
		t.Fatalf("expected the download apply to add the download class, got %#v", stepNames(secondApply.Steps))
	}

	runner := newClassTrackingRunner(uploadClass)
	if _, err := rootExecutor(runner).Execute(context.Background(), secondApply); err != nil {
		t.Fatalf("expected the download apply to execute, got %v", err)
	}

	if runner.issued(func(c Command) bool {
		joined := strings.Join(c.Args, " ")
		return strings.Contains(joined, "qdisc del") || strings.Contains(joined, "qdisc replace") || strings.Contains(joined, "class del")
	}) {
		t.Fatalf("expected no destructive command during the download apply, got %#v", runner.commands)
	}
	if !runner.classes[uploadClass] || !runner.classes[downloadClass] {
		t.Fatalf("expected both upload (%q) and download (%q) classes to survive, got %#v", uploadClass, downloadClass, runner.classes)
	}
}

// Scenario 5: when `tc -j` is unsupported the inspector parses the plain-text
// output into a valid Snapshot. That snapshot drives an idempotent apply
// (reconcile), which the executor then runs.
func TestPlainTextInspectDrivesIdempotentApplyAndExecution(t *testing.T) {
	inspectRunner := &inspectRunner{results: []Result{
		{Stdout: "qdisc htb 1: root refcnt 2 r2q 10 default 0\n"}, // plain-text qdisc
		{Stdout: ""}, // no classes yet
		{Stdout: ""}, // no filters yet
	}}

	snapshot, _, err := (Inspector{Runner: inspectRunner}).Inspect(context.Background(), InspectRequest{Device: "eth0"})
	if err != nil {
		t.Fatalf("expected plain-text inspect to succeed, got %v", err)
	}
	if len(snapshot.QDiscs) != 1 || snapshot.QDiscs[0].Kind != "htb" || snapshot.QDiscs[0].Handle != "1:" {
		t.Fatalf("expected the managed htb root to be parsed from plain text, got %#v", snapshot.QDiscs)
	}

	plan := applyPlan(t, policy.TargetKindOutbound, DirectionUpload, 2048, 0)
	reconciled, err := AppendIdempotentApply(plan, snapshot)
	if err != nil {
		t.Fatalf("expected idempotent apply against the plain-text snapshot to succeed, got %v", err)
	}
	if containsStepNamed(reconciled.Steps, stepEnsureRootQDisc) {
		t.Fatalf("expected the plain-text-observed root to be reused, got %#v", stepNames(reconciled.Steps))
	}
	if !containsStepNamed(reconciled.Steps, stepUpsertClass) {
		t.Fatalf("expected the class to still be applied, got %#v", stepNames(reconciled.Steps))
	}

	runner := &scriptedRunner{handler: func(Command) (Result, error) { return Result{}, nil }}
	if _, err := rootExecutor(runner).Execute(context.Background(), reconciled); err != nil {
		t.Fatalf("expected execution of the reconciled plan to succeed, got %v", err)
	}
	if !runner.issued(func(c Command) bool { return commandHasArgs(c, "class", "replace", "dev", "eth0") }) {
		t.Fatalf("expected the class replace command to run, got %#v", runner.commands)
	}
	if runner.issued(func(c Command) bool { return commandHasArgs(c, "qdisc", "add", "dev", "eth0", "root") }) {
		t.Fatalf("expected no root qdisc add given the observed managed root, got %#v", runner.commands)
	}
}

// Scenario 6: when `nft -j` is unsupported the nftables inspector parses the
// plain-text ruleset into a valid snapshot. A mark-attachment apply built
// against that snapshot adds the missing managed objects and executes
// successfully.
func TestPlainTextNftablesInspectDrivesMarkAttachmentApply(t *testing.T) {
	// A plain-text ruleset with an unrelated table proves the parser runs on
	// real content; the managed "raylimit" table is absent, so apply must add it.
	nftRuleset := `table inet filter {
	chain input {
		type filter hook input priority 0; policy accept;
	}
}`
	nftSnapshot, _, err := (NftablesInspector{Runner: &inspectRunner{results: []Result{{Stdout: nftRuleset}}}}).Inspect(context.Background())
	if err != nil {
		t.Fatalf("expected plain-text nft inspect to succeed, got %v", err)
	}
	if len(nftSnapshot.Tables) != 1 || nftSnapshot.Tables[0].Name != "filter" {
		t.Fatalf("expected the unrelated table to be parsed from plain text, got %#v", nftSnapshot.Tables)
	}

	plan := testMarkAttachmentPlan(t, policy.TargetKindInbound, limiter.ActionApply)
	execution := testMarkAttachmentExecution(t, IdentityKindInbound, plan.Handles.ClassID, plan.Handles.RootHandle)
	plan.MarkAttachment = &execution

	applied, err := AppendMarkAttachmentApply(plan, Snapshot{Device: "eth0"}, nftSnapshot)
	if err != nil {
		t.Fatalf("expected mark-attachment apply against the plain-text snapshot to succeed, got %v", err)
	}
	if !containsStepNamed(applied.Steps, "ensure-mark-attachment-table") {
		t.Fatalf("expected the managed table to be created, got %#v", stepNames(applied.Steps))
	}
	if !containsStepNamed(applied.Steps, "upsert-mark-attachment-filter") {
		t.Fatalf("expected the tc fw filter to be applied, got %#v", stepNames(applied.Steps))
	}

	runner := &scriptedRunner{handler: func(Command) (Result, error) { return Result{}, nil }}
	results, err := rootExecutor(runner).Execute(context.Background(), applied)
	if err != nil {
		t.Fatalf("expected execution of the mark-attachment apply to succeed, got %v", err)
	}
	if len(results) != len(applied.Steps) {
		t.Fatalf("expected every step to execute, got %d results for %d steps", len(results), len(applied.Steps))
	}
	if !runner.issued(func(c Command) bool {
		return commandHasArgs(c, "filter", "replace", "dev", "eth0") && commandHasArgs(c, "fw", "classid")
	}) {
		t.Fatalf("expected the tc fw filter command to run, got %#v", runner.commands)
	}
}
