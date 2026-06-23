package tc

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/PdYrust/RayLimit/internal/privilege"
)

func TestValidatePrivilegeRootFastPathSkipsProbe(t *testing.T) {
	probeCalled := false
	executor := Executor{
		privilegeStatus: func() privilege.Status { return privilege.Status{EUID: 0, IsRoot: true} },
		PrivilegeProbe: func(context.Context) error {
			probeCalled = true
			return nil
		},
	}

	if err := executor.validatePrivilege(context.Background()); err != nil {
		t.Fatalf("expected root to pass the privilege check, got %v", err)
	}
	if probeCalled {
		t.Fatal("expected the root fast-path to skip the probe")
	}
}

func TestValidatePrivilegeProbeSuccessAllowsNonRoot(t *testing.T) {
	executor := Executor{
		privilegeStatus: func() privilege.Status { return privilege.Status{EUID: 1000} },
		PrivilegeProbe:  func(context.Context) error { return nil },
	}

	if err := executor.validatePrivilege(context.Background()); err != nil {
		t.Fatalf("expected a successful probe to allow a non-root process (CAP_NET_ADMIN), got %v", err)
	}
}

func TestValidatePrivilegeProbeFailureRejectsNonRoot(t *testing.T) {
	executor := Executor{
		privilegeStatus: func() privilege.Status { return privilege.Status{EUID: 1000} },
		PrivilegeProbe:  func(context.Context) error { return errors.New("tc privilege probe failed") },
	}

	err := executor.validatePrivilege(context.Background())
	var permissionError PermissionError
	if !errors.As(err, &permissionError) {
		t.Fatalf("expected a PermissionError when the probe fails, got %v", err)
	}
	if !strings.Contains(permissionError.Error(), "CAP_NET_ADMIN") || !strings.Contains(permissionError.Error(), "root") {
		t.Fatalf("expected the error to explain both root and CAP_NET_ADMIN, got %q", permissionError.Error())
	}
}

func TestValidatePrivilegeSkipBypassesAllChecks(t *testing.T) {
	probeCalled := false
	executor := Executor{
		SkipPrivilegeCheck: true,
		privilegeStatus:    func() privilege.Status { return privilege.Status{EUID: 1000} },
		PrivilegeProbe: func(context.Context) error {
			probeCalled = true
			return errors.New("would have failed")
		},
	}

	if err := executor.validatePrivilege(context.Background()); err != nil {
		t.Fatalf("expected --skip-privilege-check to bypass the privilege check, got %v", err)
	}
	if probeCalled {
		t.Fatal("expected the skip escape hatch to avoid running the probe")
	}
}

func TestProbePrivilegeSucceedsForReachableTC(t *testing.T) {
	runner := &fakeRunner{}
	if err := ProbePrivilege(context.Background(), runner, "tc"); err != nil {
		t.Fatalf("expected a reachable tc probe to succeed, got %v", err)
	}
	if len(runner.commands) != 1 {
		t.Fatalf("expected exactly one probe command, got %#v", runner.commands)
	}
	got := runner.commands[0]
	if got.Path != "tc" {
		t.Fatalf("expected the probe to use the resolved tc binary, got %q", got.Path)
	}
	if len(got.Args) < 4 || got.Args[0] != "qdisc" || got.Args[1] != "show" || got.Args[2] != "dev" || got.Args[3] != "lo" {
		t.Fatalf("expected a read-only `qdisc show dev lo` probe, got %#v", got.Args)
	}
}

func TestProbePrivilegeReportsRunnerFailure(t *testing.T) {
	runner := &fakeRunner{err: errors.New("operation not permitted")}
	if err := ProbePrivilege(context.Background(), runner, "tc"); err == nil {
		t.Fatal("expected a failing probe to return an error")
	}
}
