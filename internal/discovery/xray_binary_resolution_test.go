package discovery

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"strings"
	"testing"
)

func hostTargetWithBinary(executablePath, binary string) RuntimeTarget {
	return RuntimeTarget{
		Source:   DiscoverySourceHostProcess,
		Identity: RuntimeIdentity{Name: "edge-a", Binary: binary},
		HostProcess: &HostProcessCandidate{
			PID:            1001,
			ExecutablePath: executablePath,
		},
	}
}

func TestResolveHostXrayBinaryPrefersExecutablePath(t *testing.T) {
	target := hostTargetWithBinary("/opt/xray/xray-linux-amd64", "xray-linux-amd64")
	if got := resolveHostXrayBinary(target, ""); got != "/opt/xray/xray-linux-amd64" {
		t.Fatalf("expected absolute executable path, got %q", got)
	}
}

func TestResolveHostXrayBinaryFallsBackToIdentityBinary(t *testing.T) {
	target := hostTargetWithBinary("", "xray-linux-amd64")
	if got := resolveHostXrayBinary(target, ""); got != "xray-linux-amd64" {
		t.Fatalf("expected identity binary fallback, got %q", got)
	}
}

func TestResolveHostXrayBinaryFallsBackToLiteralXray(t *testing.T) {
	target := hostTargetWithBinary("", "")
	if got := resolveHostXrayBinary(target, ""); got != "xray" {
		t.Fatalf("expected literal xray fallback, got %q", got)
	}
}

func TestResolveContainerXrayBinary(t *testing.T) {
	withBinary := RuntimeTarget{
		Source:          DiscoverySourceDockerContainer,
		Identity:        RuntimeIdentity{Name: "edge", Binary: "sanaei-linux-amd64"},
		DockerContainer: &DockerContainerCandidate{ID: "container-1"},
	}
	if got := resolveContainerXrayBinary(withBinary, ""); got != "sanaei-linux-amd64" {
		t.Fatalf("expected detected container binary, got %q", got)
	}

	withoutBinary := RuntimeTarget{
		Source:          DiscoverySourceDockerContainer,
		Identity:        RuntimeIdentity{Name: "edge"},
		DockerContainer: &DockerContainerCandidate{ID: "container-1"},
	}
	if got := resolveContainerXrayBinary(withoutBinary, ""); got != "xray" {
		t.Fatalf("expected literal xray fallback, got %q", got)
	}
}

func TestDefaultXrayAPICommandRunnerInvokesResolvedExecutablePath(t *testing.T) {
	var lookedUp string
	swapXrayLookPath(t, func(name string) (string, error) {
		lookedUp = name
		return name, nil
	})

	var execName string
	swapXrayExec(t, func(ctx context.Context, name string, _ ...string) *exec.Cmd {
		execName = name
		cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=TestHelperProcess", "--")
		cmd.Env = append(os.Environ(),
			"GO_WANT_HELPER_PROCESS=1",
			`XRAY_HELPER_STDOUT={"users":[]}`,
			"XRAY_HELPER_EXIT=0",
		)
		return cmd
	})

	const binary = "/opt/xray/xray-linux-amd64"
	if _, err := defaultXrayAPICommandRunner(context.Background(), binary, "127.0.0.1:10085", 0, "statsgetallonlineusers"); err != nil {
		t.Fatalf("expected success, got %v", err)
	}

	if lookedUp != binary {
		t.Fatalf("expected LookPath to be called with %q, got %q", binary, lookedUp)
	}
	if execName != binary {
		t.Fatalf("expected runner to invoke %q, got %q", binary, execName)
	}
}

func TestDefaultXrayAPICommandRunnerLooksUpIdentityBinaryOnPath(t *testing.T) {
	var lookedUp string
	swapXrayLookPath(t, func(name string) (string, error) {
		lookedUp = name
		return "/usr/local/bin/" + name, nil
	})
	swapXrayExec(t, fakeXrayExec(func(bool) (string, string, int) {
		return `{"users":[]}`, "", 0
	}))

	if _, err := defaultXrayAPICommandRunner(context.Background(), "xray-linux-amd64", "127.0.0.1:10085", 0, "statsgetallonlineusers"); err != nil {
		t.Fatalf("expected success, got %v", err)
	}
	if lookedUp != "xray-linux-amd64" {
		t.Fatalf("expected PATH lookup of detected binary, got %q", lookedUp)
	}
}

func TestDefaultXrayAPICommandRunnerReportsNotInstalledWhenBinaryMissing(t *testing.T) {
	swapXrayLookPath(t, func(name string) (string, error) {
		return "", exec.ErrNotFound
	})
	swapXrayExec(t, func(context.Context, string, ...string) *exec.Cmd {
		t.Fatal("expected the runner to fail before invoking the process")
		return nil
	})

	_, err := defaultXrayAPICommandRunner(context.Background(), "/nonexistent/xray", "127.0.0.1:10085", 0, "statsgetallonlineusers")
	if err == nil {
		t.Fatal("expected a not-installed error for a missing binary")
	}
	if !errors.Is(err, exec.ErrNotFound) && !strings.Contains(err.Error(), "was not found") {
		t.Fatalf("expected a not-found error, got %v", err)
	}
	if !strings.Contains(err.Error(), "/nonexistent/xray") {
		t.Fatalf("expected the missing binary to be named, got %v", err)
	}
	if code, ok := sessionQueryErrorCode(err); !ok || code != SessionEvidenceIssueUnavailable {
		t.Fatalf("expected typed unavailable error, got code=%q ok=%v err=%v", code, ok, err)
	}
}
