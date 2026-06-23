package discovery

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"testing"
)

func swapDockerExec(t *testing.T, factory func(context.Context, string, ...string) *exec.Cmd) {
	t.Helper()
	previous := dockerExecCommandContext
	dockerExecCommandContext = factory
	t.Cleanup(func() { dockerExecCommandContext = previous })
}

func swapDockerLookPath(t *testing.T, lookPath func(string) (string, error)) {
	t.Helper()
	previous := dockerLookPath
	dockerLookPath = lookPath
	t.Cleanup(func() { dockerLookPath = previous })
}

func TestNormalizeContainerCLI(t *testing.T) {
	cases := map[string]string{
		"":        "docker",
		"  ":      "docker",
		"docker":  "docker",
		"podman":  "podman",
		"nerdctl": "nerdctl",
	}
	for input, want := range cases {
		if got := normalizeContainerCLI(input); got != want {
			t.Fatalf("normalizeContainerCLI(%q) = %q, want %q", input, got, want)
		}
	}
}

func TestNewDockerProviderWithCLI(t *testing.T) {
	if got := NewDockerProviderWithCLI("docker").containerCLI; got != "docker" {
		t.Fatalf("expected default container CLI docker, got %q", got)
	}
	if got := NewDockerProviderWithCLI("podman").containerCLI; got != "podman" {
		t.Fatalf("expected podman container CLI, got %q", got)
	}
	if got := NewDockerProviderWithCLI("").containerCLI; got != "docker" {
		t.Fatalf("expected empty override to default to docker, got %q", got)
	}
}

func TestListDockerContainersUsesConfiguredContainerCLI(t *testing.T) {
	var lookedUp string
	swapDockerLookPath(t, func(name string) (string, error) {
		lookedUp = name
		return name, nil
	})

	var execName string
	swapDockerExec(t, func(ctx context.Context, name string, _ ...string) *exec.Cmd {
		execName = name
		cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=TestHelperProcess", "--")
		cmd.Env = append(os.Environ(), "GO_WANT_HELPER_PROCESS=1", "XRAY_HELPER_EXIT=0")
		return cmd
	})

	if _, err := listDockerContainers(context.Background(), "podman"); err != nil {
		t.Fatalf("expected success, got %v", err)
	}
	if lookedUp != "podman" {
		t.Fatalf("expected LookPath of podman, got %q", lookedUp)
	}
	if execName != "podman" {
		t.Fatalf("expected exec to invoke podman, got %q", execName)
	}
}

func TestListDockerContainersReportsNotInstalledNamingCLI(t *testing.T) {
	swapDockerLookPath(t, func(string) (string, error) {
		return "", exec.ErrNotFound
	})

	_, err := listDockerContainers(context.Background(), "podman")
	if err == nil {
		t.Fatal("expected a not-installed error")
	}
	var providerErr ProviderError
	if !errors.As(err, &providerErr) {
		t.Fatalf("expected ProviderError, got %T: %v", err, err)
	}
	if providerErr.Code != ProviderErrorCodeNotInstalled {
		t.Fatalf("expected not_installed code, got %#v", providerErr)
	}
	if providerErr.Message != "podman CLI was not found." {
		t.Fatalf("expected the CLI to be named in the message, got %q", providerErr.Message)
	}
}

func TestResolveHostXrayBinaryHonorsOverride(t *testing.T) {
	target := hostTargetWithBinary("/opt/xray/xray-linux-amd64", "xray-linux-amd64")
	if got := resolveHostXrayBinary(target, "/usr/local/bin/sanaei"); got != "/usr/local/bin/sanaei" {
		t.Fatalf("expected override to win, got %q", got)
	}
}

func TestResolveContainerXrayBinaryHonorsOverride(t *testing.T) {
	target := RuntimeTarget{
		Source:          DiscoverySourceDockerContainer,
		Identity:        RuntimeIdentity{Name: "edge", Binary: "xray"},
		DockerContainer: &DockerContainerCandidate{ID: "container-1"},
	}
	if got := resolveContainerXrayBinary(target, "sanaei"); got != "sanaei" {
		t.Fatalf("expected override to win, got %q", got)
	}
}

func TestSessionContainerRunnerUsesConfiguredContainerCLI(t *testing.T) {
	swapXrayLookPath(t, lookPathFound)
	var execName string
	swapXrayExec(t, func(ctx context.Context, name string, _ ...string) *exec.Cmd {
		execName = name
		cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=TestHelperProcess", "--")
		cmd.Env = append(os.Environ(), "GO_WANT_HELPER_PROCESS=1", `XRAY_HELPER_STDOUT={"users":[]}`, "XRAY_HELPER_EXIT=0")
		return cmd
	})

	provider := NewXraySessionEvidenceProvider(nil)
	provider.ContainerCLI = "podman"
	runner := provider.containerAPICommandRunner()

	if _, err := runner(context.Background(), "container-1", "xray", "127.0.0.1:10085", 0, "statsgetallonlineusers"); err != nil {
		t.Fatalf("expected success, got %v", err)
	}
	if execName != "podman" {
		t.Fatalf("expected container exec to invoke podman, got %q", execName)
	}
}
