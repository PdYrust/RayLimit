package discovery

import (
	"context"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

func TestDetectXrayProcessMatchesLikelyXrayProcess(t *testing.T) {
	evidence, ok := detectXrayProcess(processSnapshot{
		PID:            4242,
		ProcessName:    "xray",
		ExecutablePath: "/usr/local/bin/xray",
		CommandLine:    []string{"/usr/local/bin/xray", "run", "-config", "/etc/xray/config.json"},
	})
	if !ok {
		t.Fatal("expected snapshot to match xray")
	}

	if evidence.Confidence != DetectionConfidenceHigh {
		t.Fatalf("expected high confidence, got %q", evidence.Confidence)
	}

	if len(evidence.Reasons) < 2 {
		t.Fatalf("expected multiple detection reasons, got %#v", evidence.Reasons)
	}
}

func TestDetectXrayProcessRejectsNonXrayProcess(t *testing.T) {
	_, ok := detectXrayProcess(processSnapshot{
		PID:            5150,
		ProcessName:    "nginx",
		ExecutablePath: "/usr/sbin/nginx",
		CommandLine:    []string{"/usr/sbin/nginx", "-g", "daemon off;"},
	})
	if ok {
		t.Fatal("expected non-xray snapshot to be rejected")
	}
}

func TestHostProviderDiscoverConvertsProcessesIntoTargets(t *testing.T) {
	procRoot := t.TempDir()

	writeFakeProcProcess(t, procRoot, fakeProcProcess{
		pid:     1201,
		comm:    "xray\n",
		exe:     "/usr/local/bin/xray",
		cwd:     "/etc/xray",
		cmdline: []string{"/usr/local/bin/xray", "run", "-config", "/etc/xray/config.json"},
		cgroup:  "0::/system.slice/docker-ad6dba5899e091c3f64333f1b83354cdc1efb355e0fde0ff1f40453173124264.scope\n",
	})
	writeFakeProcProcess(t, procRoot, fakeProcProcess{
		pid:     2201,
		comm:    "nginx\n",
		exe:     "/usr/sbin/nginx",
		cmdline: []string{"/usr/sbin/nginx", "-g", "daemon off;"},
	})

	provider := HostProvider{procRoot: procRoot}

	result, err := provider.Discover(context.Background(), Request{})
	if err != nil {
		t.Fatalf("expected nil error, got %v", err)
	}

	targets := result.Targets
	if len(targets) != 1 {
		t.Fatalf("expected 1 target, got %d", len(targets))
	}

	if len(result.Issues) != 0 {
		t.Fatalf("expected no provider issues, got %#v", result.Issues)
	}

	target := targets[0]
	if target.Source != DiscoverySourceHostProcess {
		t.Fatalf("unexpected discovery source: %#v", target)
	}

	if target.HostProcess == nil {
		t.Fatalf("expected host process candidate, got %#v", target)
	}

	if target.HostProcess.PID != 1201 {
		t.Fatalf("unexpected pid: %#v", target.HostProcess)
	}

	if target.HostProcess.ExecutablePath != "/usr/local/bin/xray" {
		t.Fatalf("unexpected executable path: %#v", target.HostProcess)
	}

	if got := strings.Join(target.HostProcess.CommandLine, " "); !strings.Contains(got, "-config /etc/xray/config.json") {
		t.Fatalf("unexpected command line: %#v", target.HostProcess.CommandLine)
	}

	if len(target.HostProcess.ConfigPaths) != 1 || target.HostProcess.ConfigPaths[0] != "/etc/xray/config.json" {
		t.Fatalf("unexpected config paths: %#v", target.HostProcess.ConfigPaths)
	}

	expectedResolved := filepath.Join(procRoot, "1201", "root", "etc", "xray", "config.json")
	if len(target.HostProcess.ResolvedConfigPaths) != 1 || target.HostProcess.ResolvedConfigPaths[0] != expectedResolved {
		t.Fatalf("unexpected resolved config paths: %#v", target.HostProcess.ResolvedConfigPaths)
	}

	if target.HostProcess.ContainerID != "ad6dba5899e091c3f64333f1b83354cdc1efb355e0fde0ff1f40453173124264" {
		t.Fatalf("unexpected container id: %#v", target.HostProcess)
	}
}

func TestHostProviderDiscoverHandlesIncompleteMetadata(t *testing.T) {
	procRoot := t.TempDir()

	writeFakeProcProcess(t, procRoot, fakeProcProcess{
		pid:  3301,
		comm: "xray\n",
	})

	provider := HostProvider{procRoot: procRoot}

	result, err := provider.Discover(context.Background(), Request{})
	if err != nil {
		t.Fatalf("expected nil error, got %v", err)
	}

	targets := result.Targets
	if len(targets) != 1 {
		t.Fatalf("expected 1 target, got %d", len(targets))
	}

	if targets[0].HostProcess == nil || targets[0].HostProcess.PID != 3301 {
		t.Fatalf("unexpected host process target: %#v", targets[0])
	}

	if targets[0].HostProcess.ExecutablePath != "" {
		t.Fatalf("expected empty executable path, got %#v", targets[0].HostProcess)
	}

	if len(targets[0].HostProcess.CommandLine) != 0 {
		t.Fatalf("expected empty command line, got %#v", targets[0].HostProcess.CommandLine)
	}

	if len(result.Issues) != 0 {
		t.Fatalf("expected no provider issues, got %#v", result.Issues)
	}
}

func TestHostProviderDiscoverHandlesUnreadableCommandLine(t *testing.T) {
	procRoot := t.TempDir()

	writeFakeProcProcess(t, procRoot, fakeProcProcess{
		pid:          4401,
		comm:         "xray\n",
		exe:          "/usr/local/bin/xray",
		cmdlineAsDir: true,
	})

	provider := HostProvider{procRoot: procRoot}

	result, err := provider.Discover(context.Background(), Request{})
	if err != nil {
		t.Fatalf("expected nil error, got %v", err)
	}

	targets := result.Targets
	if len(targets) != 1 {
		t.Fatalf("expected 1 target, got %d", len(targets))
	}

	if len(targets[0].HostProcess.CommandLine) != 0 {
		t.Fatalf("expected unreadable command line to be ignored, got %#v", targets[0].HostProcess.CommandLine)
	}

	if len(result.Issues) != 1 {
		t.Fatalf("expected 1 provider issue, got %#v", result.Issues)
	}

	if result.Issues[0].Code != ProviderErrorCodePartialAccess {
		t.Fatalf("expected partial_access provider issue, got %#v", result.Issues[0])
	}

	if !strings.Contains(result.Issues[0].Message, "partially unreadable") {
		t.Fatalf("unexpected provider issue message: %#v", result.Issues[0])
	}

	if result.Issues[0].Hint == "" {
		t.Fatalf("expected provider issue hint, got %#v", result.Issues[0])
	}

	if !result.Issues[0].Restricted {
		t.Fatalf("expected unreadable metadata to be marked restricted, got %#v", result.Issues[0])
	}
}

type fakeProcProcess struct {
	pid          int
	comm         string
	exe          string
	cwd          string
	cmdline      []string
	cgroup       string
	cmdlineAsDir bool
}

func writeFakeProcProcess(t *testing.T, procRoot string, process fakeProcProcess) {
	t.Helper()

	processRoot := filepath.Join(procRoot, strconv.Itoa(process.pid))
	if err := os.MkdirAll(processRoot, 0o755); err != nil {
		t.Fatalf("create process root: %v", err)
	}

	if process.comm != "" {
		if err := os.WriteFile(filepath.Join(processRoot, "comm"), []byte(process.comm), 0o644); err != nil {
			t.Fatalf("write comm: %v", err)
		}
	}

	if process.cgroup != "" {
		if err := os.WriteFile(filepath.Join(processRoot, "cgroup"), []byte(process.cgroup), 0o644); err != nil {
			t.Fatalf("write cgroup: %v", err)
		}
	}

	switch {
	case process.cmdlineAsDir:
		if err := os.Mkdir(filepath.Join(processRoot, "cmdline"), 0o755); err != nil {
			t.Fatalf("create unreadable cmdline placeholder: %v", err)
		}
	case len(process.cmdline) != 0:
		if err := os.WriteFile(filepath.Join(processRoot, "cmdline"), []byte(strings.Join(process.cmdline, "\x00")+"\x00"), 0o644); err != nil {
			t.Fatalf("write cmdline: %v", err)
		}
	}

	if process.exe != "" {
		if err := os.Symlink(process.exe, filepath.Join(processRoot, "exe")); err != nil {
			t.Fatalf("write exe symlink: %v", err)
		}
	}

	if process.cwd != "" {
		if err := os.Symlink(process.cwd, filepath.Join(processRoot, "cwd")); err != nil {
			t.Fatalf("write cwd symlink: %v", err)
		}
	}
}
