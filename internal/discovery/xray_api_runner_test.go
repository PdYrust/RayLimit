package discovery

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"testing"
	"time"
)

// TestHelperProcess is not a real test. It is re-executed as a fake `xray` /
// `docker` process by the runner tests below, emitting controlled stdout,
// stderr, and exit codes supplied through the environment.
func TestHelperProcess(t *testing.T) {
	if os.Getenv("GO_WANT_HELPER_PROCESS") != "1" {
		return
	}

	fmt.Fprint(os.Stdout, os.Getenv("XRAY_HELPER_STDOUT"))
	fmt.Fprint(os.Stderr, os.Getenv("XRAY_HELPER_STDERR"))
	code, _ := strconv.Atoi(os.Getenv("XRAY_HELPER_EXIT"))
	os.Exit(code)
}

// fakeXrayExec returns an exec factory that re-executes the test binary as the
// helper process. The behave callback decides the simulated stdout, stderr, and
// exit code, and is told whether the invocation requested -json so a runtime
// that rejects the flag can be modeled.
func fakeXrayExec(behave func(jsonRequested bool) (stdout, stderr string, exit int)) func(context.Context, string, ...string) *exec.Cmd {
	return func(ctx context.Context, _ string, arg ...string) *exec.Cmd {
		jsonRequested := false
		for _, a := range arg {
			if a == "-json" {
				jsonRequested = true
				break
			}
		}

		stdout, stderr, exit := behave(jsonRequested)
		cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=TestHelperProcess", "--")
		cmd.Env = append(os.Environ(),
			"GO_WANT_HELPER_PROCESS=1",
			"XRAY_HELPER_STDOUT="+stdout,
			"XRAY_HELPER_STDERR="+stderr,
			"XRAY_HELPER_EXIT="+strconv.Itoa(exit),
		)
		return cmd
	}
}

func swapXrayExec(t *testing.T, factory func(context.Context, string, ...string) *exec.Cmd) {
	t.Helper()
	previous := xrayExecCommandContext
	xrayExecCommandContext = factory
	t.Cleanup(func() { xrayExecCommandContext = previous })
}

// swapXrayLookPath substitutes the binary resolver so runner tests do not
// depend on a real xray/docker binary being installed.
func swapXrayLookPath(t *testing.T, lookPath func(string) (string, error)) {
	t.Helper()
	previous := xrayLookPath
	xrayLookPath = lookPath
	t.Cleanup(func() { xrayLookPath = previous })
}

// lookPathFound resolves any binary to itself, modeling a successfully located
// executable.
func lookPathFound(name string) (string, error) {
	return name, nil
}

func TestDefaultXrayAPICommandRunnerReturnsStdoutAndIgnoresStderrOnSuccess(t *testing.T) {
	swapXrayLookPath(t, lookPathFound)
	swapXrayExec(t, fakeXrayExec(func(bool) (string, string, int) {
		return `{"users":["user-a"]}`, "warning: -json output is experimental", 0
	}))

	out, err := defaultXrayAPICommandRunner(context.Background(), "xray", "127.0.0.1:10085", 0, "statsgetallonlineusers")
	if err != nil {
		t.Fatalf("expected success, got %v", err)
	}
	if strings.Contains(string(out), "experimental") {
		t.Fatalf("stderr leaked into the parsed payload: %q", out)
	}
	if strings.TrimSpace(string(out)) != `{"users":["user-a"]}` {
		t.Fatalf("expected stdout-only payload, got %q", out)
	}

	users, err := queryXrayOnlineUsers(context.Background(), func(context.Context, string, ...string) ([]byte, error) {
		return out, nil
	}, "127.0.0.1:10085")
	if err != nil {
		t.Fatalf("expected parser to accept stdout payload, got %v", err)
	}
	if len(users) != 1 || users[0] != "user-a" {
		t.Fatalf("unexpected parsed users: %#v", users)
	}
}

func TestDefaultXrayAPICommandRunnerReportsStderrOnNonZeroExit(t *testing.T) {
	swapXrayLookPath(t, lookPathFound)
	swapXrayExec(t, fakeXrayExec(func(bool) (string, string, int) {
		return "", "dial tcp 127.0.0.1:10085: connect: connection refused", 1
	}))

	_, err := defaultXrayAPICommandRunner(context.Background(), "xray", "127.0.0.1:10085", 0, "statsgetallonlineusers")
	if err == nil {
		t.Fatal("expected a non-zero exit to produce an error")
	}
	if !strings.Contains(err.Error(), "connection refused") {
		t.Fatalf("expected stderr content in the error message, got %q", err.Error())
	}
	if code, ok := sessionQueryErrorCode(err); !ok || code != SessionEvidenceIssueUnavailable {
		t.Fatalf("expected typed unavailable error, got code=%q ok=%v err=%v", code, ok, err)
	}
}

func TestDefaultXrayAPICommandRunnerParsesPlainTextDespiteJSONFlag(t *testing.T) {
	swapXrayLookPath(t, lookPathFound)
	swapXrayExec(t, fakeXrayExec(func(bool) (string, string, int) {
		return "user>>>user-a>>>online\nuser>>>user-b>>>online\n", "", 0
	}))

	out, err := defaultXrayAPICommandRunner(context.Background(), "xray", "127.0.0.1:10085", 0, "statsgetallonlineusers")
	if err != nil {
		t.Fatalf("expected success, got %v", err)
	}

	users, err := queryXrayOnlineUsers(context.Background(), func(context.Context, string, ...string) ([]byte, error) {
		return out, nil
	}, "127.0.0.1:10085")
	if err != nil {
		t.Fatalf("expected plain-text parsing to succeed, got %v", err)
	}
	if len(users) != 2 || users[0] != "user-a" || users[1] != "user-b" {
		t.Fatalf("unexpected parsed users: %#v", users)
	}
}

func TestDefaultXrayAPICommandRunnerRetriesWithoutJSONWhenFlagRejected(t *testing.T) {
	swapXrayLookPath(t, lookPathFound)
	swapXrayExec(t, fakeXrayExec(func(jsonRequested bool) (string, string, int) {
		if jsonRequested {
			return "", "flag provided but not defined: -json", 2
		}
		return "user>>>user-a>>>online\n", "", 0
	}))

	out, err := defaultXrayAPICommandRunner(context.Background(), "xray", "127.0.0.1:10085", 0, "statsgetallonlineusers")
	if err != nil {
		t.Fatalf("expected plain-text retry to succeed after -json rejection, got %v", err)
	}

	users, err := queryXrayOnlineUsers(context.Background(), func(context.Context, string, ...string) ([]byte, error) {
		return out, nil
	}, "127.0.0.1:10085")
	if err != nil {
		t.Fatalf("expected parser to accept retried plain-text payload, got %v", err)
	}
	if len(users) != 1 || users[0] != "user-a" {
		t.Fatalf("unexpected parsed users after retry: %#v", users)
	}
}

func TestDefaultXrayAPICommandRunnerEmitsJSONAndConfigurableTimeoutFlags(t *testing.T) {
	swapXrayLookPath(t, lookPathFound)
	var captured []string
	swapXrayExec(t, func(ctx context.Context, _ string, arg ...string) *exec.Cmd {
		captured = append([]string(nil), arg...)
		cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=TestHelperProcess", "--")
		cmd.Env = append(os.Environ(),
			"GO_WANT_HELPER_PROCESS=1",
			`XRAY_HELPER_STDOUT={"ips":{}}`,
			"XRAY_HELPER_EXIT=0",
		)
		return cmd
	})

	if _, err := defaultXrayAPICommandRunner(context.Background(), "xray", "127.0.0.1:10085", 25*time.Second, "statsonlineiplist", "-email", "user-a"); err != nil {
		t.Fatalf("expected success, got %v", err)
	}

	for _, want := range []string{"api", "statsonlineiplist", "-json", "--server=127.0.0.1:10085", "--timeout=25", "-email", "user-a"} {
		if !containsArg(captured, want) {
			t.Fatalf("expected argv to contain %q, got %#v", want, captured)
		}
	}
}

func TestXraySessionEvidenceProviderResolvesTimeout(t *testing.T) {
	if got := NewXraySessionEvidenceProvider(nil).resolveTimeout(); got != defaultXrayAPITimeout {
		t.Fatalf("expected default timeout %s, got %s", defaultXrayAPITimeout, got)
	}
	if got := (XraySessionEvidenceProvider{}).resolveTimeout(); got != defaultXrayAPITimeout {
		t.Fatalf("expected zero-value provider to fall back to default timeout, got %s", got)
	}
}

func containsArg(args []string, want string) bool {
	for _, arg := range args {
		if arg == want {
			return true
		}
	}

	return false
}
