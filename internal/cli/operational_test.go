package cli

import (
	"bytes"
	"context"
	"strings"
	"testing"

	"github.com/PdYrust/RayLimit/internal/discovery"
	"github.com/PdYrust/RayLimit/internal/tc"
)

func validLimitOptions() limitOptions {
	return limitOptions{
		format:    discovery.OutputFormatText,
		operation: limitOperationApply,
		runtime:   limitRuntimeSelection{PID: 4242, PIDSet: true},
		target:    limitTargetSelection{IP: "203.0.113.10"},
		device:    "eth0",
		direction: tc.DirectionUpload,
		rateBytes: 1048576,
	}
}

func TestRunDebugLogLevelEmitsDiagnostics(t *testing.T) {
	service := &stubDiscoveryService{}
	app := NewApp(service)
	app.overrides.logLevel = "debug"

	var stdout, stderr bytes.Buffer
	if exit := app.Run([]string{"discover"}, &stdout, &stderr); exit != exitCodeSuccess {
		t.Fatalf("expected discover to succeed, got exit %d (stderr=%q)", exit, stderr.String())
	}

	if !strings.Contains(stderr.String(), "debug discovery") {
		t.Fatalf("expected debug-level diagnostics on stderr, got %q", stderr.String())
	}
}

func TestRunDefaultLogLevelSuppressesDebugAndInfo(t *testing.T) {
	service := &stubDiscoveryService{}
	app := NewApp(service)

	var stdout, stderr bytes.Buffer
	if exit := app.Run([]string{"discover"}, &stdout, &stderr); exit != exitCodeSuccess {
		t.Fatalf("expected discover to succeed, got exit %d (stderr=%q)", exit, stderr.String())
	}

	if strings.Contains(stderr.String(), "debug discovery") || strings.Contains(stderr.String(), "info discovery") {
		t.Fatalf("expected the default error level to suppress debug/info diagnostics, got %q", stderr.String())
	}
}

func TestRunRejectsUnsupportedLogLevel(t *testing.T) {
	service := &stubDiscoveryService{}
	app := NewApp(service)
	app.overrides.logLevel = "loud"

	var stdout, stderr bytes.Buffer
	if exit := app.Run([]string{"discover"}, &stdout, &stderr); exit != exitCodeUsage {
		t.Fatalf("expected an unsupported log level to be a usage error, got exit %d", exit)
	}
	if !strings.Contains(stderr.String(), "unsupported log level") {
		t.Fatalf("expected a clear log-level error, got %q", stderr.String())
	}
}

func TestLimitOptionsRejectsRateAboveCap(t *testing.T) {
	options := validLimitOptions()
	options.rateBytes = maxRateBytesPerSecond + 1

	err := options.Validate()
	if err == nil {
		t.Fatal("expected a rate above the cap to be rejected")
	}
	if !strings.Contains(err.Error(), "1 TiB/s") {
		t.Fatalf("expected a clear rate-cap error, got %v", err)
	}
}

func TestLimitOptionsAcceptsRateAtCap(t *testing.T) {
	options := validLimitOptions()
	options.rateBytes = maxRateBytesPerSecond

	if err := options.Validate(); err != nil {
		t.Fatalf("expected the exact 1 TiB/s rate to be accepted, got %v", err)
	}
}

func TestInspectSelectionRejectsExplicitPidZero(t *testing.T) {
	selection := inspectSelection{PID: 0, PIDSet: true}
	if err := selection.Validate(); err == nil {
		t.Fatal("expected an explicitly provided pid 0 to be rejected")
	}
}

func TestInspectSelectionAllowsUnsetPid(t *testing.T) {
	selection := inspectSelection{PID: 0, PIDSet: false}
	if err := selection.Validate(); err != nil {
		t.Fatalf("expected an unset pid to remain valid, got %v", err)
	}
}

func TestRunInspectRejectsPidZeroEndToEnd(t *testing.T) {
	service := &stubDiscoveryService{}
	app := NewApp(service)

	var stdout, stderr bytes.Buffer
	if exit := app.Run([]string{"inspect", "--pid", "0"}, &stdout, &stderr); exit != exitCodeUsage {
		t.Fatalf("expected --pid 0 to be a usage error, got exit %d (stderr=%q)", exit, stderr.String())
	}
	if !strings.Contains(stderr.String(), "kernel scheduler") {
		t.Fatalf("expected a clear pid-0 rejection, got %q", stderr.String())
	}
}

// contextAwareDiscovery fails fast when its context is already cancelled, so a
// test can confirm the signal-aware context is threaded into discovery.
type contextAwareDiscovery struct{}

func (contextAwareDiscovery) Discover(ctx context.Context, _ discovery.Request) (discovery.Result, error) {
	if err := ctx.Err(); err != nil {
		return discovery.Result{}, err
	}

	return discovery.Result{}, nil
}

func TestRunPropagatesCancelledContextToDiscovery(t *testing.T) {
	app := NewApp(contextAwareDiscovery{})

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	var stdout, stderr bytes.Buffer
	if exit := app.runWithContext(ctx, []string{"discover"}, &stdout, &stderr); exit != exitCodeFailure {
		t.Fatalf("expected a cancelled context to fail discovery, got exit %d", exit)
	}
	if !strings.Contains(stderr.String(), "discovery failed") {
		t.Fatalf("expected a discovery failure diagnostic, got %q", stderr.String())
	}
}
