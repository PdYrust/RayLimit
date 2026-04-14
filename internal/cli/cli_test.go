package cli

import (
	"bytes"
	"strings"
	"testing"

	"github.com/PdYrust/RayLimit/internal/buildinfo"
)

func TestRunWithoutArgumentsShowsRootHelp(t *testing.T) {
	var stdout bytes.Buffer
	var stderr bytes.Buffer

	exitCode := Run(nil, &stdout, &stderr)

	if exitCode != 0 {
		t.Fatalf("expected exit code 0, got %d", exitCode)
	}

	if !strings.Contains(stdout.String(), "Usage:\n  raylimit <command> [arguments]") {
		t.Fatalf("expected root usage output, got %q", stdout.String())
	}

	for _, fragment := range []string{
		"RayLimit\nReconcile-aware traffic shaping for Xray runtimes on Linux.",
		"Core commands:",
		"  limit     Plan or execute a reconcile-aware traffic limit",
		"  discover  Discover Xray runtime targets",
		"  inspect   Inspect runtime metadata and API hints",
		"Information:",
		"  version   Show version, build, and project metadata",
		"Quick start:",
		"raylimit discover",
		"raylimit inspect --pid 4242",
		"raylimit limit --pid 4242 --ip 203.0.113.4 --device eth0 --direction upload --rate 1048576",
		"Project:",
		"creator     YrustPd",
		"https://github.com/PdYrust/RayLimit",
		"https://t.me/PdYrust",
	} {
		if !strings.Contains(stdout.String(), fragment) {
			t.Fatalf("expected root help output to contain %q, got %q", fragment, stdout.String())
		}
	}

	if stderr.Len() != 0 {
		t.Fatalf("expected no stderr output, got %q", stderr.String())
	}
}

func TestRunHelpFlagShowsRootHelp(t *testing.T) {
	var stdout bytes.Buffer
	var stderr bytes.Buffer

	exitCode := Run([]string{"--help"}, &stdout, &stderr)

	if exitCode != 0 {
		t.Fatalf("expected exit code 0, got %d", exitCode)
	}

	if !strings.Contains(stdout.String(), "Global options:") || !strings.Contains(stdout.String(), "Project:") {
		t.Fatalf("expected root help output, got %q", stdout.String())
	}

	if stderr.Len() != 0 {
		t.Fatalf("expected no stderr output, got %q", stderr.String())
	}
}

func TestRunHelpForVersionCommand(t *testing.T) {
	var stdout bytes.Buffer
	var stderr bytes.Buffer

	exitCode := Run([]string{"help", "version"}, &stdout, &stderr)

	if exitCode != 0 {
		t.Fatalf("expected exit code 0, got %d", exitCode)
	}

	if !strings.Contains(stdout.String(), "Usage:\n  raylimit version") {
		t.Fatalf("expected version command help, got %q", stdout.String())
	}

	if stderr.Len() != 0 {
		t.Fatalf("expected no stderr output, got %q", stderr.String())
	}
}

func TestRunVersionFlagPrintsSummary(t *testing.T) {
	t.Cleanup(func() {
		buildinfo.Version = "dev"
		buildinfo.Commit = "unknown"
		buildinfo.BuildTime = "unknown"
	})

	buildinfo.Version = "1.2.3"

	var stdout bytes.Buffer
	var stderr bytes.Buffer

	exitCode := Run([]string{"--version"}, &stdout, &stderr)

	if exitCode != 0 {
		t.Fatalf("expected exit code 0, got %d", exitCode)
	}

	if got := stdout.String(); got != "RayLimit 1.2.3\n" {
		t.Fatalf("unexpected version output: %q", got)
	}

	if stderr.Len() != 0 {
		t.Fatalf("expected no stderr output, got %q", stderr.String())
	}
}

func TestRunVersionCommandPrintsBuildDetails(t *testing.T) {
	t.Cleanup(func() {
		buildinfo.Version = "dev"
		buildinfo.Commit = "unknown"
		buildinfo.BuildTime = "unknown"
	})

	buildinfo.Version = "2.0.0"
	buildinfo.Commit = "abc1234"
	buildinfo.BuildTime = "2026-03-12T00:00:00Z"

	var stdout bytes.Buffer
	var stderr bytes.Buffer

	exitCode := Run([]string{"version"}, &stdout, &stderr)

	if exitCode != 0 {
		t.Fatalf("expected exit code 0, got %d", exitCode)
	}

	if !strings.Contains(stdout.String(), "version     2.0.0") {
		t.Fatalf("expected version details, got %q", stdout.String())
	}

	if !strings.Contains(stdout.String(), "commit      abc1234") {
		t.Fatalf("expected commit details, got %q", stdout.String())
	}

	if !strings.Contains(stdout.String(), "built       2026-03-12T00:00:00Z") {
		t.Fatalf("expected build time details, got %q", stdout.String())
	}
	if !strings.Contains(stdout.String(), "Reconcile-aware traffic shaping for Xray runtimes on Linux.") {
		t.Fatalf("expected tagline in version details, got %q", stdout.String())
	}
	if !strings.Contains(stdout.String(), "Build:") {
		t.Fatalf("expected build section in version details, got %q", stdout.String())
	}
	if !strings.Contains(stdout.String(), "Project:") {
		t.Fatalf("expected project section in version details, got %q", stdout.String())
	}
	if !strings.Contains(stdout.String(), "creator     YrustPd") {
		t.Fatalf("expected creator details, got %q", stdout.String())
	}
	if !strings.Contains(stdout.String(), "repository  https://github.com/PdYrust/RayLimit") {
		t.Fatalf("expected repository details, got %q", stdout.String())
	}
	if !strings.Contains(stdout.String(), "telegram    https://t.me/PdYrust") {
		t.Fatalf("expected telegram details, got %q", stdout.String())
	}
	if strings.Contains(stdout.String(), "https://github.com/YrustPd") {
		t.Fatalf("expected personal github url to be absent from version details, got %q", stdout.String())
	}

	if stderr.Len() != 0 {
		t.Fatalf("expected no stderr output, got %q", stderr.String())
	}
}

func TestRunRejectsUnknownCommand(t *testing.T) {
	var stdout bytes.Buffer
	var stderr bytes.Buffer

	exitCode := Run([]string{"unknown"}, &stdout, &stderr)

	if exitCode != 2 {
		t.Fatalf("expected exit code 2, got %d", exitCode)
	}

	if stdout.Len() != 0 {
		t.Fatalf("expected no stdout output, got %q", stdout.String())
	}

	if !strings.Contains(stderr.String(), `error validation: unknown command "unknown"`) {
		t.Fatalf("expected unknown command error, got %q", stderr.String())
	}

	if !strings.Contains(stderr.String(), `raylimit help`) {
		t.Fatalf("expected usage hint, got %q", stderr.String())
	}
}

func TestRunHelpForLimitCommand(t *testing.T) {
	var stdout bytes.Buffer
	var stderr bytes.Buffer

	exitCode := Run([]string{"help", "limit"}, &stdout, &stderr)

	if exitCode != 0 {
		t.Fatalf("expected exit code 0, got %d", exitCode)
	}

	if !strings.Contains(stdout.String(), "Usage:\n  raylimit limit") {
		t.Fatalf("expected limit command help, got %q", stdout.String())
	}
	if !strings.Contains(stdout.String(), "Plan first by default. Add --execute only when the selected limiter path is concrete and the local environment can apply tc state safely.") {
		t.Fatalf("expected planning-first limit help text, got %q", stdout.String())
	}
	if !strings.Contains(stdout.String(), "--allow-missing-tc-state") {
		t.Fatalf("expected reconcile-aware limit help text, got %q", stdout.String())
	}
	if !strings.Contains(stdout.String(), "--remove") {
		t.Fatalf("expected remove workflow help text, got %q", stdout.String())
	}
	if !strings.Contains(stdout.String(), "--ip <ip|all>") || !strings.Contains(stdout.String(), "--inbound <tag>") || !strings.Contains(stdout.String(), "--outbound <tag>") {
		t.Fatalf("expected ip, inbound, and outbound workflow help text, got %q", stdout.String())
	}
	if strings.Contains(stdout.String(), "--inbound <tag>                   Inbound-scoped runtime workflow target (concrete for one readable concrete TCP listener)") {
		t.Fatalf("expected inbound help wording to be refreshed, got %q", stdout.String())
	}
	if !strings.Contains(stdout.String(), "--inbound <tag>                   Inbound-scoped target (concrete for one readable concrete TCP listener)") {
		t.Fatalf("expected inbound concrete-selector help text, got %q", stdout.String())
	}
	if !strings.Contains(stdout.String(), "--outbound <tag>                  Outbound-scoped target (concrete when readable Xray config proves one unique non-zero socket mark without proxy or dialer-proxy indirection)") {
		t.Fatalf("expected outbound concrete-socket-mark help text, got %q", stdout.String())
	}
	if !strings.Contains(stdout.String(), "Examples:") {
		t.Fatalf("expected examples section in limit help, got %q", stdout.String())
	}
	if !strings.Contains(stdout.String(), "raylimit limit --pid 4242 --ip all --device eth0 --direction upload --rate 1048576") {
		t.Fatalf("expected ip all baseline example in limit help, got %q", stdout.String())
	}
	if !strings.Contains(stdout.String(), "--unlimited") {
		t.Fatalf("expected unlimited exception help text, got %q", stdout.String())
	}
	if !strings.Contains(stdout.String(), "raylimit limit --pid 4242 --ip 203.0.113.4 --device eth0 --direction upload --unlimited") {
		t.Fatalf("expected specific ip unlimited example in limit help, got %q", stdout.String())
	}
	if !strings.Contains(stdout.String(), "raylimit limit --pid 4242 --inbound api-in --device eth0 --direction upload --rate 1048576") {
		t.Fatalf("expected inbound example in limit help, got %q", stdout.String())
	}
	if !strings.Contains(stdout.String(), "Rule precedence:") {
		t.Fatalf("expected coexistence guidance in limit help, got %q", stdout.String())
	}
	if !strings.Contains(stdout.String(), "specific IP target overrides an ip all baseline") {
		t.Fatalf("expected ip all precedence guidance, got %q", stdout.String())
	}
	if !strings.Contains(stdout.String(), "Current limiter status:") {
		t.Fatalf("expected limiter-status guidance, got %q", stdout.String())
	}
	if !strings.Contains(stdout.String(), "--ip all installs a runtime-local baseline through a direct matchall attachment") {
		t.Fatalf("expected executable-workflow guidance, got %q", stdout.String())
	}
	if !strings.Contains(stdout.String(), "--inbound adds concrete nftables mark plus tc fw attachment when readable Xray config proves one concrete TCP listener for the selected inbound tag.") {
		t.Fatalf("expected inbound workflow boundary guidance in help text, got %q", stdout.String())
	}
	if !strings.Contains(stdout.String(), "--outbound adds concrete nftables output matching plus tc fw attachment when readable Xray config proves one unique non-zero outbound socket mark without proxy or dialer-proxy indirection.") {
		t.Fatalf("expected outbound workflow boundary guidance in help text, got %q", stdout.String())
	}
	if strings.Contains(stdout.String(), "--connection <session-id>") {
		t.Fatalf("expected connection workflow help text to be removed, got %q", stdout.String())
	}

	if stderr.Len() != 0 {
		t.Fatalf("expected no stderr output, got %q", stderr.String())
	}
}

func TestRunLimitRejectsUnlimitedWithIPAllTarget(t *testing.T) {
	var stdout bytes.Buffer
	var stderr bytes.Buffer

	exitCode := Run([]string{"limit", "--pid", "4242", "--ip", "all", "--device", "eth0", "--direction", "upload", "--unlimited"}, &stdout, &stderr)

	if exitCode != 2 {
		t.Fatalf("expected exit code 2, got %d", exitCode)
	}
	if stdout.Len() != 0 {
		t.Fatalf("expected no stdout output, got %q", stdout.String())
	}
	if !strings.Contains(stderr.String(), "--unlimited requires a specific --ip target") {
		t.Fatalf("expected unlimited validation error, got %q", stderr.String())
	}
}

func TestRunLimitRejectsUnlimitedWithInboundTarget(t *testing.T) {
	var stdout bytes.Buffer
	var stderr bytes.Buffer

	exitCode := Run([]string{"limit", "--pid", "4242", "--inbound", "api-in", "--device", "eth0", "--direction", "upload", "--unlimited"}, &stdout, &stderr)

	if exitCode != 2 {
		t.Fatalf("expected exit code 2, got %d", exitCode)
	}
	if stdout.Len() != 0 {
		t.Fatalf("expected no stdout output, got %q", stdout.String())
	}
	if !strings.Contains(stderr.String(), "--unlimited requires a specific --ip target") {
		t.Fatalf("expected inbound-plus-unlimited validation error, got %q", stderr.String())
	}
}

func TestRunLimitRejectsRateWithUnlimited(t *testing.T) {
	var stdout bytes.Buffer
	var stderr bytes.Buffer

	exitCode := Run([]string{"limit", "--pid", "4242", "--ip", "203.0.113.10", "--device", "eth0", "--direction", "upload", "--rate", "2048", "--unlimited"}, &stdout, &stderr)

	if exitCode != 2 {
		t.Fatalf("expected exit code 2, got %d", exitCode)
	}
	if stdout.Len() != 0 {
		t.Fatalf("expected no stdout output, got %q", stdout.String())
	}
	if !strings.Contains(stderr.String(), "cannot use --rate with --unlimited") {
		t.Fatalf("expected rate-plus-unlimited validation error, got %q", stderr.String())
	}
}

func TestRunLimitRejectsRemoveWithUnlimited(t *testing.T) {
	var stdout bytes.Buffer
	var stderr bytes.Buffer

	exitCode := Run([]string{"limit", "--pid", "4242", "--ip", "203.0.113.10", "--device", "eth0", "--direction", "upload", "--remove", "--unlimited"}, &stdout, &stderr)

	if exitCode != 2 {
		t.Fatalf("expected exit code 2, got %d", exitCode)
	}
	if stdout.Len() != 0 {
		t.Fatalf("expected no stdout output, got %q", stdout.String())
	}
	if !strings.Contains(stderr.String(), "cannot use --unlimited with --remove") {
		t.Fatalf("expected remove-plus-unlimited validation error, got %q", stderr.String())
	}
}
