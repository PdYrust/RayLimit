package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/PdYrust/RayLimit/internal/discovery"
)

type stubDiscoveryService struct {
	result discovery.Result
	err    error
	calls  int
}

func (s *stubDiscoveryService) Discover(_ context.Context, _ discovery.Request) (discovery.Result, error) {
	s.calls++
	return s.result, s.err
}

func TestRunDiscoverShowsEmptyTextOutput(t *testing.T) {
	service := &stubDiscoveryService{}
	app := NewApp(service)

	var stdout bytes.Buffer
	var stderr bytes.Buffer

	exitCode := app.Run([]string{"discover"}, &stdout, &stderr)

	if exitCode != 0 {
		t.Fatalf("expected exit code 0, got %d", exitCode)
	}

	if got := stdout.String(); got != "No Xray runtime candidates found.\n" {
		t.Fatalf("unexpected discover output: %q", got)
	}

	if stderr.Len() != 0 {
		t.Fatalf("expected no stderr output, got %q", stderr.String())
	}

	if service.calls != 1 {
		t.Fatalf("expected discovery service to be called once, got %d", service.calls)
	}
}

func TestRunDiscoverShowsRestrictedEmptyTextOutput(t *testing.T) {
	service := &stubDiscoveryService{
		result: discovery.Result{
			ProviderErrors: []discovery.ProviderError{
				{
					Provider:   "docker",
					Source:     discovery.DiscoverySourceDockerContainer,
					Code:       discovery.ProviderErrorCodePermissionDenied,
					Message:    "Docker access was denied.",
					Hint:       "Run RayLimit as root or add the current user to the docker group.",
					Restricted: true,
				},
			},
		},
	}
	app := NewApp(service)

	var stdout bytes.Buffer
	var stderr bytes.Buffer

	exitCode := app.Run([]string{"discover"}, &stdout, &stderr)

	if exitCode != 0 {
		t.Fatalf("expected exit code 0, got %d", exitCode)
	}

	if got := stdout.String(); !strings.Contains(got, "Discovery was limited by provider availability or access issues.") {
		t.Fatalf("expected restricted discover output, got %q", got)
	}

	if !strings.Contains(stdout.String(), "Docker access was denied.") {
		t.Fatalf("expected provider issue details, got %q", stdout.String())
	}

	if !strings.Contains(stdout.String(), "hint: Run RayLimit as root or add the current user to the docker group.") {
		t.Fatalf("expected provider hint, got %q", stdout.String())
	}

	if stderr.Len() != 0 {
		t.Fatalf("expected no stderr output, got %q", stderr.String())
	}
}

func TestRunDiscoverShowsJSONOutput(t *testing.T) {
	service := &stubDiscoveryService{
		result: discovery.Result{
			Targets: []discovery.RuntimeTarget{
				{
					Source: discovery.DiscoverySourceHostProcess,
					Identity: discovery.RuntimeIdentity{
						Name:   "edge-a",
						Binary: "xray",
					},
					HostProcess: &discovery.HostProcessCandidate{PID: 1001},
				},
			},
		},
	}
	app := NewApp(service)

	var stdout bytes.Buffer
	var stderr bytes.Buffer

	exitCode := app.Run([]string{"discover", "--format", "json"}, &stdout, &stderr)

	if exitCode != 0 {
		t.Fatalf("expected exit code 0, got %d", exitCode)
	}

	var payload struct {
		Targets        []discovery.RuntimeTarget `json:"targets"`
		ProviderErrors []discovery.ProviderError `json:"provider_errors"`
	}

	if err := json.Unmarshal(stdout.Bytes(), &payload); err != nil {
		t.Fatalf("expected valid JSON output, got %v", err)
	}

	if len(payload.Targets) != 1 || payload.Targets[0].Identity.Name != "edge-a" {
		t.Fatalf("unexpected JSON payload: %#v", payload)
	}

	if len(payload.ProviderErrors) != 0 {
		t.Fatalf("expected no provider errors, got %#v", payload.ProviderErrors)
	}

	if stderr.Len() != 0 {
		t.Fatalf("expected no stderr output, got %q", stderr.String())
	}
}

func TestRunDiscoverShowsTextOutputWithTargetsHeading(t *testing.T) {
	service := &stubDiscoveryService{
		result: discovery.Result{
			Targets: []discovery.RuntimeTarget{
				{
					Source: discovery.DiscoverySourceHostProcess,
					Identity: discovery.RuntimeIdentity{
						Name:   "edge-a",
						Binary: "xray",
					},
					HostProcess: &discovery.HostProcessCandidate{PID: 1001},
				},
			},
		},
	}
	app := NewApp(service)

	var stdout bytes.Buffer
	var stderr bytes.Buffer

	exitCode := app.Run([]string{"discover"}, &stdout, &stderr)

	if exitCode != 0 {
		t.Fatalf("expected exit code 0, got %d", exitCode)
	}

	for _, fragment := range []string{
		"Discovered 1 Xray runtime candidate.",
		"Targets:",
		"1. edge-a",
		"source: host_process",
		"pid: 1001",
	} {
		if !strings.Contains(stdout.String(), fragment) {
			t.Fatalf("expected discover text output to contain %q, got %q", fragment, stdout.String())
		}
	}

	if stderr.Len() != 0 {
		t.Fatalf("expected no stderr output, got %q", stderr.String())
	}
}

func TestRunDiscoverShowsJSONProviderErrorDetails(t *testing.T) {
	service := &stubDiscoveryService{
		result: discovery.Result{
			ProviderErrors: []discovery.ProviderError{
				{
					Provider:   "docker",
					Source:     discovery.DiscoverySourceDockerContainer,
					Code:       discovery.ProviderErrorCodePermissionDenied,
					Message:    "Docker access was denied.",
					Hint:       "Run RayLimit as root or add the current user to the docker group.",
					Restricted: true,
				},
			},
		},
	}
	app := NewApp(service)

	var stdout bytes.Buffer
	var stderr bytes.Buffer

	exitCode := app.Run([]string{"discover", "--format", "json"}, &stdout, &stderr)

	if exitCode != 0 {
		t.Fatalf("expected exit code 0, got %d", exitCode)
	}

	var payload struct {
		Targets        []discovery.RuntimeTarget `json:"targets"`
		ProviderErrors []discovery.ProviderError `json:"provider_errors"`
	}

	if err := json.Unmarshal(stdout.Bytes(), &payload); err != nil {
		t.Fatalf("expected valid JSON output, got %v", err)
	}

	if len(payload.Targets) != 0 {
		t.Fatalf("expected no targets, got %#v", payload.Targets)
	}

	if len(payload.ProviderErrors) != 1 {
		t.Fatalf("expected 1 provider error, got %#v", payload.ProviderErrors)
	}

	if payload.ProviderErrors[0].Code != discovery.ProviderErrorCodePermissionDenied {
		t.Fatalf("expected permission_denied provider error, got %#v", payload.ProviderErrors[0])
	}

	if !payload.ProviderErrors[0].Restricted {
		t.Fatalf("expected restricted provider error, got %#v", payload.ProviderErrors[0])
	}

	if payload.ProviderErrors[0].Hint == "" {
		t.Fatalf("expected provider error hint, got %#v", payload.ProviderErrors[0])
	}
}

func TestRunDiscoverRejectsInvalidFormat(t *testing.T) {
	service := &stubDiscoveryService{}
	app := NewApp(service)

	var stdout bytes.Buffer
	var stderr bytes.Buffer

	exitCode := app.Run([]string{"discover", "--format", "yaml"}, &stdout, &stderr)

	if exitCode != 2 {
		t.Fatalf("expected exit code 2, got %d", exitCode)
	}

	if stdout.Len() != 0 {
		t.Fatalf("expected no stdout output, got %q", stdout.String())
	}

	if !strings.Contains(stderr.String(), `error validation: unsupported output format "yaml"`) {
		t.Fatalf("expected invalid format error, got %q", stderr.String())
	}
}

func TestRunDiscoverHandlesServiceErrors(t *testing.T) {
	service := &stubDiscoveryService{
		err: errors.New("discovery backend unavailable"),
	}
	app := NewApp(service)

	var stdout bytes.Buffer
	var stderr bytes.Buffer

	exitCode := app.Run([]string{"discover"}, &stdout, &stderr)

	if exitCode != 1 {
		t.Fatalf("expected exit code 1, got %d", exitCode)
	}

	if stdout.Len() != 0 {
		t.Fatalf("expected no stdout output, got %q", stdout.String())
	}

	if !strings.Contains(stderr.String(), "error discovery: discovery failed: discovery backend unavailable") {
		t.Fatalf("expected service error output, got %q", stderr.String())
	}
}

func TestRunDiscoverFailsOnFatalProviderErrors(t *testing.T) {
	service := &stubDiscoveryService{
		result: discovery.Result{
			ProviderErrors: []discovery.ProviderError{
				{
					Provider: "host",
					Source:   discovery.DiscoverySourceHostProcess,
					Code:     discovery.ProviderErrorCodeExecutionFailed,
					Message:  "read process table: unexpected failure",
				},
			},
		},
	}
	app := NewApp(service)

	var stdout bytes.Buffer
	var stderr bytes.Buffer

	exitCode := app.Run([]string{"discover"}, &stdout, &stderr)

	if exitCode != 1 {
		t.Fatalf("expected exit code 1, got %d", exitCode)
	}

	if !strings.Contains(stdout.String(), "Provider issues:") {
		t.Fatalf("expected provider issue output, got %q", stdout.String())
	}
}

func TestRunHelpForDiscoverCommandShowsFormatOption(t *testing.T) {
	service := &stubDiscoveryService{}
	app := NewApp(service)

	var stdout bytes.Buffer
	var stderr bytes.Buffer

	exitCode := app.Run([]string{"help", "discover"}, &stdout, &stderr)

	if exitCode != 0 {
		t.Fatalf("expected exit code 0, got %d", exitCode)
	}

	for _, fragment := range []string{
		"--format text|json",
		"Render as text or machine-readable JSON",
		"Examples:",
		"raylimit discover",
		"raylimit discover --format json",
	} {
		if !strings.Contains(stdout.String(), fragment) {
			t.Fatalf("expected discover help to contain %q, got %q", fragment, stdout.String())
		}
	}

	if stderr.Len() != 0 {
		t.Fatalf("expected no stderr output, got %q", stderr.String())
	}
}
