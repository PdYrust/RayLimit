package cli

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/PdYrust/RayLimit/internal/discovery"
)

func TestRunInspectShowsEmptyOutputWhenNoTargetsAreAvailable(t *testing.T) {
	service := &stubDiscoveryService{}
	app := NewApp(service)

	var stdout bytes.Buffer
	var stderr bytes.Buffer

	exitCode := app.Run([]string{"inspect"}, &stdout, &stderr)

	if exitCode != 0 {
		t.Fatalf("expected exit code 0, got %d", exitCode)
	}

	if got := stdout.String(); got != "No Xray runtime targets are available for inspection.\n" {
		t.Fatalf("unexpected inspect output: %q", got)
	}

	if stderr.Len() != 0 {
		t.Fatalf("expected no stderr output, got %q", stderr.String())
	}
}

func TestRunInspectShowsSingleTargetDetails(t *testing.T) {
	tempDir := t.TempDir()
	configPath := filepath.Join(tempDir, "config.json")
	config := `{
  "api": {
    "tag": "api",
    "services": ["StatsService", "HandlerService"]
  },
  "inbounds": [
    {
      "tag": "api",
      "listen": "127.0.0.1",
      "port": 10085
    }
  ]
}`
	if err := os.WriteFile(configPath, []byte(config), 0o644); err != nil {
		t.Fatalf("write config: %v", err)
	}
	resolvedConfigPath := filepath.Join(tempDir, "proc", "1001", "root", strings.TrimPrefix(configPath, string(filepath.Separator)))
	if err := os.MkdirAll(filepath.Dir(resolvedConfigPath), 0o755); err != nil {
		t.Fatalf("create resolved config parent: %v", err)
	}
	if err := os.WriteFile(resolvedConfigPath, []byte(config), 0o644); err != nil {
		t.Fatalf("write resolved config: %v", err)
	}

	service := &stubDiscoveryService{
		result: discovery.Result{
			Targets: []discovery.RuntimeTarget{
				{
					Source: discovery.DiscoverySourceHostProcess,
					Identity: discovery.RuntimeIdentity{
						Name:   "edge-a",
						Binary: "xray",
					},
					HostProcess: &discovery.HostProcessCandidate{
						PID:                 1001,
						ExecutablePath:      "/usr/local/bin/xray",
						CommandLine:         []string{"/usr/local/bin/xray", "run", "-config", configPath},
						WorkingDirectory:    "/etc/xray",
						ConfigPaths:         []string{configPath},
						ResolvedConfigPaths: []string{resolvedConfigPath},
					},
					Evidence: &discovery.DetectionEvidence{
						Confidence: discovery.DetectionConfidenceHigh,
						Reasons: []string{
							"executable name matched xray",
							"command name matched xray",
						},
					},
					ReachableAPIEndpoints: []discovery.APIEndpoint{
						{
							Name:    "api",
							Network: discovery.EndpointNetworkTCP,
							Address: "127.0.0.1",
							Port:    11085,
						},
					},
				},
			},
		},
	}
	app := NewApp(service)

	var stdout bytes.Buffer
	var stderr bytes.Buffer

	exitCode := app.Run([]string{"inspect"}, &stdout, &stderr)

	if exitCode != 0 {
		t.Fatalf("expected exit code 0, got %d", exitCode)
	}

	output := stdout.String()
	for _, fragment := range []string{
		"Inspected 1 Xray runtime target.",
		"Targets:",
		"runtime: host process",
		"pid: 1001",
		"executable: /usr/local/bin/xray",
		"command: /usr/local/bin/xray run -config " + configPath,
		"working directory: /etc/xray",
		"config hints:",
		configPath,
		"resolved config hints:",
		resolvedConfigPath,
		"api capability: likely configured",
		"api evidence: Readable configuration hints define Xray API services and a matching inbound.",
		"api endpoints:",
		"api 127.0.0.1:10085",
		"host-reachable api endpoints:",
		"api 127.0.0.1:11085",
		"detection confidence: high",
		"detection reasons:",
	} {
		if !strings.Contains(output, fragment) {
			t.Fatalf("expected inspect output to contain %q, got %q", fragment, output)
		}
	}

	if stderr.Len() != 0 {
		t.Fatalf("expected no stderr output, got %q", stderr.String())
	}
}

func TestRunInspectReturnsFailureWhenSelectionMatchesNothing(t *testing.T) {
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

	exitCode := app.Run([]string{"inspect", "--name", "missing"}, &stdout, &stderr)

	if exitCode != 1 {
		t.Fatalf("expected exit code 1, got %d", exitCode)
	}

	if !strings.Contains(stdout.String(), "No Xray runtime targets matched the current selection.") {
		t.Fatalf("expected no-match inspect output, got %q", stdout.String())
	}

	if stderr.Len() != 0 {
		t.Fatalf("expected no stderr output, got %q", stderr.String())
	}
}

func TestRunInspectHandlesMultipleTargetsCleanly(t *testing.T) {
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
				{
					Source: discovery.DiscoverySourceDockerContainer,
					Identity: discovery.RuntimeIdentity{
						Name:   "edge-b",
						Binary: "xray",
					},
					DockerContainer: &discovery.DockerContainerCandidate{ID: "container-1"},
				},
			},
		},
	}
	app := NewApp(service)

	var stdout bytes.Buffer
	var stderr bytes.Buffer

	exitCode := app.Run([]string{"inspect"}, &stdout, &stderr)

	if exitCode != 1 {
		t.Fatalf("expected exit code 1, got %d", exitCode)
	}

	if stdout.Len() != 0 {
		t.Fatalf("expected no stdout output, got %q", stdout.String())
	}

	if !strings.Contains(stderr.String(), "error selection: multiple runtime targets matched; refine the selection or use --all | count=2") {
		t.Fatalf("expected multiple-match error, got %q", stderr.String())
	}
}

func TestRunInspectShowsJSONOutput(t *testing.T) {
	tempDir := t.TempDir()
	configPath := filepath.Join(tempDir, "config.json")
	config := `{
  "api": {
    "tag": "api",
    "services": ["StatsService"]
  },
  "inbounds": [
    {
      "tag": "api",
      "listen": "127.0.0.1",
      "port": 10085
    }
  ]
}`
	if err := os.WriteFile(configPath, []byte(config), 0o644); err != nil {
		t.Fatalf("write config: %v", err)
	}

	service := &stubDiscoveryService{
		result: discovery.Result{
			Targets: []discovery.RuntimeTarget{
				{
					Source: discovery.DiscoverySourceDockerContainer,
					Identity: discovery.RuntimeIdentity{
						Name:   "edge-b",
						Binary: "xray",
					},
					DockerContainer: &discovery.DockerContainerCandidate{
						ID:          "container-1234567890ab",
						Name:        "xray-edge",
						Image:       "ghcr.io/xtls/xray-core:latest",
						CommandLine: []string{"/usr/local/bin/xray", "run"},
						State:       "running",
						Status:      "Up 5 minutes",
						ConfigPaths: []string{configPath},
					},
				},
			},
			ProviderErrors: []discovery.ProviderError{
				{
					Provider: "docker",
					Source:   discovery.DiscoverySourceDockerContainer,
					Code:     discovery.ProviderErrorCodePartialAccess,
					Message:  "Docker metadata was incomplete for 1 container.",
				},
			},
		},
	}
	app := NewApp(service)

	var stdout bytes.Buffer
	var stderr bytes.Buffer

	exitCode := app.Run([]string{"inspect", "--format", "json"}, &stdout, &stderr)

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

	if len(payload.Targets) != 1 || payload.Targets[0].DockerContainer == nil {
		t.Fatalf("unexpected inspect JSON payload: %#v", payload)
	}

	if payload.Targets[0].APICapability == nil || payload.Targets[0].APICapability.Status != discovery.APICapabilityStatusLikelyConfigured {
		t.Fatalf("expected inspect JSON api capability, got %#v", payload.Targets[0].APICapability)
	}

	if len(payload.Targets[0].DockerContainer.ConfigPaths) != 1 || payload.Targets[0].DockerContainer.ConfigPaths[0] != configPath {
		t.Fatalf("expected inspect JSON docker config hints, got %#v", payload.Targets[0].DockerContainer.ConfigPaths)
	}

	if len(payload.ProviderErrors) != 1 || payload.ProviderErrors[0].Provider != "docker" {
		t.Fatalf("unexpected inspect JSON provider errors: %#v", payload.ProviderErrors)
	}

	if stderr.Len() != 0 {
		t.Fatalf("expected no stderr output, got %q", stderr.String())
	}
}

func TestRunInspectShowsDockerConfigHintsInTextOutput(t *testing.T) {
	tempDir := t.TempDir()
	configPath := filepath.Join(tempDir, "config.json")
	config := `{
  "api": {
    "tag": "api",
    "services": ["StatsService"]
  },
  "inbounds": [
    {
      "tag": "api",
      "listen": "127.0.0.1",
      "port": 10085
    }
  ]
}`
	if err := os.WriteFile(configPath, []byte(config), 0o644); err != nil {
		t.Fatalf("write config: %v", err)
	}

	service := &stubDiscoveryService{
		result: discovery.Result{
			Targets: []discovery.RuntimeTarget{
				{
					Source: discovery.DiscoverySourceDockerContainer,
					Identity: discovery.RuntimeIdentity{
						Name:   "raylimit-xray-test",
						Binary: "xray",
					},
					DockerContainer: &discovery.DockerContainerCandidate{
						ID:          "container-1234567890ab",
						Name:        "raylimit-xray-test",
						Image:       "ghcr.io/xtls/xray-core:latest",
						CommandLine: []string{"/usr/local/bin/xray", "run"},
						State:       "running",
						Status:      "Up 5 minutes",
						ConfigPaths: []string{configPath},
					},
				},
			},
		},
	}
	app := NewApp(service)

	var stdout bytes.Buffer
	var stderr bytes.Buffer

	exitCode := app.Run([]string{"inspect"}, &stdout, &stderr)

	if exitCode != 0 {
		t.Fatalf("expected exit code 0, got %d", exitCode)
	}

	output := stdout.String()
	for _, fragment := range []string{
		"runtime: docker container",
		"container name: raylimit-xray-test",
		"config hints:",
		configPath,
		"api capability: likely configured",
	} {
		if !strings.Contains(output, fragment) {
			t.Fatalf("expected inspect output to contain %q, got %q", fragment, output)
		}
	}

	if stderr.Len() != 0 {
		t.Fatalf("expected no stderr output, got %q", stderr.String())
	}
}

func TestRunInspectRejectsInvalidSelection(t *testing.T) {
	service := &stubDiscoveryService{}
	app := NewApp(service)

	var stdout bytes.Buffer
	var stderr bytes.Buffer

	exitCode := app.Run([]string{"inspect", "--source", "invalid"}, &stdout, &stderr)

	if exitCode != 2 {
		t.Fatalf("expected exit code 2, got %d", exitCode)
	}

	if stdout.Len() != 0 {
		t.Fatalf("expected no stdout output, got %q", stdout.String())
	}

	if !strings.Contains(stderr.String(), `unsupported discovery source "invalid"`) {
		t.Fatalf("expected invalid selection error, got %q", stderr.String())
	}
}

func TestRunInspectPropagatesProviderIssuesWhenSelectionFindsNoTargets(t *testing.T) {
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

	exitCode := app.Run([]string{"inspect", "--container", "xray-edge"}, &stdout, &stderr)

	if exitCode != 1 {
		t.Fatalf("expected exit code 1, got %d", exitCode)
	}

	output := stdout.String()
	if !strings.Contains(output, "No Xray runtime targets matched the current selection.") {
		t.Fatalf("expected no-match inspect output, got %q", output)
	}
	if !strings.Contains(output, "Inspection was limited by provider availability or access issues.") {
		t.Fatalf("expected limitation message, got %q", output)
	}
	if !strings.Contains(output, "Docker access was denied.") {
		t.Fatalf("expected provider issue details, got %q", output)
	}
	if stderr.Len() != 0 {
		t.Fatalf("expected no stderr output, got %q", stderr.String())
	}
}

func TestRunHelpForInspectCommandShowsSelectionOptions(t *testing.T) {
	service := &stubDiscoveryService{}
	app := NewApp(service)

	var stdout bytes.Buffer
	var stderr bytes.Buffer

	exitCode := app.Run([]string{"help", "inspect"}, &stdout, &stderr)

	if exitCode != 0 {
		t.Fatalf("expected exit code 0, got %d", exitCode)
	}

	for _, fragment := range []string{
		"--format text|json",
		"Render as text or machine-readable JSON",
		"--name <name>",
		"--pid <pid>",
		"--container <id-or-name>",
		"--all",
		"Examples:",
		"raylimit inspect --pid 4242",
		"raylimit inspect --container raylimit-xray-test --format json",
	} {
		if !strings.Contains(stdout.String(), fragment) {
			t.Fatalf("expected inspect help to contain %q, got %q", fragment, stdout.String())
		}
	}

	if stderr.Len() != 0 {
		t.Fatalf("expected no stderr output, got %q", stderr.String())
	}
}
