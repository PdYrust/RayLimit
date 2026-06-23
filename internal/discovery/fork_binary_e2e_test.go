package discovery

import (
	"context"
	"sort"
	"testing"
	"time"
)

// hostAPITarget builds a host RuntimeTarget that carries an executable path and
// a readable API config, so the evidence provider's detection -> enrich ->
// query path can run fully in-process.
func hostAPITarget(t *testing.T, execPath, binary, configPath string) RuntimeTarget {
	t.Helper()

	return RuntimeTarget{
		Source:   DiscoverySourceHostProcess,
		Identity: RuntimeIdentity{Name: "edge-a", Binary: binary},
		HostProcess: &HostProcessCandidate{
			PID:            1001,
			ExecutablePath: execPath,
			ConfigPaths:    []string{configPath},
		},
	}
}

func forkAPIConfig(t *testing.T) string {
	t.Helper()

	return writeXrayAPIConfig(t, `{
  "api": {"tag":"api","services":["StatsService"]},
  "inbounds": [{"tag":"api","listen":"127.0.0.1","port":10085}]
}`)
}

// Scenario 1: a host runtime whose binary is the fork release name
// "xray-linux-amd64" at an absolute path. Discovery detects it at high
// confidence, the API query is issued through the absolute executable path, and
// plain-text statsgetallonlineusers (3 records, one with an empty email) plus
// plain-text statsonlineiplist (2 IPs per user) yield 4 sessions for the two
// non-empty users.
func TestForkBinaryHostPlainTextEndToEndYieldsFourSessions(t *testing.T) {
	const execPath = "/opt/xray/xray-linux-amd64"

	evidence, ok := detectXrayProcess(processSnapshot{
		PID:            1001,
		ProcessName:    "xray-linux-amd6", // 15-char truncated /proc comm
		ExecutablePath: execPath,
		CommandLine:    []string{execPath, "run", "-c", "/etc/xray/config.json"},
	})
	if !ok || evidence.Confidence != DetectionConfidenceHigh {
		t.Fatalf("expected high-confidence fork detection, got ok=%v evidence=%#v", ok, evidence)
	}
	if got := resolveHostXrayBinary(hostAPITarget(t, execPath, "xray-linux-amd64", "ignored"), ""); got != execPath {
		t.Fatalf("expected API query to use the absolute fork path, got %q", got)
	}

	configPath := forkAPIConfig(t)
	provider := NewXraySessionEvidenceProvider(stubRuntimeTargetDiscoverer{
		result: Result{Targets: []RuntimeTarget{hostAPITarget(t, execPath, "xray-linux-amd64", configPath)}},
	})
	provider.ProbeEndpoint = func(context.Context, APIEndpoint) error { return nil }

	var queriedBinary string
	provider.RunAPICommand = func(_ context.Context, binary string, _ string, _ time.Duration, command string, args ...string) ([]byte, error) {
		queriedBinary = binary
		switch command {
		case "statsgetallonlineusers":
			// Three records; the middle one has an empty email segment and must
			// be skipped, leaving user-a and user-c.
			return []byte("user>>>user-a>>>online\nuser>>>>>>online\nuser>>>user-c>>>online\n"), nil
		case "statsonlineiplist":
			switch args[len(args)-1] {
			case "user-a":
				return []byte("user>>>user-a>>>online>>>203.0.113.10\nuser>>>user-a>>>online>>>203.0.113.11\n"), nil
			case "user-c":
				return []byte("user>>>user-c>>>online>>>203.0.113.20\nuser>>>user-c>>>online>>>203.0.113.21\n"), nil
			default:
				t.Fatalf("unexpected statsonlineiplist email %#v", args)
				return nil, nil
			}
		default:
			t.Fatalf("unexpected command %q", command)
			return nil, nil
		}
	}

	result, err := provider.ObserveSessions(context.Background(), testXrayEvidenceRuntime())
	if err != nil {
		t.Fatalf("expected observation to succeed, got %v", err)
	}
	if result.State() != SessionEvidenceStateAvailable {
		t.Fatalf("expected available state, got %#v", result)
	}
	if queriedBinary != execPath {
		t.Fatalf("expected the API runner to be invoked with the absolute fork path, got %q", queriedBinary)
	}
	if len(result.Evidence) != 4 {
		t.Fatalf("expected 4 sessions (2 users x 2 IPs), got %d: %#v", len(result.Evidence), result.Evidence)
	}

	gotIPs := make([]string, 0, len(result.Evidence))
	for _, ev := range result.Evidence {
		gotIPs = append(gotIPs, ev.Session.Client.IP)
	}
	sort.Strings(gotIPs)
	wantIPs := []string{"203.0.113.10", "203.0.113.11", "203.0.113.20", "203.0.113.21"}
	for i := range wantIPs {
		if gotIPs[i] != wantIPs[i] {
			t.Fatalf("unexpected observed client IPs: got %#v want %#v", gotIPs, wantIPs)
		}
	}
}

// Scenario 2: a Sanaei fork container. Detection fires on the image (High),
// command (High), label (Medium), and published API port (Low); the resulting
// target's binary is the in-container fork name that the container API query
// would invoke.
func TestSanaeiForkContainerDetectionAndBinaryResolution(t *testing.T) {
	container := dockerContainerSummary{
		ID:      "container-1",
		Name:    "sanaei-edge",
		Image:   "ghcr.io/sanaei/sanaei:latest",
		Command: "/usr/local/bin/sanaei-linux-amd64 run -c /etc/sanaei/config.json",
		State:   "running",
	}
	inspect := dockerContainerInspect{
		ID:     "container-1",
		Path:   "/usr/local/bin/sanaei-linux-amd64",
		Args:   []string{"run", "-c", "/etc/sanaei/config.json"},
		Labels: map[string]string{"app": "sanaei"},
		Ports: []dockerPortBinding{{
			ContainerPort: 10085,
			Protocol:      "tcp",
			HostIP:        "0.0.0.0",
			HostPort:      10085,
		}},
	}

	evidence, ok := detectXrayContainerEvidence(container, inspect)
	if !ok {
		t.Fatal("expected the Sanaei fork container to be detected")
	}
	if evidence.Confidence != DetectionConfidenceHigh {
		t.Fatalf("expected high overall confidence, got %q", evidence.Confidence)
	}
	if len(evidence.Reasons) != 4 {
		t.Fatalf("expected image, command, label, and port reasons, got %#v", evidence.Reasons)
	}

	target, ok := targetFromDockerContainer(container, inspect)
	if !ok {
		t.Fatal("expected a runtime target for the detected container")
	}
	if target.Identity.Binary != "sanaei-linux-amd64" {
		t.Fatalf("expected the in-container fork binary, got %q", target.Identity.Binary)
	}
	if got := resolveContainerXrayBinary(target, ""); got != "sanaei-linux-amd64" {
		t.Fatalf("expected the container API query to use %q, got %q", "sanaei-linux-amd64", got)
	}
}

// Scenario 3 (regression): a vanilla "xray" host runtime returning the JSON wire
// format behaves exactly as before — the query path produces one observed
// session through the literal "xray" binary.
func TestVanillaXrayJSONEndToEndRegression(t *testing.T) {
	const execPath = "/usr/local/bin/xray"
	configPath := forkAPIConfig(t)

	provider := NewXraySessionEvidenceProvider(stubRuntimeTargetDiscoverer{
		result: Result{Targets: []RuntimeTarget{hostAPITarget(t, execPath, "xray", configPath)}},
	})
	provider.ProbeEndpoint = func(context.Context, APIEndpoint) error { return nil }

	var queriedBinary string
	provider.RunAPICommand = func(_ context.Context, binary string, _ string, _ time.Duration, command string, _ ...string) ([]byte, error) {
		queriedBinary = binary
		switch command {
		case "statsgetallonlineusers":
			return []byte(`{"users":["user-a"]}`), nil
		case "statsonlineiplist":
			return []byte(`{"name":"user>>>user-a>>>online","ips":{"203.0.113.10":1710000000}}`), nil
		default:
			t.Fatalf("unexpected command %q", command)
			return nil, nil
		}
	}

	result, err := provider.ObserveSessions(context.Background(), testXrayEvidenceRuntime())
	if err != nil {
		t.Fatalf("expected observation to succeed, got %v", err)
	}
	if result.State() != SessionEvidenceStateAvailable {
		t.Fatalf("expected available state, got %#v", result)
	}
	if queriedBinary != execPath {
		t.Fatalf("expected the vanilla xray path to be queried, got %q", queriedBinary)
	}
	if len(result.Evidence) != 1 || result.Evidence[0].Session.Client.IP != "203.0.113.10" {
		t.Fatalf("expected one JSON-derived session, got %#v", result.Evidence)
	}
	if !IsXrayOnlineIPSessionID(result.Evidence[0].Session.ID) {
		t.Fatalf("expected a synthetic online-ip session id, got %#v", result.Evidence[0])
	}
}

// Scenario 7: when the fork's StatsUserOnline service is not enabled, an empty
// online-user result must surface the typed not-enabled error rather than being
// reported as a genuine no-sessions outcome.
func TestStatsUserOnlineNotEnabledSurfacesTypedError(t *testing.T) {
	endpoint := APIEndpoint{Name: "api", Network: EndpointNetworkTCP, Address: "127.0.0.1", Port: 10085}
	runner := func(_ context.Context, command string, _ ...string) ([]byte, error) {
		if command != "statsgetallonlineusers" {
			t.Fatalf("unexpected command %q", command)
		}
		// Plain-text empty result while the service-presence gate is disabled.
		return []byte("   \n"), nil
	}

	statsUserOnlineDisabled := false
	evidence, err := queryXraySessions(
		context.Background(),
		testXrayEvidenceRuntime(),
		endpoint,
		"127.0.0.1:10085",
		runner,
		&statsUserOnlineDisabled,
	)
	if err == nil {
		t.Fatalf("expected a typed StatsUserOnline-not-enabled error, got evidence %#v", evidence)
	}
	code, ok := sessionQueryErrorCode(err)
	if !ok || code != SessionEvidenceIssueStatsUserOnlineNotEnabled {
		t.Fatalf("expected the not-enabled issue code (not no-sessions), got code=%q ok=%v err=%v", code, ok, err)
	}
}

// Scenario 8: the --xray-binary override (surfaced as XrayBinaryOverride on the
// provider) takes precedence over the detected executable path when querying.
func TestXrayBinaryOverrideTakesPrecedenceOverDetection(t *testing.T) {
	const override = "/opt/xray/xray-linux-amd64"

	// Unit-level precedence: an explicit override beats a detected executable path.
	if got := resolveHostXrayBinary(hostAPITarget(t, "/usr/bin/xray", "xray", "ignored"), override); got != override {
		t.Fatalf("expected the override to win over the detected path, got %q", got)
	}

	configPath := forkAPIConfig(t)
	provider := NewXraySessionEvidenceProvider(stubRuntimeTargetDiscoverer{
		result: Result{Targets: []RuntimeTarget{hostAPITarget(t, "/usr/bin/xray", "xray", configPath)}},
	})
	provider.XrayBinaryOverride = override
	provider.ProbeEndpoint = func(context.Context, APIEndpoint) error { return nil }

	var queriedBinary string
	provider.RunAPICommand = func(_ context.Context, binary string, _ string, _ time.Duration, command string, _ ...string) ([]byte, error) {
		queriedBinary = binary
		switch command {
		case "statsgetallonlineusers":
			return []byte(`{"users":[]}`), nil
		default:
			t.Fatalf("unexpected command %q", command)
			return nil, nil
		}
	}

	if _, err := provider.ObserveSessions(context.Background(), testXrayEvidenceRuntime()); err != nil {
		t.Fatalf("expected observation to succeed, got %v", err)
	}
	if queriedBinary != override {
		t.Fatalf("expected the override binary %q to be queried, got %q", override, queriedBinary)
	}
}
