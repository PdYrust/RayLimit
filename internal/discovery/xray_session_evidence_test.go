package discovery

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

type stubRuntimeTargetDiscoverer struct {
	result Result
	err    error
}

func (d stubRuntimeTargetDiscoverer) Discover(context.Context, Request) (Result, error) {
	return d.result, d.err
}

func testXrayEvidenceRuntime() SessionRuntime {
	return SessionRuntime{
		Source:   DiscoverySourceHostProcess,
		Name:     "edge-a",
		HostPID:  1001,
		Provider: "host",
	}
}

func testXrayEvidenceDockerRuntime() SessionRuntime {
	return SessionRuntime{
		Source:      DiscoverySourceDockerContainer,
		Name:        "raylimit-xray-test",
		ContainerID: "container-1",
		Provider:    "docker",
	}
}

func testXrayEvidenceTarget(t *testing.T, configPath string) RuntimeTarget {
	t.Helper()

	return RuntimeTarget{
		Source:   DiscoverySourceHostProcess,
		Identity: RuntimeIdentity{Name: "edge-a", Binary: "xray"},
		HostProcess: &HostProcessCandidate{
			PID:         1001,
			ConfigPaths: []string{configPath},
		},
	}
}

func testXrayEvidenceDockerTarget(t *testing.T, configPath string) RuntimeTarget {
	t.Helper()

	return RuntimeTarget{
		Source:   DiscoverySourceDockerContainer,
		Identity: RuntimeIdentity{Name: "raylimit-xray-test", Binary: "xray"},
		DockerContainer: &DockerContainerCandidate{
			ID:          "container-1",
			Name:        "raylimit-xray-test",
			ConfigPaths: []string{configPath},
		},
	}
}

func writeXrayAPIConfig(t *testing.T, body string) string {
	t.Helper()

	tempDir := t.TempDir()
	configPath := filepath.Join(tempDir, "config.json")
	if err := os.WriteFile(configPath, []byte(body), 0o644); err != nil {
		t.Fatalf("write config: %v", err)
	}

	return configPath
}

func testObservedSession() SessionEvidence {
	return SessionEvidence{
		Session: Session{
			ID:      "conn-1",
			Runtime: testXrayEvidenceRuntime(),
			Client: SessionClient{
				IP: "203.0.113.10",
			},
			Route: SessionRoute{
				InboundTag:  "api-in",
				OutboundTag: "proxy-out",
			},
		},
		Confidence: SessionEvidenceConfidenceHigh,
	}
}

func TestXraySessionEvidenceProviderReportsUnavailableWhenEndpointIsReachableButQueryFails(t *testing.T) {
	configPath := writeXrayAPIConfig(t, `{
  "api": {"tag":"api","services":["StatsService"]},
  "inbounds": [{"tag":"api","listen":"127.0.0.1","port":10085}]
}`)

	provider := NewXraySessionEvidenceProvider(stubRuntimeTargetDiscoverer{
		result: Result{
			Targets: []RuntimeTarget{testXrayEvidenceTarget(t, configPath)},
		},
	})
	provider.ProbeEndpoint = func(context.Context, APIEndpoint) error { return nil }
	provider.RunAPICommand = func(context.Context, string, string, ...string) ([]byte, error) {
		return nil, newXraySessionQueryError(SessionEvidenceIssueUnavailable, "Xray API command failed during test")
	}

	result, err := provider.ObserveSessions(context.Background(), testXrayEvidenceRuntime())
	if err != nil {
		t.Fatalf("expected observation to succeed, got %v", err)
	}

	if result.Provider != xraySessionEvidenceProviderName {
		t.Fatalf("unexpected provider name: %#v", result)
	}
	if result.State() != SessionEvidenceStateUnavailable {
		t.Fatalf("expected unavailable state, got %#v", result)
	}
	if len(result.Issues) != 1 || !strings.Contains(result.Issues[0].Message, "command failed") {
		t.Fatalf("unexpected issues: %#v", result.Issues)
	}
}

func TestXraySessionEvidenceProviderPrefersHostReachableEndpointForContainerizedHostProcess(t *testing.T) {
	target := RuntimeTarget{
		Source:   DiscoverySourceHostProcess,
		Identity: RuntimeIdentity{Name: "edge-a", Binary: "xray"},
		HostProcess: &HostProcessCandidate{
			PID:         1001,
			ContainerID: "container-1",
			ConfigPaths: []string{"/proc/1001/root/etc/xray/config.json"},
		},
		APICapability: &APICapability{
			Status: APICapabilityStatusLikelyConfigured,
			Reason: "Readable configuration hints define Xray API services and a matching inbound.",
		},
		APIEndpoints: []APIEndpoint{
			{
				Name:    "api",
				Network: EndpointNetworkTCP,
				Address: "127.0.0.1",
				Port:    10085,
			},
		},
		ReachableAPIEndpoints: []APIEndpoint{
			{
				Name:    "api",
				Network: EndpointNetworkTCP,
				Address: "127.0.0.1",
				Port:    11085,
			},
		},
	}

	provider := NewXraySessionEvidenceProvider(stubRuntimeTargetDiscoverer{
		result: Result{
			Targets: []RuntimeTarget{target},
		},
	})
	probed := APIEndpoint{}
	provider.ProbeEndpoint = func(_ context.Context, endpoint APIEndpoint) error {
		probed = endpoint
		return nil
	}
	provider.QuerySessions = func(context.Context, RuntimeTarget, APIEndpoint) ([]SessionEvidence, error) {
		return nil, nil
	}

	result, err := provider.ObserveSessions(context.Background(), testXrayEvidenceRuntime())
	if err != nil {
		t.Fatalf("expected observation to succeed, got %v", err)
	}

	if result.State() != SessionEvidenceStateNoSessions {
		t.Fatalf("expected no-sessions state, got %#v", result)
	}
	if probed.Port != 11085 {
		t.Fatalf("expected host-reachable endpoint to be probed, got %#v", probed)
	}
}

func TestXraySessionEvidenceProviderReportsInsufficientWhenContainerizedHostProcessHasOnlyRuntimeLocalEndpoint(t *testing.T) {
	target := RuntimeTarget{
		Source:   DiscoverySourceHostProcess,
		Identity: RuntimeIdentity{Name: "edge-a", Binary: "xray"},
		HostProcess: &HostProcessCandidate{
			PID:         1001,
			ContainerID: "container-1",
			ConfigPaths: []string{"/proc/1001/root/etc/xray/config.json"},
		},
		APICapability: &APICapability{
			Status: APICapabilityStatusLikelyConfigured,
			Reason: "Readable configuration hints define Xray API services and a matching inbound.",
		},
		APIEndpoints: []APIEndpoint{
			{
				Name:    "api",
				Network: EndpointNetworkTCP,
				Address: "127.0.0.1",
				Port:    10085,
			},
		},
	}

	provider := NewXraySessionEvidenceProvider(stubRuntimeTargetDiscoverer{
		result: Result{
			Targets: []RuntimeTarget{target},
		},
	})

	result, err := provider.ObserveSessions(context.Background(), testXrayEvidenceRuntime())
	if err != nil {
		t.Fatalf("expected observation to succeed, got %v", err)
	}

	if result.State() != SessionEvidenceStateInsufficient {
		t.Fatalf("expected insufficient state, got %#v", result)
	}
	if len(result.Issues) != 1 || !strings.Contains(result.Issues[0].Message, "only runtime-local API endpoint hints are available") {
		t.Fatalf("unexpected issues: %#v", result.Issues)
	}
}

func TestXraySessionEvidenceProviderUsesRoutingDerivedAPIEndpointHint(t *testing.T) {
	configPath := writeXrayAPIConfig(t, `{
  "api": {"tag":"api","services":["StatsService"]},
  "inbounds": [{"tag":"api-in","listen":"127.0.0.1","port":10085}],
  "routing": {
    "rules": [
      {
        "type": "field",
        "inboundTag": ["api-in"],
        "outboundTag": "api"
      }
    ]
  }
}`)

	provider := NewXraySessionEvidenceProvider(stubRuntimeTargetDiscoverer{
		result: Result{
			Targets: []RuntimeTarget{testXrayEvidenceTarget(t, configPath)},
		},
	})
	provider.ProbeEndpoint = func(context.Context, APIEndpoint) error { return nil }
	provider.QuerySessions = func(context.Context, RuntimeTarget, APIEndpoint) ([]SessionEvidence, error) {
		return nil, nil
	}

	result, err := provider.ObserveSessions(context.Background(), testXrayEvidenceRuntime())
	if err != nil {
		t.Fatalf("expected observation to succeed, got %v", err)
	}

	if result.State() != SessionEvidenceStateNoSessions {
		t.Fatalf("expected no-sessions state, got %#v", result)
	}
	if len(result.Issues) != 0 {
		t.Fatalf("expected no issues, got %#v", result.Issues)
	}
}

func TestXraySessionEvidenceProviderReturnsNoSessionsWhenQueryFindsNone(t *testing.T) {
	configPath := writeXrayAPIConfig(t, `{
  "api": {"tag":"api","services":["StatsService"]},
  "inbounds": [{"tag":"api","listen":"127.0.0.1","port":10085}]
}`)

	provider := NewXraySessionEvidenceProvider(stubRuntimeTargetDiscoverer{
		result: Result{
			Targets: []RuntimeTarget{testXrayEvidenceTarget(t, configPath)},
		},
	})
	provider.ProbeEndpoint = func(context.Context, APIEndpoint) error { return nil }
	provider.RunAPICommand = func(_ context.Context, _ string, command string, args ...string) ([]byte, error) {
		switch command {
		case "statsgetallonlineusers":
			return []byte(`{"users":[]}`), nil
		default:
			t.Fatalf("unexpected xray api command %q with args %#v", command, args)
			return nil, nil
		}
	}

	result, err := provider.ObserveSessions(context.Background(), testXrayEvidenceRuntime())
	if err != nil {
		t.Fatalf("expected observation to succeed, got %v", err)
	}

	if result.State() != SessionEvidenceStateNoSessions {
		t.Fatalf("expected no-sessions state, got %#v", result)
	}
	if len(result.Evidence) != 0 || len(result.Issues) != 0 {
		t.Fatalf("expected empty observation result, got %#v", result)
	}
}

func TestXraySessionEvidenceProviderQueriesContainerizedHostProcessViaContainerAPICommand(t *testing.T) {
	target := RuntimeTarget{
		Source:   DiscoverySourceHostProcess,
		Identity: RuntimeIdentity{Name: "edge-a", Binary: "xray"},
		HostProcess: &HostProcessCandidate{
			PID:         1001,
			ContainerID: "container-1",
			ConfigPaths: []string{"/proc/1001/root/etc/xray/config.json"},
		},
		APICapability: &APICapability{
			Status: APICapabilityStatusLikelyConfigured,
			Reason: "Readable configuration hints define Xray API services and a matching inbound.",
		},
		APIEndpoints: []APIEndpoint{
			{
				Name:    "api",
				Network: EndpointNetworkTCP,
				Address: "127.0.0.1",
				Port:    10085,
			},
		},
		ReachableAPIEndpoints: []APIEndpoint{
			{
				Name:    "api",
				Network: EndpointNetworkTCP,
				Address: "127.0.0.1",
				Port:    11085,
			},
		},
	}

	provider := NewXraySessionEvidenceProvider(stubRuntimeTargetDiscoverer{
		result: Result{
			Targets: []RuntimeTarget{target},
		},
	})
	provider.ProbeEndpoint = func(context.Context, APIEndpoint) error { return nil }
	provider.RunAPICommand = func(context.Context, string, string, ...string) ([]byte, error) {
		t.Fatal("expected host-side xray api command runner to remain unused for containerized host-process query")
		return nil, nil
	}
	provider.RunContainerAPICommand = func(_ context.Context, containerID string, server string, command string, args ...string) ([]byte, error) {
		if containerID != "container-1" {
			t.Fatalf("unexpected container id %q", containerID)
		}
		if server != "127.0.0.1:10085" {
			t.Fatalf("expected runtime-local container api endpoint, got %q", server)
		}
		switch command {
		case "statsgetallonlineusers":
			return []byte(`{"users":["user-a"]}`), nil
		case "statsonlineiplist":
			if len(args) != 2 || args[0] != "-email" || args[1] != "user-a" {
				t.Fatalf("unexpected statsonlineiplist args %#v", args)
			}
			return []byte(`{"name":"user>>>user-a>>>online","ips":{"203.0.113.10":1710000000}}`), nil
		default:
			t.Fatalf("unexpected xray api command %q with args %#v", command, args)
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
	if len(result.Evidence) != 1 {
		t.Fatalf("expected one observed session, got %#v", result)
	}
	if result.Evidence[0].Session.Client.IP != "203.0.113.10" {
		t.Fatalf("expected live client ip evidence, got %#v", result.Evidence[0])
	}
}

func TestXraySessionEvidenceProviderReportsContainerAPIQueryPermissionDenied(t *testing.T) {
	target := RuntimeTarget{
		Source:   DiscoverySourceHostProcess,
		Identity: RuntimeIdentity{Name: "edge-a", Binary: "xray"},
		HostProcess: &HostProcessCandidate{
			PID:         1001,
			ContainerID: "container-1",
			ConfigPaths: []string{"/proc/1001/root/etc/xray/config.json"},
		},
		APICapability: &APICapability{
			Status: APICapabilityStatusLikelyConfigured,
			Reason: "Readable configuration hints define Xray API services and a matching inbound.",
		},
		APIEndpoints: []APIEndpoint{
			{
				Name:    "api",
				Network: EndpointNetworkTCP,
				Address: "127.0.0.1",
				Port:    10085,
			},
		},
		ReachableAPIEndpoints: []APIEndpoint{
			{
				Name:    "api",
				Network: EndpointNetworkTCP,
				Address: "127.0.0.1",
				Port:    11085,
			},
		},
	}

	provider := NewXraySessionEvidenceProvider(stubRuntimeTargetDiscoverer{
		result: Result{
			Targets: []RuntimeTarget{target},
		},
	})
	provider.ProbeEndpoint = func(context.Context, APIEndpoint) error { return nil }
	provider.RunContainerAPICommand = func(context.Context, string, string, string, ...string) ([]byte, error) {
		return nil, newXraySessionQueryError(SessionEvidenceIssuePermissionDenied, "Xray API command access was denied inside the container")
	}

	result, err := provider.ObserveSessions(context.Background(), testXrayEvidenceRuntime())
	if err != nil {
		t.Fatalf("expected observation to succeed, got %v", err)
	}

	if result.State() != SessionEvidenceStateUnavailable {
		t.Fatalf("expected unavailable state, got %#v", result)
	}
	if len(result.Issues) != 1 || result.Issues[0].Code != SessionEvidenceIssuePermissionDenied {
		t.Fatalf("unexpected issues: %#v", result.Issues)
	}
}

func TestXraySessionEvidenceProviderReturnsObservedSessionsFromOnlineIPEvidence(t *testing.T) {
	configPath := writeXrayAPIConfig(t, `{
  "api": {"tag":"api","services":["StatsService"]},
  "inbounds": [{"tag":"api","listen":"127.0.0.1","port":10085}]
}`)

	provider := NewXraySessionEvidenceProvider(stubRuntimeTargetDiscoverer{
		result: Result{
			Targets: []RuntimeTarget{testXrayEvidenceTarget(t, configPath)},
		},
	})
	provider.ProbeEndpoint = func(context.Context, APIEndpoint) error { return nil }
	provider.RunAPICommand = func(_ context.Context, _ string, command string, args ...string) ([]byte, error) {
		switch command {
		case "statsgetallonlineusers":
			return []byte(`{"users":["user-a"]}`), nil
		case "statsonlineiplist":
			if len(args) != 2 || args[0] != "-email" || args[1] != "user-a" {
				t.Fatalf("unexpected statsonlineiplist args %#v", args)
			}
			return []byte(`{"name":"user>>>user-a>>>online","ips":{"203.0.113.10":1710000000}}`), nil
		default:
			t.Fatalf("unexpected xray api command %q with args %#v", command, args)
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
	if len(result.Evidence) != 1 {
		t.Fatalf("expected one observed session, got %#v", result)
	}
	if !IsXrayOnlineIPSessionID(result.Evidence[0].Session.ID) {
		t.Fatalf("expected synthetic online-ip session id, got %#v", result.Evidence[0])
	}
	if result.Evidence[0].Session.Client.IP != "203.0.113.10" {
		t.Fatalf("expected client ip evidence to be preserved, got %#v", result.Evidence[0])
	}
	if result.Evidence[0].Runtime.HostPID != 1001 {
		t.Fatalf("expected runtime association to be normalized, got %#v", result.Evidence[0])
	}
}

func TestXraySessionEvidenceProviderFlagsInvalidQueryEvidence(t *testing.T) {
	configPath := writeXrayAPIConfig(t, `{
  "api": {"tag":"api","services":["StatsService"]},
  "inbounds": [{"tag":"api","listen":"127.0.0.1","port":10085}]
}`)

	provider := NewXraySessionEvidenceProvider(stubRuntimeTargetDiscoverer{
		result: Result{
			Targets: []RuntimeTarget{testXrayEvidenceTarget(t, configPath)},
		},
	})
	provider.ProbeEndpoint = func(context.Context, APIEndpoint) error { return nil }
	provider.RunAPICommand = func(_ context.Context, _ string, command string, args ...string) ([]byte, error) {
		switch command {
		case "statsgetallonlineusers":
			return []byte(`{"users":["user-a"]}`), nil
		case "statsonlineiplist":
			return []byte(`{"name":"user>>>user-a>>>online","ips":{"203.0.113.10":1710000000,"not-an-ip":1710000001}}`), nil
		default:
			t.Fatalf("unexpected xray api command %q with args %#v", command, args)
			return nil, nil
		}
	}

	result, err := provider.ObserveSessions(context.Background(), testXrayEvidenceRuntime())
	if err != nil {
		t.Fatalf("expected observation to succeed, got %v", err)
	}

	if result.State() != SessionEvidenceStateAvailable {
		t.Fatalf("expected available state with valid evidence preserved, got %#v", result)
	}
	if len(result.Evidence) != 1 {
		t.Fatalf("expected one valid evidence entry, got %#v", result)
	}
	if len(result.Issues) != 1 || result.Issues[0].Code != SessionEvidenceIssueInsufficient {
		t.Fatalf("expected insufficient issue for invalid evidence, got %#v", result.Issues)
	}
}

func TestXraySessionEvidenceProviderReturnsMultipleObservedSessionsFromOnlineIPs(t *testing.T) {
	configPath := writeXrayAPIConfig(t, `{
  "api": {"tag":"api","services":["StatsService"]},
  "inbounds": [{"tag":"api","listen":"127.0.0.1","port":10085}]
}`)

	provider := NewXraySessionEvidenceProvider(stubRuntimeTargetDiscoverer{
		result: Result{
			Targets: []RuntimeTarget{testXrayEvidenceTarget(t, configPath)},
		},
	})
	provider.ProbeEndpoint = func(context.Context, APIEndpoint) error { return nil }
	provider.RunAPICommand = func(_ context.Context, _ string, command string, args ...string) ([]byte, error) {
		switch command {
		case "statsgetallonlineusers":
			return []byte(`{"users":["user-b","user-a"]}`), nil
		case "statsonlineiplist":
			if len(args) != 2 || args[0] != "-email" {
				t.Fatalf("unexpected statsonlineiplist args %#v", args)
			}
			switch args[1] {
			case "user-a":
				return []byte(`{"name":"user>>>user-a>>>online","ips":{"203.0.113.10":1710000000}}`), nil
			case "user-b":
				return []byte(`{"name":"user>>>user-b>>>online","ips":{"203.0.113.11":1710000001,"203.0.113.12":1710000002}}`), nil
			default:
				t.Fatalf("unexpected statsonlineiplist email %q", args[1])
				return nil, nil
			}
		default:
			t.Fatalf("unexpected xray api command %q with args %#v", command, args)
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
	if len(result.Evidence) != 3 {
		t.Fatalf("expected three observed sessions, got %#v", result)
	}
	if result.Evidence[0].Session.ID != "xray-online-ip:user-a:203.0.113.10" ||
		result.Evidence[1].Session.ID != "xray-online-ip:user-b:203.0.113.11" ||
		result.Evidence[2].Session.ID != "xray-online-ip:user-b:203.0.113.12" {
		t.Fatalf("expected deterministic evidence ordering, got %#v", result.Evidence)
	}
}

func TestXraySessionEvidenceProviderReportsInsufficientWhenOnlineUserHasNoIPEntries(t *testing.T) {
	configPath := writeXrayAPIConfig(t, `{
  "api": {"tag":"api","services":["StatsService"]},
  "inbounds": [{"tag":"api","listen":"127.0.0.1","port":10085}]
}`)

	provider := NewXraySessionEvidenceProvider(stubRuntimeTargetDiscoverer{
		result: Result{
			Targets: []RuntimeTarget{testXrayEvidenceTarget(t, configPath)},
		},
	})
	provider.ProbeEndpoint = func(context.Context, APIEndpoint) error { return nil }
	provider.RunAPICommand = func(_ context.Context, _ string, command string, args ...string) ([]byte, error) {
		switch command {
		case "statsgetallonlineusers":
			return []byte(`{"users":["user-a"]}`), nil
		case "statsonlineiplist":
			return []byte(`{"name":"user>>>user-a>>>online","ips":{}}`), nil
		default:
			t.Fatalf("unexpected xray api command %q with args %#v", command, args)
			return nil, nil
		}
	}

	result, err := provider.ObserveSessions(context.Background(), testXrayEvidenceRuntime())
	if err != nil {
		t.Fatalf("expected observation to succeed, got %v", err)
	}

	if result.State() != SessionEvidenceStateInsufficient {
		t.Fatalf("expected insufficient state, got %#v", result)
	}
	if len(result.Issues) != 1 || result.Issues[0].Code != SessionEvidenceIssueInsufficient {
		t.Fatalf("expected insufficient issue, got %#v", result.Issues)
	}
	if !strings.Contains(result.Issues[0].Message, "no live client IP evidence") {
		t.Fatalf("expected issue to mention missing online ip evidence, got %#v", result.Issues)
	}
}

func TestXraySessionEvidenceProviderReportsUnavailableWhenAPINotEvident(t *testing.T) {
	configPath := writeXrayAPIConfig(t, `{"inbounds":[{"tag":"socks","listen":"127.0.0.1","port":1080}]}`)

	provider := NewXraySessionEvidenceProvider(stubRuntimeTargetDiscoverer{
		result: Result{
			Targets: []RuntimeTarget{testXrayEvidenceTarget(t, configPath)},
		},
	})

	result, err := provider.ObserveSessions(context.Background(), testXrayEvidenceRuntime())
	if err != nil {
		t.Fatalf("expected observation to succeed, got %v", err)
	}

	if result.State() != SessionEvidenceStateUnavailable {
		t.Fatalf("expected unavailable state, got %#v", result)
	}
	if len(result.Issues) != 1 || !strings.Contains(result.Issues[0].Message, "No Xray API capability was evident") {
		t.Fatalf("unexpected issues: %#v", result.Issues)
	}
}

func TestXraySessionEvidenceProviderReportsPermissionDeniedWhenAPICapabilityIsUnknownDueToUnreadableConfig(t *testing.T) {
	target := RuntimeTarget{
		Source:   DiscoverySourceHostProcess,
		Identity: RuntimeIdentity{Name: "edge-a", Binary: "xray"},
		HostProcess: &HostProcessCandidate{
			PID:         1001,
			ConfigPaths: []string{"/etc/xray/config.json"},
		},
		APICapability: &APICapability{
			Status:     APICapabilityStatusUnknown,
			Limitation: APICapabilityLimitationPermissionDenied,
			Reason:     "API capability is unknown because access to Xray configuration hints was denied for /etc/xray/config.json. Run RayLimit as root or make the configuration readable.",
		},
	}

	provider := NewXraySessionEvidenceProvider(stubRuntimeTargetDiscoverer{
		result: Result{
			Targets: []RuntimeTarget{target},
		},
	})

	result, err := provider.ObserveSessions(context.Background(), testXrayEvidenceRuntime())
	if err != nil {
		t.Fatalf("expected observation to succeed, got %v", err)
	}

	if result.State() != SessionEvidenceStateUnavailable {
		t.Fatalf("expected unavailable state, got %#v", result)
	}
	if len(result.Issues) != 1 || result.Issues[0].Code != SessionEvidenceIssuePermissionDenied {
		t.Fatalf("unexpected issues: %#v", result.Issues)
	}
	if !strings.Contains(result.Issues[0].Message, "/etc/xray/config.json") {
		t.Fatalf("expected issue to mention unreadable config path, got %#v", result.Issues)
	}
}

func TestXraySessionEvidenceProviderReportsInsufficientWhenAPICapabilityPointsToMissingConfigPath(t *testing.T) {
	target := RuntimeTarget{
		Source:   DiscoverySourceHostProcess,
		Identity: RuntimeIdentity{Name: "edge-a", Binary: "xray"},
		HostProcess: &HostProcessCandidate{
			PID:         1001,
			ConfigPaths: []string{"/etc/xray/config.json"},
		},
		APICapability: &APICapability{
			Status:     APICapabilityStatusUnknown,
			Limitation: APICapabilityLimitationMissingConfigPath,
			Reason:     "API capability is unknown because Xray configuration hints pointed to missing paths: /etc/xray/config.json.",
		},
	}

	provider := NewXraySessionEvidenceProvider(stubRuntimeTargetDiscoverer{
		result: Result{
			Targets: []RuntimeTarget{target},
		},
	})

	result, err := provider.ObserveSessions(context.Background(), testXrayEvidenceRuntime())
	if err != nil {
		t.Fatalf("expected observation to succeed, got %v", err)
	}

	if result.State() != SessionEvidenceStateInsufficient {
		t.Fatalf("expected insufficient state, got %#v", result)
	}
	if len(result.Issues) != 1 || result.Issues[0].Code != SessionEvidenceIssueInsufficient {
		t.Fatalf("unexpected issues: %#v", result.Issues)
	}
	if !strings.Contains(result.Issues[0].Message, "missing paths") {
		t.Fatalf("expected issue to mention missing config path, got %#v", result.Issues)
	}
}

func TestXraySessionEvidenceProviderReportsPermissionDeniedProbeFailures(t *testing.T) {
	configPath := writeXrayAPIConfig(t, `{
  "api": {"tag":"api","services":["StatsService"]},
  "inbounds": [{"tag":"api","listen":"127.0.0.1","port":10085}]
}`)

	provider := NewXraySessionEvidenceProvider(stubRuntimeTargetDiscoverer{
		result: Result{
			Targets: []RuntimeTarget{testXrayEvidenceTarget(t, configPath)},
		},
	})
	provider.ProbeEndpoint = func(context.Context, APIEndpoint) error {
		return fsPermissionError()
	}

	result, err := provider.ObserveSessions(context.Background(), testXrayEvidenceRuntime())
	if err != nil {
		t.Fatalf("expected observation to succeed, got %v", err)
	}

	if result.State() != SessionEvidenceStateUnavailable {
		t.Fatalf("expected unavailable state, got %#v", result)
	}
	if len(result.Issues) != 1 || result.Issues[0].Code != SessionEvidenceIssuePermissionDenied {
		t.Fatalf("unexpected issues: %#v", result.Issues)
	}
}

func TestXraySessionEvidenceProviderReportsUnavailableWhenRuntimeCannotBeResolved(t *testing.T) {
	provider := NewXraySessionEvidenceProvider(stubRuntimeTargetDiscoverer{
		result: Result{},
	})

	result, err := provider.ObserveSessions(context.Background(), testXrayEvidenceRuntime())
	if err != nil {
		t.Fatalf("expected observation to succeed, got %v", err)
	}

	if result.State() != SessionEvidenceStateUnavailable {
		t.Fatalf("expected unavailable state, got %#v", result)
	}
	if len(result.Issues) != 1 || !strings.Contains(result.Issues[0].Message, "no matching discovered runtime target") {
		t.Fatalf("unexpected issues: %#v", result.Issues)
	}
}

func TestXraySessionEvidenceProviderReportsNoSessionsForDockerRuntimeWhenEndpointIsReachable(t *testing.T) {
	configPath := writeXrayAPIConfig(t, `{
  "api": {"tag":"api","services":["StatsService"]},
  "inbounds": [{"tag":"api","listen":"127.0.0.1","port":10085}]
}`)

	provider := NewXraySessionEvidenceProvider(stubRuntimeTargetDiscoverer{
		result: Result{
			Targets: []RuntimeTarget{testXrayEvidenceDockerTarget(t, configPath)},
		},
	})
	provider.APIDetector.inspectDocker = stubDockerInspectWithPublishedAPIPort()
	provider.ProbeEndpoint = func(context.Context, APIEndpoint) error { return nil }
	provider.QuerySessions = func(context.Context, RuntimeTarget, APIEndpoint) ([]SessionEvidence, error) {
		return nil, nil
	}

	result, err := provider.ObserveSessions(context.Background(), testXrayEvidenceDockerRuntime())
	if err != nil {
		t.Fatalf("expected observation to succeed, got %v", err)
	}

	if result.Provider != xraySessionEvidenceProviderName {
		t.Fatalf("unexpected provider name: %#v", result)
	}
	if result.State() != SessionEvidenceStateNoSessions {
		t.Fatalf("expected no-sessions state, got %#v", result)
	}
	if len(result.Issues) != 0 {
		t.Fatalf("expected no issues, got %#v", result.Issues)
	}
}

func TestXraySessionEvidenceProviderReturnsObservedSessionsForDockerRuntime(t *testing.T) {
	configPath := writeXrayAPIConfig(t, `{
  "api": {"tag":"api","services":["StatsService"]},
  "inbounds": [{"tag":"api","listen":"127.0.0.1","port":10085}]
}`)

	provider := NewXraySessionEvidenceProvider(stubRuntimeTargetDiscoverer{
		result: Result{
			Targets: []RuntimeTarget{testXrayEvidenceDockerTarget(t, configPath)},
		},
	})
	provider.APIDetector.inspectDocker = stubDockerInspectWithPublishedAPIPort()
	provider.ProbeEndpoint = func(context.Context, APIEndpoint) error { return nil }
	provider.QuerySessions = func(context.Context, RuntimeTarget, APIEndpoint) ([]SessionEvidence, error) {
		observed := testObservedSession()
		observed.Runtime = testXrayEvidenceDockerRuntime()
		observed.Session.Runtime = testXrayEvidenceDockerRuntime()
		return []SessionEvidence{observed}, nil
	}

	result, err := provider.ObserveSessions(context.Background(), testXrayEvidenceDockerRuntime())
	if err != nil {
		t.Fatalf("expected observation to succeed, got %v", err)
	}

	if result.State() != SessionEvidenceStateAvailable {
		t.Fatalf("expected available state, got %#v", result)
	}
	if len(result.Evidence) != 1 {
		t.Fatalf("expected one observed session, got %#v", result)
	}
	if result.Evidence[0].Runtime.ContainerID != "container-1" {
		t.Fatalf("expected docker runtime association to be preserved, got %#v", result.Evidence[0])
	}
	if result.Evidence[0].Session.Client.IP != "203.0.113.10" {
		t.Fatalf("expected client ip evidence to be preserved, got %#v", result.Evidence[0])
	}
}

func fsPermissionError() error {
	return &os.PathError{Op: "dial", Path: "/var/run/xray.sock", Err: os.ErrPermission}
}

func stubDockerInspectWithPublishedAPIPort() dockerInspectFunc {
	return func(context.Context, []string) (map[string]dockerContainerInspect, error) {
		return map[string]dockerContainerInspect{
			"container-1": {
				ID: "container-1",
				Ports: []dockerPortBinding{
					{
						ContainerPort: 10085,
						Protocol:      "tcp",
						HostIP:        "127.0.0.1",
						HostPort:      11085,
					},
				},
			},
		}, nil
	}
}
