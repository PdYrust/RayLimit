package discovery

import (
	"context"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestAPICapabilityDetectorMarksUnknownWhenNoConfigHintExists(t *testing.T) {
	target := RuntimeTarget{
		Source:      DiscoverySourceHostProcess,
		Identity:    RuntimeIdentity{Name: "edge-a", Binary: "xray"},
		HostProcess: &HostProcessCandidate{PID: 1001},
	}

	enriched, err := NewAPICapabilityDetector().EnrichTarget(context.Background(), target)
	if err != nil {
		t.Fatalf("expected nil error, got %v", err)
	}

	if enriched.APICapability == nil {
		t.Fatal("expected api capability to be populated")
	}

	if enriched.APICapability.Status != APICapabilityStatusUnknown {
		t.Fatalf("expected unknown api capability, got %#v", enriched.APICapability)
	}
	if enriched.APICapability.Limitation != APICapabilityLimitationMissingConfigHint {
		t.Fatalf("expected missing-config-hint limitation, got %#v", enriched.APICapability)
	}
}

func TestAPICapabilityDetectorMarksUnknownWhenConfigIsUnreadable(t *testing.T) {
	tempDir := t.TempDir()
	configPath := filepath.Join(tempDir, "config.json")
	if err := os.WriteFile(configPath, []byte(`{}`), 0o644); err != nil {
		t.Fatalf("write config: %v", err)
	}

	info, err := os.Stat(configPath)
	if err != nil {
		t.Fatalf("stat config: %v", err)
	}

	detector := APICapabilityDetector{
		readFile: func(string) ([]byte, error) {
			return nil, fs.ErrPermission
		},
		readDir: os.ReadDir,
		statPath: func(string) (os.FileInfo, error) {
			return info, nil
		},
	}

	target := RuntimeTarget{
		Source:   DiscoverySourceHostProcess,
		Identity: RuntimeIdentity{Name: "edge-a", Binary: "xray"},
		HostProcess: &HostProcessCandidate{
			PID:         1001,
			ConfigPaths: []string{configPath},
		},
	}

	enriched, err := detector.EnrichTarget(context.Background(), target)
	if err != nil {
		t.Fatalf("expected nil error, got %v", err)
	}

	if enriched.APICapability == nil || enriched.APICapability.Status != APICapabilityStatusUnknown {
		t.Fatalf("expected unknown api capability, got %#v", enriched.APICapability)
	}

	if enriched.APICapability.Limitation != APICapabilityLimitationPermissionDenied {
		t.Fatalf("expected permission-denied api capability limitation, got %#v", enriched.APICapability)
	}
	if !strings.Contains(enriched.APICapability.Reason, configPath) {
		t.Fatalf("expected api capability reason to mention unreadable config path, got %#v", enriched.APICapability)
	}
	if !strings.Contains(enriched.APICapability.Reason, "Run RayLimit as root") {
		t.Fatalf("unexpected api capability reason: %#v", enriched.APICapability)
	}
}

func TestAPICapabilityDetectorDetectsAPIFromReadableConfig(t *testing.T) {
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

	target := RuntimeTarget{
		Source:   DiscoverySourceHostProcess,
		Identity: RuntimeIdentity{Name: "edge-a", Binary: "xray"},
		HostProcess: &HostProcessCandidate{
			PID:         1001,
			ConfigPaths: []string{configPath},
		},
	}

	enriched, err := NewAPICapabilityDetector().EnrichTarget(context.Background(), target)
	if err != nil {
		t.Fatalf("expected nil error, got %v", err)
	}

	if enriched.APICapability == nil || enriched.APICapability.Status != APICapabilityStatusLikelyConfigured {
		t.Fatalf("expected likely configured api capability, got %#v", enriched.APICapability)
	}

	if len(enriched.APIEndpoints) != 1 {
		t.Fatalf("expected 1 api endpoint, got %#v", enriched.APIEndpoints)
	}

	if enriched.APIEndpoints[0].Address != "127.0.0.1" || enriched.APIEndpoints[0].Port != 10085 {
		t.Fatalf("unexpected api endpoint: %#v", enriched.APIEndpoints[0])
	}
}

func TestAPICapabilityDetectorUsesResolvedHostProcessConfigHints(t *testing.T) {
	tempDir := t.TempDir()
	resolvedConfigPath := filepath.Join(tempDir, "proc", "1001", "root", "etc", "xray", "config.json")
	if err := os.MkdirAll(filepath.Dir(resolvedConfigPath), 0o755); err != nil {
		t.Fatalf("create config parent: %v", err)
	}

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
	if err := os.WriteFile(resolvedConfigPath, []byte(config), 0o644); err != nil {
		t.Fatalf("write config: %v", err)
	}

	target := RuntimeTarget{
		Source:   DiscoverySourceHostProcess,
		Identity: RuntimeIdentity{Name: "edge-a", Binary: "xray"},
		HostProcess: &HostProcessCandidate{
			PID:                 1001,
			ConfigPaths:         []string{"/etc/xray/config.json"},
			ResolvedConfigPaths: []string{resolvedConfigPath},
		},
	}

	enriched, err := NewAPICapabilityDetector().EnrichTarget(context.Background(), target)
	if err != nil {
		t.Fatalf("expected nil error, got %v", err)
	}

	if enriched.APICapability == nil || enriched.APICapability.Status != APICapabilityStatusLikelyConfigured {
		t.Fatalf("expected likely configured api capability, got %#v", enriched.APICapability)
	}
	if len(enriched.APIEndpoints) != 1 || enriched.APIEndpoints[0].Port != 10085 {
		t.Fatalf("unexpected api endpoints: %#v", enriched.APIEndpoints)
	}
}

func TestAPICapabilityDetectorMapsContainerizedHostProcessAPIEndpointToPublishedHostPort(t *testing.T) {
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

	detector := APICapabilityDetector{
		readFile: os.ReadFile,
		readDir:  os.ReadDir,
		statPath: os.Stat,
		inspectDocker: func(context.Context, []string) (map[string]dockerContainerInspect, error) {
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
		},
	}

	target := RuntimeTarget{
		Source:   DiscoverySourceHostProcess,
		Identity: RuntimeIdentity{Name: "edge-a", Binary: "xray"},
		HostProcess: &HostProcessCandidate{
			PID:         1001,
			ContainerID: "container-1",
			ConfigPaths: []string{configPath},
		},
	}

	enriched, err := detector.EnrichTarget(context.Background(), target)
	if err != nil {
		t.Fatalf("expected nil error, got %v", err)
	}

	if len(enriched.APIEndpoints) != 1 || enriched.APIEndpoints[0].Port != 10085 {
		t.Fatalf("unexpected internal api endpoints: %#v", enriched.APIEndpoints)
	}
	if len(enriched.ReachableAPIEndpoints) != 1 {
		t.Fatalf("expected 1 host-reachable api endpoint, got %#v", enriched.ReachableAPIEndpoints)
	}
	if enriched.ReachableAPIEndpoints[0].Address != "127.0.0.1" || enriched.ReachableAPIEndpoints[0].Port != 11085 {
		t.Fatalf("unexpected host-reachable api endpoint: %#v", enriched.ReachableAPIEndpoints[0])
	}
}

func TestAPICapabilityDetectorLeavesContainerizedHostProcessWithoutReachableEndpointWhenPortMappingIsUnavailable(t *testing.T) {
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

	detector := APICapabilityDetector{
		readFile: os.ReadFile,
		readDir:  os.ReadDir,
		statPath: os.Stat,
		inspectDocker: func(context.Context, []string) (map[string]dockerContainerInspect, error) {
			return map[string]dockerContainerInspect{}, nil
		},
	}

	target := RuntimeTarget{
		Source:   DiscoverySourceHostProcess,
		Identity: RuntimeIdentity{Name: "edge-a", Binary: "xray"},
		HostProcess: &HostProcessCandidate{
			PID:         1001,
			ContainerID: "container-1",
			ConfigPaths: []string{configPath},
		},
	}

	enriched, err := detector.EnrichTarget(context.Background(), target)
	if err != nil {
		t.Fatalf("expected nil error, got %v", err)
	}

	if len(enriched.APIEndpoints) != 1 || enriched.APIEndpoints[0].Port != 10085 {
		t.Fatalf("unexpected internal api endpoints: %#v", enriched.APIEndpoints)
	}
	if len(enriched.ReachableAPIEndpoints) != 0 {
		t.Fatalf("expected no host-reachable api endpoints, got %#v", enriched.ReachableAPIEndpoints)
	}
}

func TestAPICapabilityDetectorDerivesAPIEndpointFromRoutingRule(t *testing.T) {
	tempDir := t.TempDir()
	configPath := filepath.Join(tempDir, "config.json")
	config := `{
  "api": {
    "tag": "api",
    "services": ["StatsService"]
  },
  "inbounds": [
    {
      "tag": "api-in",
      "listen": "127.0.0.1",
      "port": 10085
    }
  ],
  "routing": {
    "rules": [
      {
        "type": "field",
        "inboundTag": ["api-in"],
        "outboundTag": "api"
      }
    ]
  }
}`
	if err := os.WriteFile(configPath, []byte(config), 0o644); err != nil {
		t.Fatalf("write config: %v", err)
	}

	target := RuntimeTarget{
		Source:   DiscoverySourceHostProcess,
		Identity: RuntimeIdentity{Name: "edge-a", Binary: "xray"},
		HostProcess: &HostProcessCandidate{
			PID:         1001,
			ConfigPaths: []string{configPath},
		},
	}

	enriched, err := NewAPICapabilityDetector().EnrichTarget(context.Background(), target)
	if err != nil {
		t.Fatalf("expected nil error, got %v", err)
	}

	if enriched.APICapability == nil || enriched.APICapability.Status != APICapabilityStatusLikelyConfigured {
		t.Fatalf("expected likely configured api capability, got %#v", enriched.APICapability)
	}
	if !strings.Contains(enriched.APICapability.Reason, "routing-assisted API inbound") {
		t.Fatalf("unexpected api capability reason: %#v", enriched.APICapability)
	}
	if len(enriched.APIEndpoints) != 1 {
		t.Fatalf("expected 1 api endpoint, got %#v", enriched.APIEndpoints)
	}
	if enriched.APIEndpoints[0].Name != "api-in" || enriched.APIEndpoints[0].Address != "127.0.0.1" || enriched.APIEndpoints[0].Port != 10085 {
		t.Fatalf("unexpected api endpoint: %#v", enriched.APIEndpoints[0])
	}
}

func TestAPICapabilityDetectorMarksNotEvidentWhenReadableConfigHasNoAPI(t *testing.T) {
	tempDir := t.TempDir()
	configPath := filepath.Join(tempDir, "config.json")
	config := `{
  "inbounds": [
    {
      "tag": "socks-in",
      "listen": "127.0.0.1",
      "port": 1080
    }
  ]
}`
	if err := os.WriteFile(configPath, []byte(config), 0o644); err != nil {
		t.Fatalf("write config: %v", err)
	}

	target := RuntimeTarget{
		Source:   DiscoverySourceHostProcess,
		Identity: RuntimeIdentity{Name: "edge-a", Binary: "xray"},
		HostProcess: &HostProcessCandidate{
			PID:         1001,
			ConfigPaths: []string{configPath},
		},
	}

	enriched, err := NewAPICapabilityDetector().EnrichTarget(context.Background(), target)
	if err != nil {
		t.Fatalf("expected nil error, got %v", err)
	}

	if enriched.APICapability == nil || enriched.APICapability.Status != APICapabilityStatusNotEvident {
		t.Fatalf("expected not_evident api capability, got %#v", enriched.APICapability)
	}

	if len(enriched.APIEndpoints) != 0 {
		t.Fatalf("expected no api endpoints, got %#v", enriched.APIEndpoints)
	}
}

func TestAPICapabilityDetectorLeavesAPIEndpointUnknownWhenRoutingDoesNotReachAPITag(t *testing.T) {
	tempDir := t.TempDir()
	configPath := filepath.Join(tempDir, "config.json")
	config := `{
  "api": {
    "tag": "api",
    "services": ["StatsService"]
  },
  "inbounds": [
    {
      "tag": "api-in",
      "listen": "127.0.0.1",
      "port": 10085
    }
  ],
  "routing": {
    "rules": [
      {
        "type": "field",
        "inboundTag": ["api-in"],
        "outboundTag": "direct"
      }
    ]
  }
}`
	if err := os.WriteFile(configPath, []byte(config), 0o644); err != nil {
		t.Fatalf("write config: %v", err)
	}

	target := RuntimeTarget{
		Source:   DiscoverySourceHostProcess,
		Identity: RuntimeIdentity{Name: "edge-a", Binary: "xray"},
		HostProcess: &HostProcessCandidate{
			PID:         1001,
			ConfigPaths: []string{configPath},
		},
	}

	enriched, err := NewAPICapabilityDetector().EnrichTarget(context.Background(), target)
	if err != nil {
		t.Fatalf("expected nil error, got %v", err)
	}

	if enriched.APICapability == nil || enriched.APICapability.Status != APICapabilityStatusLikelyConfigured {
		t.Fatalf("expected likely configured api capability, got %#v", enriched.APICapability)
	}
	if !strings.Contains(enriched.APICapability.Reason, "no API inbound was evident") {
		t.Fatalf("unexpected api capability reason: %#v", enriched.APICapability)
	}
	if len(enriched.APIEndpoints) != 0 {
		t.Fatalf("expected no api endpoints, got %#v", enriched.APIEndpoints)
	}
}

func TestAPICapabilityDetectorReturnsUnknownForPartialConfigHints(t *testing.T) {
	tempDir := t.TempDir()
	readablePath := filepath.Join(tempDir, "10_base.json")
	if err := os.WriteFile(readablePath, []byte(`{"inbounds":[{"tag":"socks","listen":"127.0.0.1","port":1080}]}`), 0o644); err != nil {
		t.Fatalf("write config: %v", err)
	}

	target := RuntimeTarget{
		Source:   DiscoverySourceHostProcess,
		Identity: RuntimeIdentity{Name: "edge-a", Binary: "xray"},
		HostProcess: &HostProcessCandidate{
			PID:         1001,
			ConfigPaths: []string{readablePath, filepath.Join(tempDir, "missing.json")},
		},
	}

	enriched, err := NewAPICapabilityDetector().EnrichTarget(context.Background(), target)
	if err != nil {
		t.Fatalf("expected nil error, got %v", err)
	}

	if enriched.APICapability == nil || enriched.APICapability.Status != APICapabilityStatusUnknown {
		t.Fatalf("expected unknown api capability, got %#v", enriched.APICapability)
	}
	if enriched.APICapability.Limitation != APICapabilityLimitationMissingConfigPath {
		t.Fatalf("expected missing-config-path api capability limitation, got %#v", enriched.APICapability)
	}
	if !strings.Contains(enriched.APICapability.Reason, "missing paths") {
		t.Fatalf("unexpected api capability reason: %#v", enriched.APICapability)
	}
}

func TestAPICapabilityDetectorAggregatesConfigDirectoryHints(t *testing.T) {
	tempDir := t.TempDir()
	configDir := filepath.Join(tempDir, "confdir")
	if err := os.MkdirAll(configDir, 0o755); err != nil {
		t.Fatalf("create config dir: %v", err)
	}

	if err := os.WriteFile(filepath.Join(configDir, "10_api.json"), []byte(`{"api":{"tag":"api","services":["StatsService"]}}`), 0o644); err != nil {
		t.Fatalf("write api config: %v", err)
	}
	if err := os.WriteFile(filepath.Join(configDir, "20_inbounds.json"), []byte(`{"inbounds":[{"tag":"api","listen":"127.0.0.1","port":10085}]}`), 0o644); err != nil {
		t.Fatalf("write inbound config: %v", err)
	}

	target := RuntimeTarget{
		Source:   DiscoverySourceHostProcess,
		Identity: RuntimeIdentity{Name: "edge-a", Binary: "xray"},
		HostProcess: &HostProcessCandidate{
			PID:         1001,
			ConfigPaths: []string{configDir},
		},
	}

	enriched, err := NewAPICapabilityDetector().EnrichTarget(context.Background(), target)
	if err != nil {
		t.Fatalf("expected nil error, got %v", err)
	}

	if enriched.APICapability == nil || enriched.APICapability.Status != APICapabilityStatusLikelyConfigured {
		t.Fatalf("expected likely configured api capability, got %#v", enriched.APICapability)
	}

	if len(enriched.APIEndpoints) != 1 || enriched.APIEndpoints[0].Port != 10085 {
		t.Fatalf("unexpected api endpoints: %#v", enriched.APIEndpoints)
	}
}

func TestAPICapabilityDetectorDetectsAPIFromDockerConfigHints(t *testing.T) {
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

	target := RuntimeTarget{
		Source:   DiscoverySourceDockerContainer,
		Identity: RuntimeIdentity{Name: "raylimit-xray-test", Binary: "xray"},
		DockerContainer: &DockerContainerCandidate{
			ID:          "container-1",
			Name:        "raylimit-xray-test",
			ConfigPaths: []string{configPath},
		},
	}

	enriched, err := NewAPICapabilityDetector().EnrichTarget(context.Background(), target)
	if err != nil {
		t.Fatalf("expected nil error, got %v", err)
	}

	if enriched.APICapability == nil || enriched.APICapability.Status != APICapabilityStatusLikelyConfigured {
		t.Fatalf("expected likely configured api capability, got %#v", enriched.APICapability)
	}

	if len(enriched.APIEndpoints) != 1 || enriched.APIEndpoints[0].Port != 10085 {
		t.Fatalf("unexpected api endpoints: %#v", enriched.APIEndpoints)
	}
}
