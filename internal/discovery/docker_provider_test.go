package discovery

import (
	"context"
	"errors"
	"path/filepath"
	"strings"
	"testing"
)

func TestDetectXrayContainerMatchesLikelyXrayContainer(t *testing.T) {
	evidence, ok := detectXrayContainer(dockerContainerSummary{
		ID:      "4fd2c0d51d0a8f5d",
		Name:    "xray-edge",
		Image:   "ghcr.io/xtls/xray-core:latest",
		Command: `"/usr/local/bin/xray run -config /etc/xray/config.json"`,
	})
	if !ok {
		t.Fatal("expected container to match xray")
	}

	if evidence.Confidence != DetectionConfidenceHigh {
		t.Fatalf("expected high confidence, got %q", evidence.Confidence)
	}

	if len(evidence.Reasons) != 2 {
		t.Fatalf("expected image and command reasons, got %#v", evidence.Reasons)
	}
}

func TestDetectXrayContainerRejectsNonXrayContainer(t *testing.T) {
	_, ok := detectXrayContainer(dockerContainerSummary{
		ID:      "container-1",
		Name:    "web",
		Image:   "nginx:latest",
		Command: `"/docker-entrypoint.sh nginx -g 'daemon off;'"`,
	})
	if ok {
		t.Fatal("expected non-xray container to be rejected")
	}
}

func TestDockerProviderHandlesUnavailableDockerGracefully(t *testing.T) {
	provider := DockerProvider{
		listContainers: func(context.Context) ([]dockerContainerSummary, error) {
			return nil, dockerUnavailableIssue(errors.New("docker daemon is unavailable"))
		},
	}

	result, err := provider.Discover(context.Background(), Request{})
	if err != nil {
		t.Fatalf("expected nil error, got %v", err)
	}

	if len(result.Targets) != 0 {
		t.Fatalf("expected no targets, got %#v", result.Targets)
	}

	if len(result.Issues) != 1 {
		t.Fatalf("expected 1 provider issue, got %#v", result.Issues)
	}

	if result.Issues[0].Code != ProviderErrorCodeUnavailable {
		t.Fatalf("expected unavailable provider issue, got %#v", result.Issues[0])
	}
}

func TestClassifyDockerCommandErrorMatchesPermissionDenied(t *testing.T) {
	message := "permission denied while trying to connect to the docker API at unix:///var/run/docker.sock"
	issue, ok := classifyDockerCommandError(message, errors.New("permission denied"))
	if !ok {
		t.Fatalf("expected permission denied message to be classified: %q", message)
	}

	if issue.Code != ProviderErrorCodePermissionDenied {
		t.Fatalf("expected permission_denied issue, got %#v", issue)
	}

	if !issue.Restricted {
		t.Fatalf("expected permission_denied issue to be restricted, got %#v", issue)
	}
}

func TestParseDockerPSOutputSkipsMalformedLines(t *testing.T) {
	output := []byte("{not-json}\n" +
		`{"ID":"1","Image":"ghcr.io/xtls/xray-core:latest","Names":"xray","Command":"\"xray run\"","State":"running","Status":"Up 2 hours"}` +
		"\n")

	containers := parseDockerPSOutput(output)
	if len(containers) != 1 {
		t.Fatalf("expected 1 valid container, got %d", len(containers))
	}

	if containers[0].Name != "xray" {
		t.Fatalf("unexpected parsed container: %#v", containers[0])
	}
}

func TestDockerProviderSkipsPartialContainerMetadata(t *testing.T) {
	provider := DockerProvider{
		listContainers: func(context.Context) ([]dockerContainerSummary, error) {
			return []dockerContainerSummary{
				{
					ID:      "",
					Image:   "ghcr.io/xtls/xray-core:latest",
					Command: `"/usr/local/bin/xray run"`,
				},
			}, nil
		},
	}

	result, err := provider.Discover(context.Background(), Request{})
	if err != nil {
		t.Fatalf("expected nil error, got %v", err)
	}

	if len(result.Targets) != 0 {
		t.Fatalf("expected no targets, got %#v", result.Targets)
	}

	if len(result.Issues) != 0 {
		t.Fatalf("expected no provider issues, got %#v", result.Issues)
	}
}

func TestDockerProviderHandlesPermissionDeniedDockerAccessGracefully(t *testing.T) {
	provider := DockerProvider{
		listContainers: func(context.Context) ([]dockerContainerSummary, error) {
			return nil, dockerPermissionDeniedIssue(errors.New("permission denied"))
		},
	}

	result, err := provider.Discover(context.Background(), Request{})
	if err != nil {
		t.Fatalf("expected nil error, got %v", err)
	}

	if len(result.Targets) != 0 {
		t.Fatalf("expected no targets, got %#v", result.Targets)
	}

	if len(result.Issues) != 1 {
		t.Fatalf("expected 1 provider issue, got %#v", result.Issues)
	}

	if result.Issues[0].Code != ProviderErrorCodePermissionDenied {
		t.Fatalf("expected permission_denied provider issue, got %#v", result.Issues[0])
	}

	if result.Issues[0].Hint == "" {
		t.Fatalf("expected permission_denied hint, got %#v", result.Issues[0])
	}
}

func TestDockerProviderHandlesMissingDockerCLIGracefully(t *testing.T) {
	provider := DockerProvider{
		listContainers: func(context.Context) ([]dockerContainerSummary, error) {
			return nil, dockerNotInstalledIssue(errors.New("executable file not found"))
		},
	}

	result, err := provider.Discover(context.Background(), Request{})
	if err != nil {
		t.Fatalf("expected nil error, got %v", err)
	}

	if len(result.Issues) != 1 {
		t.Fatalf("expected 1 provider issue, got %#v", result.Issues)
	}

	if result.Issues[0].Code != ProviderErrorCodeNotInstalled {
		t.Fatalf("expected not_installed provider issue, got %#v", result.Issues[0])
	}
}

func TestTargetFromDockerContainerConvertsMetadata(t *testing.T) {
	target, ok := targetFromDockerContainer(dockerContainerSummary{
		ID:      "4fd2c0d51d0a8f5d7e22",
		Name:    "xray-gateway",
		Image:   "ghcr.io/xtls/xray-core:latest",
		Command: `"/usr/local/bin/xray run -config /etc/xray/config.json"`,
		State:   "running",
		Status:  "Up 5 minutes",
	}, dockerContainerInspect{})
	if !ok {
		t.Fatal("expected docker target to be created")
	}

	if target.Source != DiscoverySourceDockerContainer {
		t.Fatalf("unexpected source: %#v", target)
	}

	if target.DockerContainer == nil {
		t.Fatalf("expected docker container candidate, got %#v", target)
	}

	if target.DockerContainer.Name != "xray-gateway" {
		t.Fatalf("unexpected container name: %#v", target.DockerContainer)
	}

	if target.DockerContainer.Image != "ghcr.io/xtls/xray-core:latest" {
		t.Fatalf("unexpected container image: %#v", target.DockerContainer)
	}

	if target.DockerContainer.State != "running" || target.DockerContainer.Status != "Up 5 minutes" {
		t.Fatalf("unexpected container status: %#v", target.DockerContainer)
	}

	if got := strings.Join(target.DockerContainer.CommandLine, " "); !strings.Contains(got, "xray run") {
		t.Fatalf("unexpected command line: %#v", target.DockerContainer.CommandLine)
	}

	if target.Identity.Binary != "xray" {
		t.Fatalf("unexpected binary identity: %#v", target.Identity)
	}
}

func TestTargetFromDockerContainerUsesInspectMetadataForCommandLabelsAndConfigPaths(t *testing.T) {
	target, ok := targetFromDockerContainer(dockerContainerSummary{
		ID:      "4fd2c0d51d0a8f5d7e22",
		Name:    "xray-gateway",
		Image:   "ghcr.io/xtls/xray-core:latest",
		Command: `"/bin/sh -c xray run"`,
		State:   "running",
		Status:  "Up 5 minutes",
	}, dockerContainerInspect{
		ID:     "4fd2c0d51d0a8f5d7e22",
		Path:   "/usr/local/bin/xray",
		Args:   []string{"run", "-config", "/etc/xray/config.json"},
		Labels: map[string]string{"app": "xray"},
		Mounts: []dockerMount{
			{
				Source:      "/srv/xray/config.json",
				Destination: "/etc/xray/config.json",
				Type:        "bind",
			},
		},
	})
	if !ok {
		t.Fatal("expected docker target to be created")
	}

	if got := strings.Join(target.DockerContainer.CommandLine, " "); got != "/usr/local/bin/xray run -config /etc/xray/config.json" {
		t.Fatalf("unexpected inspected command line: %#v", target.DockerContainer.CommandLine)
	}

	if got := target.DockerContainer.Labels["app"]; got != "xray" {
		t.Fatalf("expected inspected labels to be preserved, got %#v", target.DockerContainer.Labels)
	}

	if len(target.DockerContainer.ConfigPaths) != 1 || target.DockerContainer.ConfigPaths[0] != "/srv/xray/config.json" {
		t.Fatalf("unexpected docker config hints: %#v", target.DockerContainer.ConfigPaths)
	}
}

func TestTargetFromDockerContainerMapsDefaultConfigHintsFromMountedDirectory(t *testing.T) {
	target, ok := targetFromDockerContainer(dockerContainerSummary{
		ID:      "4fd2c0d51d0a8f5d7e22",
		Name:    "xray-gateway",
		Image:   "ghcr.io/xtls/xray-core:latest",
		Command: `"/usr/local/bin/xray run"`,
		State:   "running",
		Status:  "Up 5 minutes",
	}, dockerContainerInspect{
		ID:   "4fd2c0d51d0a8f5d7e22",
		Path: "/usr/local/bin/xray",
		Args: []string{"run"},
		Mounts: []dockerMount{
			{
				Source:      "/srv/xray",
				Destination: "/etc/xray",
				Type:        "bind",
			},
		},
	})
	if !ok {
		t.Fatal("expected docker target to be created")
	}

	if len(target.DockerContainer.ConfigPaths) != 2 {
		t.Fatalf("unexpected docker config hints: %#v", target.DockerContainer.ConfigPaths)
	}

	if target.DockerContainer.ConfigPaths[0] != filepath.Join("/srv/xray", "config.json") {
		t.Fatalf("unexpected docker config hints: %#v", target.DockerContainer.ConfigPaths)
	}
}

func TestDockerInspectFromLineParsesPublishedPorts(t *testing.T) {
	inspect := dockerInspectFromLine(dockerInspectLine{
		ID:   "container-1",
		Path: "/usr/local/bin/xray",
		Args: []string{"run"},
		NetworkSettings: struct {
			Ports map[string][]struct {
				HostIP   string `json:"HostIp"`
				HostPort string `json:"HostPort"`
			} `json:"Ports"`
		}{
			Ports: map[string][]struct {
				HostIP   string `json:"HostIp"`
				HostPort string `json:"HostPort"`
			}{
				"10085/tcp": {
					{HostIP: "127.0.0.1", HostPort: "11085"},
				},
			},
		},
	})

	if len(inspect.Ports) != 1 {
		t.Fatalf("expected one published port binding, got %#v", inspect.Ports)
	}
	if inspect.Ports[0].ContainerPort != 10085 || inspect.Ports[0].HostPort != 11085 || inspect.Ports[0].HostIP != "127.0.0.1" {
		t.Fatalf("unexpected published port binding: %#v", inspect.Ports[0])
	}
}

func TestDockerProviderReportsPartialInspectAccessAndPreservesTargets(t *testing.T) {
	provider := DockerProvider{
		listContainers: func(context.Context) ([]dockerContainerSummary, error) {
			return []dockerContainerSummary{
				{
					ID:      "container-1",
					Name:    "xray-edge",
					Image:   "ghcr.io/xtls/xray-core:latest",
					Command: `"/usr/local/bin/xray run"`,
					State:   "running",
					Status:  "Up 2 minutes",
				},
			}, nil
		},
		inspectContainers: func(context.Context, []string) (map[string]dockerContainerInspect, error) {
			return nil, dockerPermissionDeniedIssue(errors.New("permission denied"))
		},
	}

	result, err := provider.Discover(context.Background(), Request{})
	if err != nil {
		t.Fatalf("expected nil error, got %v", err)
	}

	if len(result.Targets) != 1 {
		t.Fatalf("expected discovered target to be preserved, got %#v", result.Targets)
	}

	if len(result.Issues) != 1 {
		t.Fatalf("expected one partial-access issue, got %#v", result.Issues)
	}

	if result.Issues[0].Code != ProviderErrorCodePartialAccess {
		t.Fatalf("expected partial_access provider issue, got %#v", result.Issues[0])
	}
}

func TestTargetFromDockerContainerRejectsStoppedContainer(t *testing.T) {
	_, ok := targetFromDockerContainer(dockerContainerSummary{
		ID:      "4fd2c0d51d0a8f5d7e22",
		Name:    "xray-gateway",
		Image:   "ghcr.io/xtls/xray-core:latest",
		Command: `"/usr/local/bin/xray run"`,
		State:   "exited",
		Status:  "Exited (0) 2 minutes ago",
	}, dockerContainerInspect{})
	if ok {
		t.Fatal("expected stopped container to be rejected")
	}
}
