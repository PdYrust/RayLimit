package discovery

import (
	"context"
	"reflect"
	"testing"
)

func TestTargetFromDockerContainerDetectsViaLabel(t *testing.T) {
	target, ok := targetFromDockerContainer(dockerContainerSummary{
		ID:      "container-1",
		Name:    "edge",
		Image:   "ubuntu:22.04",
		Command: `"bash"`,
		State:   "running",
	}, dockerContainerInspect{
		ID:     "container-1",
		Labels: map[string]string{"app": "xray"},
	})
	if !ok {
		t.Fatal("expected label signal to detect the container")
	}
	if target.Evidence == nil || target.Evidence.Confidence != DetectionConfidenceMedium {
		t.Fatalf("expected medium confidence from a label match, got %#v", target.Evidence)
	}
}

func TestTargetFromDockerContainerDetectsViaAPIPort(t *testing.T) {
	target, ok := targetFromDockerContainer(dockerContainerSummary{
		ID:      "container-2",
		Name:    "edge",
		Image:   "ubuntu:22.04",
		Command: `"bash"`,
		State:   "running",
	}, dockerContainerInspect{
		ID: "container-2",
		Ports: []dockerPortBinding{
			{ContainerPort: 10085, Protocol: "tcp", HostIP: "0.0.0.0", HostPort: 10085},
		},
	})
	if !ok {
		t.Fatal("expected API port signal to detect the container")
	}
	if target.Evidence == nil || target.Evidence.Confidence != DetectionConfidenceLow {
		t.Fatalf("expected low confidence from a port match, got %#v", target.Evidence)
	}
}

func TestDetectXrayContainerEvidenceTakesHighestConfidence(t *testing.T) {
	evidence, ok := detectXrayContainerEvidence(dockerContainerSummary{
		ID:    "container-3",
		Image: "ghcr.io/xtls/xray-core:latest",
		State: "running",
	}, dockerContainerInspect{
		ID: "container-3",
		Ports: []dockerPortBinding{
			{ContainerPort: 10085, Protocol: "tcp", HostPort: 10085},
		},
	})
	if !ok {
		t.Fatal("expected detection")
	}
	if evidence.Confidence != DetectionConfidenceHigh {
		t.Fatalf("expected the image (High) signal to win over the port (Low) signal, got %q", evidence.Confidence)
	}
	if len(evidence.Reasons) != 2 {
		t.Fatalf("expected both image and port reasons, got %#v", evidence.Reasons)
	}
}

func TestDockerProviderRecordsNoMatchesWhenNothingDetected(t *testing.T) {
	provider := DockerProvider{
		listContainers: func(context.Context) ([]dockerContainerSummary, error) {
			return []dockerContainerSummary{
				{ID: "container-1", Name: "web", Image: "ubuntu:22.04", Command: `"bash"`, State: "running"},
			}, nil
		},
		inspectContainers: func(context.Context, []string) (map[string]dockerContainerInspect, error) {
			return map[string]dockerContainerInspect{"container-1": {ID: "container-1"}}, nil
		},
	}

	result, err := provider.Discover(context.Background(), Request{})
	if err != nil {
		t.Fatalf("expected nil error, got %v", err)
	}
	if len(result.Targets) != 0 {
		t.Fatalf("expected no targets, got %#v", result.Targets)
	}
	if len(result.Issues) != 1 || result.Issues[0].Code != ProviderErrorCodeNoMatches {
		t.Fatalf("expected a single no_matches issue, got %#v", result.Issues)
	}
	if !result.Issues[0].Limitation() {
		t.Fatalf("expected no_matches to be a limitation, got %#v", result.Issues[0])
	}
}

func TestDockerProviderDoesNotRecordNoMatchesForInvalidContainers(t *testing.T) {
	provider := DockerProvider{
		listContainers: func(context.Context) ([]dockerContainerSummary, error) {
			return []dockerContainerSummary{{ID: "", Image: "ubuntu:22.04", Command: `"bash"`}}, nil
		},
	}

	result, err := provider.Discover(context.Background(), Request{})
	if err != nil {
		t.Fatalf("expected nil error, got %v", err)
	}
	if len(result.Issues) != 0 {
		t.Fatalf("expected no issues for an unevaluable container, got %#v", result.Issues)
	}
}

func TestDockerDefaultConfigHintsForFork(t *testing.T) {
	hints := dockerDefaultConfigHints("sanaei-linux-amd64")
	for _, want := range []string{"/etc/sanaei/config.json", "/etc/sanaei"} {
		if !containsString(hints, want) {
			t.Fatalf("expected hints to contain %q, got %#v", want, hints)
		}
	}
}

func TestDockerDefaultConfigHintsForVanillaUnchanged(t *testing.T) {
	want := []string{
		"/etc/xray/config.json",
		"/etc/xray",
		"/usr/local/etc/xray/config.json",
		"/usr/local/etc/xray",
	}
	if got := dockerDefaultConfigHints("xray"); !reflect.DeepEqual(got, want) {
		t.Fatalf("expected vanilla hints unchanged, got %#v", got)
	}
}

func TestDockerConfigDirNameStripsReleaseSuffixes(t *testing.T) {
	cases := map[string]string{
		"sanaei-linux-amd64":         "sanaei",
		"xray-darwin-arm64":          "xray",
		"xray-windows-4.0-amd64.exe": "xray",
		"/opt/xray/xray-linux-amd64": "xray",
		"xray":                       "xray",
		"":                           "xray",
	}
	for input, want := range cases {
		if got := dockerConfigDirName(input); got != want {
			t.Fatalf("dockerConfigDirName(%q) = %q, want %q", input, got, want)
		}
	}
}

func containsString(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}

	return false
}
