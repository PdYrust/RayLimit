package discovery

import "testing"

func TestMatchesXrayFamilyBinary(t *testing.T) {
	cases := map[string]bool{
		"xray":                         true,
		"xray-core":                    true,
		"xray-linux-amd64":             true,
		"xray-darwin-arm64":            true,
		"xray-windows-4.0-amd64.exe":   true,
		"xray-linux-amd6":              true, // 15-char truncated /proc comm
		"sanaei":                       true,
		"sanaei-linux-amd64":           true,
		"sanaei-core":                  true,
		"XRAY-LINUX-AMD64":             true, // case-insensitive
		"/usr/local/bin/xray":          true, // path is reduced to basename
		"/opt/sanaei/sanaei-linux":     true,
		"my-xray-fork":                 false, // substring, not a prefix
		"proxy-sanaei":                 false,
		"nginx":                        false,
		"":                             false,
		"xraylet-unrelated-but-prefix": true, // documented: simple prefix match
	}

	for input, want := range cases {
		if got := matchesXrayFamilyBinary(input); got != want {
			t.Fatalf("matchesXrayFamilyBinary(%q) = %v, want %v", input, got, want)
		}
	}
}

func TestContainsXrayFamilyMarker(t *testing.T) {
	cases := map[string]bool{
		"xray":         true,
		"xray-core":    true,
		"my-xray-fork": true,
		"sanaei":       true,
		"some-sanaei":  true,
		"MY-XRAY":      true, // case-insensitive
		"nginx":        false,
		"":             false,
	}

	for input, want := range cases {
		if got := containsXrayFamilyMarker(input); got != want {
			t.Fatalf("containsXrayFamilyMarker(%q) = %v, want %v", input, got, want)
		}
	}
}

func TestDetectXrayProcessMatchesForkAndTruncatedComm(t *testing.T) {
	evidence, ok := detectXrayProcess(processSnapshot{
		PID:            7001,
		ProcessName:    "xray-linux-amd6", // truncated comm
		ExecutablePath: "/usr/local/bin/xray-linux-amd64",
		CommandLine:    []string{"/usr/local/bin/xray-linux-amd64", "run"},
	})
	if !ok {
		t.Fatal("expected suffixed fork binary to be detected")
	}
	if evidence.Confidence != DetectionConfidenceHigh {
		t.Fatalf("expected high confidence, got %q", evidence.Confidence)
	}
}

func TestDetectXrayProcessMatchesSanaeiFork(t *testing.T) {
	evidence, ok := detectXrayProcess(processSnapshot{
		PID:            7002,
		ProcessName:    "sanaei-linux-am", // truncated comm
		ExecutablePath: "/opt/sanaei/sanaei-linux-amd64",
		CommandLine:    []string{"/opt/sanaei/sanaei-linux-amd64", "-config", "/etc/sanaei/config.json"},
	})
	if !ok {
		t.Fatal("expected sanaei fork to be detected")
	}
	if evidence.Confidence != DetectionConfidenceHigh {
		t.Fatalf("expected high confidence, got %q", evidence.Confidence)
	}
}

func TestDetectXrayContainerHighConfidenceForFamilyImage(t *testing.T) {
	evidence, ok := detectXrayContainer(dockerContainerSummary{
		ID:    "container-1",
		Image: "ghcr.io/example/xray-linux-amd64:latest",
	})
	if !ok {
		t.Fatal("expected family image to be detected")
	}
	if evidence.Confidence != DetectionConfidenceHigh {
		t.Fatalf("expected high confidence for family image, got %q", evidence.Confidence)
	}
}

func TestDetectXrayContainerMediumConfidenceForSubstringImage(t *testing.T) {
	evidence, ok := detectXrayContainer(dockerContainerSummary{
		ID:    "container-2",
		Image: "registry.example.com/team/my-xray-fork:1.2.3",
	})
	if !ok {
		t.Fatal("expected substring image to be detected")
	}
	if evidence.Confidence != DetectionConfidenceMedium {
		t.Fatalf("expected medium confidence for substring-only image, got %q", evidence.Confidence)
	}
}

func TestDetectXrayContainerRejectsUnrelatedImageAndCommand(t *testing.T) {
	if _, ok := detectXrayContainer(dockerContainerSummary{
		ID:      "container-3",
		Image:   "nginx:latest",
		Command: `"/docker-entrypoint.sh nginx -g 'daemon off;'"`,
	}); ok {
		t.Fatal("expected unrelated container to be rejected")
	}
}

func TestChooseDockerBinaryDoesNotGuessXrayWithoutCommand(t *testing.T) {
	if got := chooseDockerBinary(nil); got != "" {
		t.Fatalf("expected empty binary without a command line, got %q", got)
	}
	if got := chooseDockerBinary([]string{"/usr/local/bin/sanaei-linux-amd64", "run"}); got != "sanaei-linux-amd64" {
		t.Fatalf("expected command basename, got %q", got)
	}
}
