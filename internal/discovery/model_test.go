package discovery

import (
	"strings"
	"testing"
)

func TestDiscoverySourceValid(t *testing.T) {
	if !DiscoverySourceHostProcess.Valid() {
		t.Fatal("expected host process source to be valid")
	}

	if !DiscoverySourceDockerContainer.Valid() {
		t.Fatal("expected docker container source to be valid")
	}

	if DiscoverySource("").Valid() {
		t.Fatal("expected empty source to be invalid")
	}
}

func TestRuntimeTargetValidateHostProcessTarget(t *testing.T) {
	target := RuntimeTarget{
		Source: DiscoverySourceHostProcess,
		Identity: RuntimeIdentity{
			Name:    "edge-xray",
			Binary:  "xray",
			Version: "1.8.20",
		},
		HostProcess: &HostProcessCandidate{
			PID:            4242,
			ExecutablePath: "/usr/bin/xray",
			CommandLine:    []string{"/usr/bin/xray", "-config", "/etc/xray/config.json"},
			ConfigPaths:    []string{"/etc/xray/config.json"},
		},
		APICapability: &APICapability{
			Status: APICapabilityStatusLikelyConfigured,
			Reason: "Readable configuration hints define Xray API services and a matching inbound.",
		},
		APIEndpoints: []APIEndpoint{
			{
				Name:    "stats",
				Network: EndpointNetworkTCP,
				Address: "127.0.0.1",
				Port:    10085,
			},
		},
		Inbounds: []InboundSummary{
			{
				Tag:           "socks-in",
				Protocol:      "socks",
				ListenAddress: "127.0.0.1",
				Port:          1080,
			},
		},
		Outbounds: []OutboundSummary{
			{
				Tag:      "direct",
				Protocol: "freedom",
			},
		},
		Evidence: &DetectionEvidence{
			Confidence: DetectionConfidenceHigh,
			Reasons: []string{
				"binary path matched xray",
				"command line referenced an xray configuration file",
			},
		},
	}

	if err := target.Validate(); err != nil {
		t.Fatalf("expected host process target to validate, got %v", err)
	}
}

func TestRuntimeTargetValidateDockerTarget(t *testing.T) {
	target := RuntimeTarget{
		Source: DiscoverySourceDockerContainer,
		Identity: RuntimeIdentity{
			Name:   "xray-gateway",
			Binary: "xray",
		},
		DockerContainer: &DockerContainerCandidate{
			ID:    "4fd2c0d51d0a",
			Name:  "xray-gateway",
			Image: "ghcr.io/example/xray:latest",
		},
		Evidence: &DetectionEvidence{
			Confidence: DetectionConfidenceMedium,
			Reasons: []string{
				"container name matched xray naming conventions",
			},
		},
	}

	if err := target.Validate(); err != nil {
		t.Fatalf("expected docker target to validate, got %v", err)
	}
}

func TestRuntimeTargetValidateRejectsZeroValueTarget(t *testing.T) {
	var target RuntimeTarget

	err := target.Validate()
	if err == nil {
		t.Fatal("expected zero-value target to fail validation")
	}

	if !strings.Contains(err.Error(), "invalid discovery source") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestRuntimeTargetValidateRejectsConflictingCandidates(t *testing.T) {
	target := RuntimeTarget{
		Source: DiscoverySourceHostProcess,
		HostProcess: &HostProcessCandidate{
			PID: 1,
		},
		DockerContainer: &DockerContainerCandidate{
			ID: "container-id",
		},
	}

	err := target.Validate()
	if err == nil {
		t.Fatal("expected conflicting candidates to fail validation")
	}

	if !strings.Contains(err.Error(), "cannot include a docker container candidate") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestRuntimeTargetValidateRejectsInvalidEvidence(t *testing.T) {
	target := RuntimeTarget{
		Source: DiscoverySourceDockerContainer,
		DockerContainer: &DockerContainerCandidate{
			ID: "container-id",
		},
		Evidence: &DetectionEvidence{
			Reasons: []string{"candidate image name matched xray"},
		},
	}

	err := target.Validate()
	if err == nil {
		t.Fatal("expected invalid evidence to fail validation")
	}

	if !strings.Contains(err.Error(), "detection reasons require a confidence level") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestRuntimeTargetValidateRejectsInvalidEndpointPort(t *testing.T) {
	target := RuntimeTarget{
		Source: DiscoverySourceHostProcess,
		HostProcess: &HostProcessCandidate{
			PID: 99,
		},
		APIEndpoints: []APIEndpoint{
			{
				Name: "stats",
				Port: 70000,
			},
		},
	}

	err := target.Validate()
	if err == nil {
		t.Fatal("expected invalid endpoint port to fail validation")
	}

	if !strings.Contains(err.Error(), "endpoint port must be between 0 and 65535") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestRuntimeTargetValidateRejectsInvalidAPICapabilityStatus(t *testing.T) {
	target := RuntimeTarget{
		Source: DiscoverySourceHostProcess,
		HostProcess: &HostProcessCandidate{
			PID: 99,
		},
		APICapability: &APICapability{
			Status: "invalid",
		},
	}

	err := target.Validate()
	if err == nil {
		t.Fatal("expected invalid api capability to fail validation")
	}

	if !strings.Contains(err.Error(), "invalid api capability status") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestRuntimeTargetValidateRejectsInvalidAPICapabilityLimitation(t *testing.T) {
	target := RuntimeTarget{
		Source: DiscoverySourceHostProcess,
		HostProcess: &HostProcessCandidate{
			PID: 99,
		},
		APICapability: &APICapability{
			Status:     APICapabilityStatusUnknown,
			Limitation: "invalid",
		},
	}

	err := target.Validate()
	if err == nil {
		t.Fatal("expected invalid api capability limitation to fail validation")
	}

	if !strings.Contains(err.Error(), "invalid api capability limitation") {
		t.Fatalf("unexpected error: %v", err)
	}
}
