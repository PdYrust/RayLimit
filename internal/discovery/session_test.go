package discovery

import (
	"strings"
	"testing"
)

func TestSessionValidateHostSession(t *testing.T) {
	session := Session{
		ID: "conn-1",
		Runtime: SessionRuntime{
			Source:   DiscoverySourceHostProcess,
			Provider: "host",
			Name:     "edge-a",
			HostPID:  4242,
		},
		Policy: SessionPolicyIdentity{
			UUID: "F47AC10B-58CC-4372-A567-0E02B2C3D479",
		},
		Client: SessionClient{
			IP: "203.0.113.10",
		},
		Route: SessionRoute{
			InboundTag:  "api-in",
			OutboundTag: "direct",
		},
	}

	if err := session.Validate(); err != nil {
		t.Fatalf("expected host session to validate, got %v", err)
	}
}

func TestSessionValidateRejectsZeroValueSession(t *testing.T) {
	var session Session

	err := session.Validate()
	if err == nil {
		t.Fatal("expected zero-value session to fail validation")
	}

	if !strings.Contains(err.Error(), "invalid runtime association") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestSessionSamePolicyIdentityAllowsDistinctSessionsForSharedUUID(t *testing.T) {
	first := Session{
		ID: "conn-1",
		Runtime: SessionRuntime{
			Source:  DiscoverySourceHostProcess,
			HostPID: 1001,
		},
		Policy: SessionPolicyIdentity{
			UUID: "F47AC10B-58CC-4372-A567-0E02B2C3D479",
		},
	}

	second := Session{
		ID: "conn-2",
		Runtime: SessionRuntime{
			Source:  DiscoverySourceHostProcess,
			HostPID: 1001,
		},
		Policy: SessionPolicyIdentity{
			UUID: "f47ac10b-58cc-4372-a567-0e02b2c3d479",
		},
	}

	if first.ID == second.ID {
		t.Fatal("expected sessions to remain distinct per connection")
	}

	if !first.SamePolicyIdentity(second) {
		t.Fatalf("expected shared uuid to correlate policy identity, got %#v and %#v", first, second)
	}
}

func TestSessionRuntimeValidateRejectsConflictingAssociation(t *testing.T) {
	runtime := SessionRuntime{
		Source:      DiscoverySourceDockerContainer,
		HostPID:     1001,
		ContainerID: "container-1",
	}

	err := runtime.Validate()
	if err == nil {
		t.Fatal("expected conflicting runtime association to fail validation")
	}

	if !strings.Contains(err.Error(), "cannot include a host process id") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestSessionValidateRejectsInvalidClientIP(t *testing.T) {
	session := Session{
		Runtime: SessionRuntime{
			Source:  DiscoverySourceHostProcess,
			HostPID: 4242,
		},
		Client: SessionClient{
			IP: "not-an-ip",
		},
	}

	err := session.Validate()
	if err == nil {
		t.Fatal("expected invalid client ip to fail validation")
	}

	if !strings.Contains(err.Error(), "invalid client ip") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestSessionRuntimeValidateDockerAssociation(t *testing.T) {
	runtime := SessionRuntime{
		Source:      DiscoverySourceDockerContainer,
		Provider:    "docker",
		Name:        "xray-edge",
		ContainerID: "container-1",
	}

	if err := runtime.Validate(); err != nil {
		t.Fatalf("expected docker runtime association to validate, got %v", err)
	}
}

func TestSessionRuntimeFromTargetMatchesTarget(t *testing.T) {
	target := RuntimeTarget{
		Source: DiscoverySourceHostProcess,
		Identity: RuntimeIdentity{
			Name:   "edge-a",
			Binary: "xray",
		},
		HostProcess: &HostProcessCandidate{
			PID: 4242,
		},
	}

	runtime, err := SessionRuntimeFromTarget(target)
	if err != nil {
		t.Fatalf("expected runtime association from target, got %v", err)
	}

	if runtime.Source != DiscoverySourceHostProcess || runtime.HostPID != 4242 {
		t.Fatalf("unexpected runtime association: %#v", runtime)
	}

	if !runtime.MatchesTarget(target) {
		t.Fatalf("expected runtime association to match target, got %#v and %#v", runtime, target)
	}
}
