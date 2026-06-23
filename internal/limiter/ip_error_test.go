package limiter

import (
	"errors"
	"testing"

	"github.com/PdYrust/RayLimit/internal/discovery"
	"github.com/PdYrust/RayLimit/internal/ipaddr"
	"github.com/PdYrust/RayLimit/internal/policy"
)

func TestSubjectValidatePreservesInvalidIPCause(t *testing.T) {
	subject := Subject{
		Kind:  policy.TargetKindIP,
		Value: "not-an-ip",
		Binding: RuntimeBinding{
			Runtime: discovery.SessionRuntime{
				Source:  discovery.DiscoverySourceHostProcess,
				HostPID: 4242,
				Name:    "edge-a",
			},
		},
	}

	err := subject.Validate()
	if err == nil {
		t.Fatal("expected an invalid ip subject value to fail validation")
	}
	if !errors.Is(err, ipaddr.ErrInvalidIP) {
		t.Fatalf("expected the invalid-IP root cause in the error chain, got %v", err)
	}
}
