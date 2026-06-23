package policy

import (
	"errors"
	"testing"

	"github.com/PdYrust/RayLimit/internal/ipaddr"
)

func TestTargetValidatePreservesInvalidIPCause(t *testing.T) {
	target := Target{Kind: TargetKindIP, Value: "not-an-ip"}

	err := target.Validate()
	if err == nil {
		t.Fatal("expected an invalid ip target value to fail validation")
	}
	if !errors.Is(err, ipaddr.ErrInvalidIP) {
		t.Fatalf("expected the invalid-IP root cause in the error chain, got %v", err)
	}
}
