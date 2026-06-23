package cli

import (
	"errors"
	"testing"

	"github.com/PdYrust/RayLimit/internal/ipaddr"
)

func TestLimitTargetSelectionValidatePreservesInvalidIPCause(t *testing.T) {
	selection := limitTargetSelection{IP: "not-an-ip"}

	err := selection.Validate()
	if err == nil {
		t.Fatal("expected an invalid --ip value to fail validation")
	}
	if !errors.Is(err, ipaddr.ErrInvalidIP) {
		t.Fatalf("expected the invalid-IP root cause in the error chain, got %v", err)
	}
}
