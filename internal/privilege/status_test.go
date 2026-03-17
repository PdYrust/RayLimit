package privilege

import "testing"

func TestCurrentReportsRootWhenEffectiveUserIsZero(t *testing.T) {
	previous := euidFunc
	euidFunc = func() int { return 0 }
	t.Cleanup(func() {
		euidFunc = previous
	})

	status := Current()
	if !status.IsRoot {
		t.Fatal("expected zero effective user id to be treated as root")
	}
	if status.EUID != 0 {
		t.Fatalf("expected effective user id 0, got %d", status.EUID)
	}
}

func TestCurrentReportsNonRootWhenEffectiveUserIsNonZero(t *testing.T) {
	previous := euidFunc
	euidFunc = func() int { return 1000 }
	t.Cleanup(func() {
		euidFunc = previous
	})

	status := Current()
	if status.IsRoot {
		t.Fatal("expected non-zero effective user id to be treated as non-root")
	}
	if status.EUID != 1000 {
		t.Fatalf("expected effective user id 1000, got %d", status.EUID)
	}
}
