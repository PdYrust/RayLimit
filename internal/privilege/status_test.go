package privilege

import (
	"os"
	"sync"
	"testing"
)

func TestCurrentReportsRootWhenEffectiveUserIsZero(t *testing.T) {
	status := currentWith(func() int { return 0 })
	if !status.IsRoot {
		t.Fatal("expected zero effective user id to be treated as root")
	}
	if status.EUID != 0 {
		t.Fatalf("expected effective user id 0, got %d", status.EUID)
	}
}

func TestCurrentReportsNonRootWhenEffectiveUserIsNonZero(t *testing.T) {
	status := currentWith(func() int { return 1000 })
	if status.IsRoot {
		t.Fatal("expected non-zero effective user id to be treated as non-root")
	}
	if status.EUID != 1000 {
		t.Fatalf("expected effective user id 1000, got %d", status.EUID)
	}
}

// TestCurrentWithInjectedEUID exercises the injection mechanism across the
// root boundary, replacing the previous mutable euidFunc global.
func TestCurrentWithInjectedEUID(t *testing.T) {
	cases := []struct {
		name       string
		euid       int
		wantRoot   bool
		wantEUIDIs int
	}{
		{name: "root", euid: 0, wantRoot: true, wantEUIDIs: 0},
		{name: "non-root user", euid: 1000, wantRoot: false, wantEUIDIs: 1000},
		{name: "unsupported platform sentinel", euid: -1, wantRoot: false, wantEUIDIs: -1},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			euid := tc.euid
			status := currentWith(func() int { return euid })
			if status.IsRoot != tc.wantRoot {
				t.Fatalf("euid %d: expected IsRoot=%v, got %v", tc.euid, tc.wantRoot, status.IsRoot)
			}
			if status.EUID != tc.wantEUIDIs {
				t.Fatalf("euid %d: expected EUID=%d, got %d", tc.euid, tc.wantEUIDIs, status.EUID)
			}
		})
	}
}

// TestCurrentWithIsConcurrencySafe proves the injection mechanism carries no
// shared mutable state, so concurrent callers cannot race (guards make test-race).
func TestCurrentWithIsConcurrencySafe(t *testing.T) {
	const goroutines = 64
	var wg sync.WaitGroup
	wg.Add(goroutines)
	for i := 0; i < goroutines; i++ {
		euid := i
		go func() {
			defer wg.Done()
			status := currentWith(func() int { return euid })
			if status.EUID != euid {
				t.Errorf("expected EUID=%d, got %d", euid, status.EUID)
			}
			if (euid == 0) != status.IsRoot {
				t.Errorf("euid %d: IsRoot=%v inconsistent", euid, status.IsRoot)
			}
		}()
	}
	wg.Wait()
}

// TestCurrentIntegratesWithGetEUID confirms the public Current entry point is
// wired to the real platform lookup.
func TestCurrentIntegratesWithGetEUID(t *testing.T) {
	status := Current()
	if status.EUID != getEUID() {
		t.Fatalf("expected Current to report getEUID()=%d, got %d", getEUID(), status.EUID)
	}
	if status.EUID == 0 && os.Geteuid() != 0 {
		t.Fatal("Current reported root but process is not root")
	}
}
