package tc

import (
	"context"
	"sync"
)

// tcJSONCapability caches whether the local tc binary supports `-j` JSON output.
// The probe runs once and the result is memoized for the process lifetime.
//
// Note: the per-call format detection in the state parsers (tcOutputIsJSON) is
// authoritative for choosing the JSON vs plain-text path, so a system whose tc
// silently ignores `-j` is handled correctly even without this probe. The probe
// exists as the specified, cached capability signal — for example so a startup
// or control-loop component can log or short-circuit once — without being
// inserted into the read-only inspect command sequence.
type tcJSONCapability struct {
	once      sync.Once
	supported bool
}

// defaultTCJSONCapability is the process-wide cached tc `-j` capability.
var defaultTCJSONCapability tcJSONCapability

// Supported returns whether `tc -j` produces JSON, probing once and caching the
// result. Subsequent calls return the cached value without re-probing.
func (c *tcJSONCapability) Supported(ctx context.Context, runner Runner, binary string) bool {
	c.once.Do(func() {
		c.supported = probeTCJSONSupport(ctx, runner, binary)
	})

	return c.supported
}

// TCJSONSupported reports, using the process-wide cache, whether the local tc
// binary emits JSON for `-j`. It probes at most once.
//
// Deferred: not consumed for routing; per-call byte-peeking (tcOutputIsJSON) is
// the authoritative routing mechanism. This probe is retained, correct and
// unwired, as a capability signal for a possible future startup/control-loop
// consumer. It currently has no production caller. It accepts a binary
// parameter, so it honors the --tc-binary override when a future consumer wires
// it (mirroring NftJSONSupported).
func TCJSONSupported(ctx context.Context, runner Runner, binary string) bool {
	return defaultTCJSONCapability.Supported(ctx, runner, binary)
}

// probeTCJSONSupport runs `tc -j qdisc show dev lo` and reports whether the
// output begins with a JSON array. Any execution error is treated as "not
// supported" so callers fall back to the plain-text path.
func probeTCJSONSupport(ctx context.Context, runner Runner, binary string) bool {
	if runner == nil {
		runner = SystemRunner{}
	}
	if binary == "" {
		binary = defaultBinary
	}

	result, err := runner.Run(ctx, Command{
		Path: binary,
		Args: []string{"-j", "qdisc", "show", "dev", "lo"},
	})
	if err != nil {
		return false
	}

	return tcOutputIsJSON(result.Stdout)
}
