package tc

import (
	"context"
	"sync"
)

// nftJSONCapability caches whether the local nft binary supports `-j` JSON
// output. The probe runs once and the result is memoized for the process
// lifetime.
//
// Note: the per-call format detection in ParseNftablesSnapshot (nftOutputIsJSON)
// is authoritative for choosing the JSON vs plain-text path, so a system whose
// nft silently ignores `-j` is handled correctly even without this probe. The
// probe exists as the specified, cached capability signal — for example so a
// startup or control-loop component can log or short-circuit once — without
// being inserted into the read-only inspect command.
type nftJSONCapability struct {
	once      sync.Once
	supported bool
}

// defaultNftJSONCapability is the process-wide cached nft `-j` capability.
var defaultNftJSONCapability nftJSONCapability

// Supported returns whether `nft -j` produces JSON, probing once and caching the
// result. Subsequent calls return the cached value without re-probing.
func (c *nftJSONCapability) Supported(ctx context.Context, runner Runner, binary string) bool {
	c.once.Do(func() {
		c.supported = probeNftJSONSupport(ctx, runner, binary)
	})

	return c.supported
}

// NftJSONSupported reports, using the process-wide cache, whether the local nft
// binary emits JSON for `-j`. It probes at most once.
//
// Deferred: not consumed for routing; per-call byte-peeking (nftOutputIsJSON)
// is the authoritative routing mechanism. This probe is retained, correct and
// unwired, as a capability signal for a possible future startup/control-loop
// consumer. It currently has no production caller. It accepts a binary
// parameter, so it honors the --nft-binary override when a future consumer
// wires it.
func NftJSONSupported(ctx context.Context, runner Runner, binary string) bool {
	return defaultNftJSONCapability.Supported(ctx, runner, binary)
}

// probeNftJSONSupport runs `nft -j list ruleset` and reports whether the output
// begins with a JSON document. Any execution error is treated as "not
// supported" so callers fall back to the plain-text path.
func probeNftJSONSupport(ctx context.Context, runner Runner, binary string) bool {
	if runner == nil {
		runner = SystemRunner{}
	}
	if binary == "" {
		binary = defaultNftBinary
	}

	result, err := runner.Run(ctx, Command{
		Path: binary,
		Args: []string{"-j", "list", "ruleset"},
	})
	if err != nil {
		return false
	}

	return nftOutputIsJSON(result.Stdout)
}
