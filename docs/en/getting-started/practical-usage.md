# Practical Usage

RayLimit is designed around one operational rule: inspect first, preview second, execute only when the current path is concrete.

The same workflow works for both supported run paths:

- an installed release package using `raylimit`
- a local source path using `go run ./cmd/raylimit` or `./bin/raylimit`

## Recommended Order

1. Discover candidate runtimes.
2. Inspect the selected runtime.
3. Preview the requested speed limiter in dry-run mode.
4. Review the observation, decision, and outcome.
5. Execute only when the report shows a concrete path and the host is suitable for live mutation.

## Understand `--direction`

RayLimit applies one side of a speed limiter policy at a time:

- `--direction upload` applies the upload side
- `--direction download` applies the download side

If you want to control both sides, run separate commands. The exact packet match or mark-backed attachment model depends on the selected speed limiter family and the concrete backend currently available for that family.

## Read Dry-Run Output Correctly

The dry-run report is the product contract. Focus on these sections:

- requested state: what you asked RayLimit to shape
- observation: what RayLimit could compare on the host
- decision: whether the current state is apply, no-op, remove, or blocked
- outcome: the final summary for the request

When the current path is not concrete, RayLimit blocks explicitly instead of guessing.

## Installed Path Versus Source Path

The product behavior is the same in both modes. The practical difference is how you invoke it:

- installed path: use `raylimit`
- source path: use `go run ./cmd/raylimit` for the fastest direct run from source
- local build path: use `./bin/raylimit` after `make build`

If you are validating host behavior repeatedly, `./bin/raylimit` is usually easier to reuse than repeating `go run`.

## High-Value Example Flows

### IP Speed Limiter

```bash
sudo raylimit limit --pid 1234 --ip 203.0.113.10 --device eth0 --direction upload --rate 2048
```

Use this when one visible client address is the correct shaping identity.

### UUID Speed Limiter

```bash
sudo raylimit limit --pid 1234 --uuid user-a --device eth0 --direction upload --rate 2048
```

Use this when you want one runtime-local shared pool for one UUID instead of separate per-session caps.

### Inbound Or Outbound Speed Limiter

```bash
sudo raylimit limit --pid 1234 --inbound api-in --device eth0 --direction upload --rate 2048
sudo raylimit limit --pid 1234 --outbound proxy-out --device eth0 --direction upload --rate 2048
```

Use these when the runtime tag is the operational identity you want to control.

## What Is Concrete Today

- IP is concrete when the direct client-IP attachment path is available.
- Inbound is concrete when readable runtime configuration proves one concrete TCP listener for the selected inbound tag.
- Outbound is concrete when readable runtime configuration proves one unique non-zero socket mark without proxy indirection.
- UUID is concrete when live membership can be attached safely through attachable client IPs or the current exact-user RoutingService socket scopes.
- Connection is not yet broadly developed as a concrete apply path; the current foundation stays conservative.

## What Blocked Means

Blocked execution is a deliberate safety outcome, not a generic failure. RayLimit blocks when:

- the runtime evidence is too weak
- the current selector is unreadable or ambiguous
- the current backend cannot produce an exact-user-safe attachment
- the host state cannot be compared safely enough for live mutation

That is especially important for UUID, inbound, outbound, and connection workflows, where “current scope” matters more than simple command syntax.
