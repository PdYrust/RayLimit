# Contributing

RayLimit contributions should improve the project without making it noisier, broader, or less honest about current product scope.

## Before You Start

- Read the current `README.md` and the relevant pages under `docs-site/pages/`.
- Check existing issues before opening a new one or starting overlapping work.
- Prefer one clear change per pull request.
- Open or comment on an issue first if the change would broaden a speed limiter scope, change operator-facing behavior, or reshape a public surface.

## Prerequisites

- **Go 1.22+** (see `go.mod`).
- **make** — all validation flows go through the Makefile.
- **shellcheck** — required only when you touch `scripts/`.
- **npm** — required only when you touch `docs-site/`.

## Working Style

- Preserve current release truth. If a speed limiter is concrete only in a narrow scope, keep that boundary explicit.
- Keep changes reviewable. Small patches with clear reasoning are preferred over broad refactors.
- Update tests when behavior changes.
- Update docs, help text, or output examples when public behavior changes.
- Avoid speculative scaffolding unless it materially improves the current codebase.

## Development Workflow

Use the narrowest validation that matches your change, then include the exact commands in your pull request.

Baseline checks for any Go change:

- `make fmt`
- `make vet`
- `make test` (runs `go vet` then the full suite)
- `make build`

Conditional checks:

- `make test-race` — **required** for any change touching concurrency (goroutines, shared state, channels, `sync`).
- `make vuln` — runs `govulncheck`; run it when you add or update dependencies.
- `make shellcheck` — runs `shellcheck -x scripts/*.sh`; **required** for any change touching `scripts/`.
- `make package` / `make verify-packages` — when you change release packaging or installer behavior.

## Environment Variables For Testing

Each global override flag has a `RAYLIMIT_` environment fallback. The flag wins; the environment variable is the lowest-priority fallback and is consulted only when the flag is not set. This makes env vars convenient for tests and CI without rewriting command lines.

| Environment variable | Equivalent flag | Notes |
| -------------------- | --------------- | ----- |
| `RAYLIMIT_XRAY_BINARY` | `--xray-binary` | Xray binary path/name |
| `RAYLIMIT_CONTAINER_CLI` | `--container-cli` | `docker` (default), `podman`, `nerdctl` |
| `RAYLIMIT_TC_BINARY` | `--tc-binary` | `tc` binary path |
| `RAYLIMIT_NFT_BINARY` | `--nft-binary` | `nft` binary path |
| `RAYLIMIT_LOG_LEVEL` | `--log-level` | `error\|warn\|info\|debug` (default `error`) |
| `RAYLIMIT_SKIP_PRIVILEGE_CHECK` | `--skip-privilege-check` (`limit`) | Trust `CAP_NET_ADMIN`; real `tc` still enforces `EPERM` |
| `RAYLIMIT_SKIP_CHECKSUM` | `--skip-checksum` (installer scripts) | Bypass `SHA256SUMS` verification |

## Adding a New Xray-Family Binary To Detection

Detection prefix-matches a normalized binary basename (lowercase, trailing `.exe` removed) against an allowlist.

1. Add the new lowercase basename prefix to `xrayRuntimeAliases` in `internal/discovery/xray_runtime_alias.go`. If the binary is a fork that needs fork-specific behavior, also add it to `sanaeiRuntimeAliases` (or the relevant fork list).
2. Because matching is a prefix match, you only need the stem — `xray` already covers `xray-linux-amd64`, and the truncated `/proc/<pid>/comm` form.
3. Add a test case alongside the existing alias tests asserting the new binary matches (and, for a fork, that it is distinguished from vanilla `xray`/`xray-core`).
4. Run `make test`.

## Adding a New Global Flag

Global overrides follow one wiring pattern in `internal/cli/cli.go`:

1. Add a field to the `cliOverrides` struct.
2. Add a `case` in `globalOverrideTarget` mapping the flag name to that field.
3. Add the `RAYLIMIT_*` fallback in `resolveOverrides` (flag wins; env is the fallback).
4. Add a one-line entry to the global-overrides help text.
5. Thread the resolved value to its consumer.
6. Add tests mirroring the existing override tests (flag parsing, env fallback, flag-wins-over-env, default behavior).

Keep the env-var name consistent with the existing `RAYLIMIT_` convention and document it in `README.md` and `docs-site/` when it is user-facing.

## Reproducible Builds

The build stamps a UTC build time into the binary. Set `SOURCE_DATE_EPOCH` to a fixed Unix timestamp to make it deterministic:

```bash
SOURCE_DATE_EPOCH=0 make build
SOURCE_DATE_EPOCH=0 make build
```

Two builds with the same `SOURCE_DATE_EPOCH` must produce byte-identical binaries (compare with `sha256sum`). When unset, the current time is used. Reproducibility via `SOURCE_DATE_EPOCH` relies on GNU `date` (the Linux target).

## Pull Request Checklist

Each item is verifiable with a concrete command:

- [ ] `make test` passes (add `make test-race` if the change touches concurrency).
- [ ] `make vet` is clean.
- [ ] `make shellcheck` is clean (only if you changed `scripts/`).
- [ ] `make vuln` is clean (only if you changed dependencies).
- [ ] Docs updated — `README.md` and/or `docs-site/` — if user-facing behavior, flags, or output changed.
- [ ] Reproducibility holds — two `SOURCE_DATE_EPOCH=0 make build` runs match (only if you changed build/packaging).
- [ ] The PR description explains what changed, why, and how it was validated — without pasting implementation code.

A good pull request makes four things easy to review: what changed, why it changed, how it was validated, and whether docs, help text, or operator-facing output changed. If a change is intentionally narrow, say so. If it leaves a boundary in place, say that too.

## Licensing

By contributing to RayLimit, you agree that your contributions will be distributed under the repository's AGPL-3.0 license.
