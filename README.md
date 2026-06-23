<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="assets/logo/raylimit-icon-white.svg">
    <img src="assets/logo/raylimit-icon.svg" alt="RayLimit icon" width="144">
  </picture>
</p>

<h1 align="center">RayLimit</h1>

<p align="center">Reconcile-aware traffic shaping for Xray runtimes on Linux.</p>

<p align="center">
  <a href="LICENSE"><img src="https://img.shields.io/badge/license-AGPL--3.0-111111" alt="License: AGPL-3.0"></a>
  <img src="https://img.shields.io/badge/go-1.22%2B-00ADD8" alt="Go 1.22+">
  <img src="https://img.shields.io/badge/status-beta-111111" alt="Beta status">
  <a href="https://pdyrust.github.io/RayLimit/"><img src="https://img.shields.io/badge/docs-English-0A7EA4" alt="Documentation"></a>
  <a href="https://t.me/PdYrust"><img src="https://img.shields.io/badge/Telegram-%40PdYrust-229ED9?logo=telegram&logoColor=white" alt="Telegram channel"></a>
</p>

RayLimit is a Linux CLI for discovering Xray runtimes, inspecting runtime state, and applying guarded speed limiters with dry-run-first workflows.

The implemented speed limiter families are validated and actively developed. Their concrete execution scopes depend on the runtime evidence and selectors available on the host.

Current public release line: `v0.4.0-beta`.

## Install

From a release package:

```bash
tar -xzf raylimit_v0.4.0-beta_linux_amd64.tar.gz
cd raylimit_v0.4.0-beta_linux_amd64
sudo ./scripts/install.sh
```

From a local checkout:

```bash
make build
sudo ./scripts/install.sh
```

The installer verifies the release `SHA256SUMS` before copying anything into place and refuses to continue if a file does not match. Pass `--skip-checksum` to bypass verification (not recommended). `update.sh` performs the same check.

## Recent Changes

Highlights since the previous release line. See the [documentation hub](https://pdyrust.github.io/RayLimit/) for details.

- **Sanaei-fork support.** Discovery recognizes `sanaei*` fork binaries in addition to vanilla `xray`/`xray-core`. When a fork's `StatsUserOnline` service is not enabled, live session queries now report a clear, actionable error instead of a silent "no sessions".
- **Plain-text `tc`/`nft` fallback.** State parsing works on hosts whose `tc` or `nft` ignore JSON (`-j`) output, falling back to plain-text parsing automatically.
- **Idempotent re-apply.** Re-applying a limit against an already-managed device preserves existing sibling classes and filters instead of tearing the tree down, with an execution-time recovery backstop.
- **Binary-override flags.** `--xray-binary`, `--tc-binary`, `--nft-binary`, and `--container-cli` (each with a `RAYLIMIT_*` env equivalent) let you point RayLimit at non-standard binaries.
- **Checksum-verified install.** `install.sh` and `update.sh` verify the packaged `SHA256SUMS`.

## Current Speed Limiter Families

| Speed limiter | Current release truth                                                                                                                                                                                |
| ------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `ip`          | Validated and concrete for a runtime-local `--ip all` baseline, specific per-IP overrides, and specific per-IP unlimited exceptions, including native IPv6 within the current attachment assumptions |
| `inbound`     | Validated and concrete when readable runtime configuration proves one concrete TCP listener for the selected inbound tag                                                                             |
| `outbound`    | Validated and concrete when readable runtime configuration proves one unique non-zero outbound socket mark without proxy indirection                                                                 |

## Common Commands

```bash
raylimit --help
raylimit discover
raylimit discover --xray-binary /opt/sanaei/sanaei-linux-amd64
raylimit inspect --pid 1234
raylimit limit --pid 1234 --inbound api-in --device eth0 --direction upload --rate 2048
```

## Global Flags

Place global flags before the subcommand. A flag wins over its environment variable.

| Flag                    | Environment variable      | Purpose                                                                  |
| ----------------------- | ------------------------- | ------------------------------------------------------------------------ |
| `--xray-binary <path>`  | `RAYLIMIT_XRAY_BINARY`    | Override the Xray binary path/name                                       |
| `--container-cli <name>`| `RAYLIMIT_CONTAINER_CLI`  | Container CLI for discovery and queries (default `docker`; `podman`, `nerdctl`) |
| `--tc-binary <path>`    | `RAYLIMIT_TC_BINARY`      | Override the `tc` binary path                                            |
| `--nft-binary <path>`   | `RAYLIMIT_NFT_BINARY`     | Override the `nft` binary path                                           |
| `--log-level <level>`   | `RAYLIMIT_LOG_LEVEL`      | Diagnostic verbosity: `error\|warn\|info\|debug` (default `error`)       |

The `limit` command additionally accepts `--skip-privilege-check` (env `RAYLIMIT_SKIP_PRIVILEGE_CHECK`) to skip the up-front privilege check and trust `CAP_NET_ADMIN`; real `tc` commands still enforce `EPERM`.

## Documentation

[Open the documentation hub](https://pdyrust.github.io/RayLimit/).

## Development

Contributions are welcome — see [CONTRIBUTING.md](CONTRIBUTING.md) for working style and pull-request expectations.

Common local checks:

```bash
make test         # go vet + full test suite
make test-race    # test suite under the race detector
make vet          # go vet across all packages
make vuln         # govulncheck across all packages
make shellcheck   # shellcheck the release shell scripts
```

## Project

-   Creator: YrustPd
-   Repository: https://github.com/PdYrust/RayLimit

## License

RayLimit is licensed under the GNU Affero General Public License v3.0 (AGPL-3.0). See [LICENSE](LICENSE).
