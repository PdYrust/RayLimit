<p align="center">
  <img src="assets/logo/raylimit-icon.svg" alt="RayLimit icon" width="144">
</p>

<h1 align="center">RayLimit</h1>

<p align="center">Reconcile-aware traffic shaping for Xray runtimes on Linux.</p>

<p align="center">
  <a href="LICENSE"><img src="https://img.shields.io/badge/license-AGPL--3.0-111111" alt="License: AGPL-3.0"></a>
  <img src="https://img.shields.io/badge/go-1.22%2B-00ADD8" alt="Go 1.22+">
  <img src="https://img.shields.io/badge/status-beta-111111" alt="Beta status">
  <a href="https://pdyrust.github.io/RayLimit/"><img src="https://img.shields.io/badge/docs-English%20and%20Persian--ready-0A7EA4" alt="Documentation"></a>
</p>

RayLimit is a Linux CLI for discovering Xray runtimes, inspecting runtime state, and applying guarded speed limiters with dry-run-first workflows.

The implemented speed limiter families are validated and actively developed. Their concrete execution scopes depend on the runtime evidence and selectors available on the host.

Current public release line: `v0.1.0-beta`.

## Install

From a release package:

```bash
tar -xzf raylimit_v0.1.0-beta_linux_amd64.tar.gz
cd raylimit_v0.1.0-beta_linux_amd64
sudo ./scripts/install.sh
```

From a local checkout:

```bash
make build
sudo ./scripts/install.sh
```

## Current Speed Limiter Families

| Speed limiter | Current release truth |
| --- | --- |
| `ip` | Validated and concrete for direct client-IP attachment, including native IPv6 within the current attachment assumptions |
| `uuid` | Validated and actively developed as the preferred identity-oriented path, with concrete shared-pool execution under attachable client IPs and the current exact-user RoutingService socket scopes |
| `inbound` | Validated and concrete when readable runtime configuration proves one concrete TCP listener for the selected inbound tag |
| `outbound` | Validated and concrete when readable runtime configuration proves one unique non-zero outbound socket mark without proxy indirection |
| `connection` | Not yet broadly developed. Foundational work is in place, and broader concrete support is planned for future releases |

## Common Commands

```bash
raylimit --help
raylimit discover
raylimit inspect --pid 1234
raylimit limit --pid 1234 --uuid user-a --device eth0 --direction upload --rate 2048
```

## Documentation

[Open the documentation hub](https://pdyrust.github.io/RayLimit/).

## Project

- Creator: YrustPd
- Repository: https://github.com/PdYrust/RayLimit
- Telegram: https://t.me/PdYrust

## License

RayLimit is licensed under the GNU Affero General Public License v3.0 (AGPL-3.0). See [LICENSE](LICENSE).
