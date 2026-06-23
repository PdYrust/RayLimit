# Security Policy

This document describes RayLimit's security-relevant behavior and how to report a vulnerability. RayLimit mutates host traffic-control state and runs with elevated privilege, so the guarantees below matter operationally.

## Binary Integrity

Release packages ship a `SHA256SUMS` manifest. `scripts/install.sh` and `scripts/update.sh` verify every packaged file against that manifest before copying anything into place:

- if a file does not match, installation aborts (the package may be corrupt or tampered with);
- if the `SHA256SUMS` file is absent, installation aborts;
- if `sha256sum` is not available on the host, installation aborts.

The `--skip-checksum` flag (which sets `RAYLIMIT_SKIP_CHECKSUM=1`) bypasses this verification. It is intended for development against a hand-assembled or unsigned package only. Do not use it for production installs — it disables the integrity guard.

Builds are reproducible: the build stamps a UTC build time that is made deterministic by setting `SOURCE_DATE_EPOCH` to a fixed Unix timestamp. Two builds with the same `SOURCE_DATE_EPOCH` produce byte-identical binaries, which lets you independently rebuild and compare a release artifact. Reproducibility via `SOURCE_DATE_EPOCH` relies on GNU `date` (the Linux target).

## Privilege Model

Real `tc` mutation requires either root or the `CAP_NET_ADMIN` capability. Dry-run planning needs no elevated privilege. Before executing, RayLimit gates privilege in this precedence:

1. `--skip-privilege-check` (or `RAYLIMIT_SKIP_PRIVILEGE_CHECK`) — operator escape hatch that bypasses all up-front checks.
2. Effective UID 0 — root fast-path, always sufficient, never probes.
3. A read-only `CAP_NET_ADMIN` probe — for non-root processes, RayLimit runs `tc qdisc show dev lo` (read-only, side-effect-free, time-bounded). If it succeeds, execution is allowed; any failure, hang, or missing `tc` falls back to the UID decision and yields a clear error explaining both remediation paths (run as root, or grant `CAP_NET_ADMIN`, e.g. systemd `AmbientCapabilities=CAP_NET_ADMIN`).

Use `--skip-privilege-check` only when the host genuinely has capability-based `tc` access that the probe cannot detect (for example certain container capability configurations). The escape hatch only skips the up-front check — the real `tc` command still fails with `EPERM` if privilege is actually missing, so it cannot grant access that the kernel withholds.

## Log Safety

Diagnostic log fields are quoted whenever a value contains whitespace, field delimiters, shell metacharacters, or control characters, so a crafted value (for example an attacker-influenced runtime name) cannot forge additional log fields or inject shell/ANSI sequences into a diagnostic line.

This hardening reduces log-forging risk but does not make logs safe to execute. Treat log output as untrusted input: do not pipe it into a shell, `eval` it, or interpolate it into commands without your own validation.

## Reporting A Vulnerability

Do not report security issues through public issues or public discussions.

Use GitHub Security Advisories for private disclosure when that channel is available for this repository.

If private advisory reporting is unavailable, contact the maintainer as `@YrustPd` first and request a private reporting path before sending exploit details.

Include enough information to assess the issue quickly:

- affected RayLimit version, branch, or commit
- Linux distribution and kernel when relevant
- reproduction steps or a proof of concept
- expected impact
- any mitigation you already confirmed

## Supported Versions

RayLimit is currently in its public beta line.

Security fixes are expected to target:

- the current public beta release line
- the current `main` branch when the issue has not yet been released

Older beta builds may not receive backported fixes.
