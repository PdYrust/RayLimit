# Contributing

RayLimit contributions should improve the project without making it noisier, broader, or less honest about current product scope.

## Before You Start

- Read the current `README.md` and the relevant pages under `docs/`.
- Check existing issues before opening a new one or starting overlapping work.
- Prefer one clear change per pull request.
- Open or comment on an issue first if the change would broaden a speed limiter scope, change operator-facing behavior, or reshape a public surface.

## Working Style

- Preserve current release truth. If a speed limiter is concrete only in a narrow scope, keep that boundary explicit.
- Keep changes reviewable. Small patches with clear reasoning are preferred over broad refactors.
- Update tests when behavior changes.
- Update docs, help text, or output examples when public behavior changes.
- Avoid speculative scaffolding unless it materially improves the current codebase.

## Local Validation

Use the narrowest validation that matches your change, then include the exact commands in your pull request.

Common checks:

- `make fmt`
- `make test`
- `make build`

If you change release packaging or installer behavior, also run the relevant package target:

- `make package`
- `make verify-packages`

## Pull Requests

A good pull request makes four things easy to review:

- what changed
- why it changed
- how it was validated
- whether docs, help text, or operator-facing output changed

If a change is intentionally narrow, say so. If it leaves a boundary in place, say that too.

## Licensing

By contributing to RayLimit, you agree that your contributions will be distributed under the repository's AGPL-3.0 license.
