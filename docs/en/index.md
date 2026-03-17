# RayLimit Documentation

The English documentation is the primary reference track for RayLimit.

RayLimit is built for operators who need to inspect Xray runtimes and control traffic deliberately, and for technical readers who want a serious explanation of the product model and backend truth.

Use the header language selector to move between English and Persian documentation.

## Quick Start

If you are new to RayLimit, read these pages in order:

1. [Installation](getting-started/installation.md)
2. [Common commands](getting-started/common-commands.md)
3. [Practical usage](getting-started/practical-usage.md)
4. [Speed limiter families](speed-limiters/index.md)

That path is enough to get a Linux host installed, inspected, and into dry-run planning safely.

It also covers both supported execution styles:

- install from a release package and use `raylimit` from a normal system path
- run directly from source or a local build with `go run ./cmd/raylimit` or `./bin/raylimit`

## What The Product Does

RayLimit helps you:

- discover Xray runtimes on a Linux host
- inspect runtime state in text or JSON
- preview speed limiter decisions in dry-run mode
- apply concrete speed limiters only when the current runtime evidence is strong enough
- keep blocked states explicit instead of guessing with unsafe identities

## Current Scope Snapshot

| Area | Current release truth |
| --- | --- |
| Discovery and inspection | Practical and ready for operator use |
| Dry-run planning | The default and expected starting point for every speed limiter family |
| IP speed limiter | Concrete |
| UUID speed limiter | Concrete in the current safe evidence scopes |
| Inbound and outbound speed limiters | Concrete in their current selector-qualified scopes |
| Connection speed limiter | Not yet broadly developed; foundational work is in place |
