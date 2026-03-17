# Development And Internals

This page is for readers who want to work on RayLimit directly or understand the codebase with more precision than the operator pages require.

## Working Model

RayLimit is a Linux-oriented Go CLI with a dry-run-first operational model.

That means code changes should preserve these product-level rules:

- execution stays opt-in through `--execute`
- blocked states stay explicit and technically honest
- one runtime-local subject maps to one reconcile decision
- cleanup stays conservative

## Common Maintainer Commands

```bash
make fmt
make test
make build
make package
```

For direct Go work:

```bash
gofmt -w ./cmd ./internal
go test ./...
go build ./...
```

## Source Layout

| Path | Purpose |
| --- | --- |
| `cmd/raylimit` | CLI entrypoint |
| `internal/buildinfo` | build metadata surfaced by the CLI |
| `internal/cli` | help, command routing, text/JSON output, and workflow orchestration |
| `internal/discovery` | runtime discovery, inspection, output rendering, and runtime evidence |
| `internal/correlation` | UUID membership and aggregate logic |
| `internal/policy` | rule model, precedence, and effective directional limit evaluation |
| `internal/limiter` | desired state, applied state, and reconcile decisions |
| `internal/tc` | backend planning, guarded execution, state observation, and attachment logic |
| `scripts/` | install, update, and uninstall helpers |

## What “Validated And Actively Developed” Means

For RayLimit, that phrase has a precise meaning:

- the implemented speed limiter families have real command surfaces
- their current concrete scopes are exercised through tests and validation-oriented product behavior
- blocked states are part of the supported contract, not hidden gaps

It does not mean every speed limiter family is equally broad today. Scope still differs by backend truth and available runtime evidence.

## Working On Speed Limiter Families

Each speed limiter family has two layers:

- a logical identity model, such as IP, UUID, inbound tag, outbound tag, or connection
- a backend attachment model that determines whether execution is concrete today

When changing one of these families, review both:

- the logical subject semantics
- the concrete execution boundary

That is especially important for UUID, where the identity model is strong but the attachment path must remain exact-user-safe.

## Output And Contract Discipline

Changes to RayLimit should preserve the CLI contract:

- text output stays readable and operational
- JSON output stays machine-friendly
- blocked outcomes remain explicit
- no-op and remove behavior remain distinguishable from apply

## Related Material

- [Architecture](architecture.md)
- [Validation](../reference/validation.md)
- [Glossary](../reference/glossary.md)
- [Diagram workspace](../diagrams/index.md)
