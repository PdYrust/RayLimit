# Architecture

RayLimit is organized around one clear idea: select one runtime-scoped subject, evaluate whether that subject is concrete enough to shape safely, then either plan or execute the matching traffic-control work without guessing.

## End-To-End Flow

At a high level, every `limit` request follows the same control path:

1. discover and select one runtime target
2. inspect enough host-visible metadata to understand the runtime
3. build one logical speed limiter subject such as IP, UUID, inbound tag, outbound tag, or connection
4. observe current backend state
5. evaluate whether the subject can be shaped concretely today
6. produce a dry-run plan, a no-op result, a remove plan, or an explicit blocked verdict
7. execute only when the current path is concrete and execution has been requested explicitly

That flow is consistent across speed limiter families. What changes is the evidence and attachment model behind each family.

## Package Boundaries

| Package | Responsibility |
| --- | --- |
| `cmd/raylimit` | process entrypoint |
| `internal/buildinfo` | version and build metadata |
| `internal/cli` | command routing, help, text/JSON rendering, and orchestration |
| `internal/discovery` | runtime discovery, inspection, runtime evidence, and output rendering |
| `internal/correlation` | UUID membership and aggregate subject reduction |
| `internal/policy` | rule validation, precedence, and effective per-direction limit selection |
| `internal/limiter` | desired state, applied state, and reconcile decision modeling |
| `internal/tc` | planning, guarded execution, observed `tc`/`nftables` state, and backend-specific attachment logic |

## Runtime Targeting And Evidence

RayLimit stays runtime-local by design.

A selected subject always belongs to one chosen runtime target:

- one PID, container, or name selection produces one runtime target
- speed limiter subjects are then interpreted inside that runtime
- the same tag, UUID, or connection string on another runtime is a separate subject

Evidence quality determines how far RayLimit can go:

- some paths are concrete through packet-visible data
- some depend on readable runtime configuration
- some depend on live RoutingService evidence
- weak evidence keeps execution blocked by design

## Traffic Shaping Backends

RayLimit currently uses two backend families.

### Direct Attachment

This is the most straightforward path. RayLimit can attach traffic directly with packet-facing selectors.

Current concrete example:

- IP speed limiter by client IP, including the current native IPv6 scope

### Mark-Backed Attachment

Some speed limiter families are not directly packet-visible. In those cases, RayLimit uses a mark-backed model:

- `nftables` classifies traffic or restores a connection-associated mark
- `tc fw` attaches the marked traffic to the selected class

Current concrete examples:

- inbound when one concrete TCP listener can be derived conservatively
- outbound when one unique non-zero socket mark can be derived conservatively
- UUID in the current non-IP exact-user RoutingService socket scopes

## Speed Limiter Truth By Family

| Speed limiter family | Logical subject | Current backend truth |
| --- | --- | --- |
| IP | one visible client IP on one runtime | direct attachment |
| UUID | one runtime-local shared UUID pool | direct attachment for attachable client IPs, mark-backed attachment for the current exact-user RoutingService socket scopes |
| Inbound | one inbound tag on one runtime | mark-backed when one concrete TCP listener is available |
| Outbound | one outbound tag on one runtime | mark-backed when one unique non-zero socket mark is available |
| Connection | one runtime-local connection identity | planning and cleanup foundation only |

## Decision Model

Three ideas shape the product behavior:

### Dry-Run First

Planning without mutation is the default for every speed limiter family.

### Comparable Observed State

RayLimit prefers to compare current backend state before execution. That keeps no-op detection, delta apply, and cleanup honest.

### Blocked By Design

When the current path is not exact enough to attach traffic safely, RayLimit blocks explicitly instead of inventing a weaker identity.

That is most visible in:

- UUID shared-pool execution
- inbound and outbound selector derivation
- connection apply execution

## Why The Product Feels Consistent

Even though the speed limiter families differ technically, the operator contract stays stable:

- one runtime target
- one logical subject
- one direction at a time
- dry-run by default
- explicit concrete or blocked verdict
- conservative cleanup
