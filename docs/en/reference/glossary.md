# Glossary

## Speed Limiter

A RayLimit control surface that selects traffic by one product-facing identity such as IP, UUID, inbound tag, outbound tag, or connection.

## Runtime Target

One discovered Xray runtime selected by PID, container identity, or another stable runtime-local selector.

## Runtime-Local

Scoped to one selected runtime target. The same UUID, inbound tag, outbound tag, or connection string on another runtime is a different subject.

## Dry-Run

The default execution mode. RayLimit plans and reports what it would do without mutating the host.

## Execute

The explicit live-mutation mode enabled with `--execute`.

## Direction

The upload or download side of a speed limiter policy. RayLimit plans one direction at a time.

## Direct Attachment

A concrete packet-facing `tc` attachment path that does not need an auxiliary marking backend.

## Mark-Backed Attachment

A shaping path where `nftables` produces or restores marks and `tc fw` uses those marks to attach traffic to the selected class.

## Shared UUID Pool

One runtime-local aggregate bandwidth pool for a selected UUID, shared across the live sessions that belong to that UUID on that runtime.

## Aggregate Membership

The currently trusted live sessions that belong to one runtime-local UUID shared pool.

## RoutingService Evidence

Runtime-linked routing context that can provide exact-user socket tuples for the current UUID non-IP attachment scopes.

## Selector

The concrete backend-facing identity RayLimit needs in order to classify traffic safely, such as a client IP, a concrete TCP listener, or a unique outbound socket mark.

## Comparable Observed State

Backend state RayLimit can inspect and compare safely before deciding whether the correct result is apply, no-op, remove, or blocked.

## Concrete Execution

A state where RayLimit has enough trustworthy evidence to attach traffic honestly and perform live mutation.

## Blocked By Design

An explicit safety verdict that prevents live mutation when RayLimit does not have enough trustworthy evidence to attach traffic honestly.
