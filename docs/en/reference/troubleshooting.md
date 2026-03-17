# Troubleshooting

This page covers the most common operator-facing problems and the product meaning behind them.

## `tc` Is Missing

If RayLimit cannot inspect or execute `tc`, install the Linux `tc` userspace tool and ensure it is in `PATH`.

Typical signal:

- `tc state inspection failed`
- `exec: "tc": executable file not found`

## Real Execution Is Blocked By Privilege

Real mutation requires root on Linux.

If dry-run works but `--execute` is blocked, rerun through a root path only on a host you are prepared to change.

## No Runtime Matches The Selection

If `inspect` or `limit` cannot find the target, verify the runtime is actually discoverable first:

```bash
sudo raylimit discover
```

Then repeat the command with the exact PID, container, or name selection you intend to use.

## Observed State Is Missing Or Not Comparable

If RayLimit cannot compare current backend state, live execution may stay blocked or downgraded to a more conservative outcome.

Read the observation section of the report first. It tells you whether the current state is:

- available
- comparable
- matched
- unavailable

## Inbound Or Outbound Execution Is Blocked

That usually means RayLimit could not derive one concrete selector from readable runtime configuration.

Common reasons:

- unreadable configuration
- ambiguous selector state
- inbound listener is not one concrete TCP listener
- outbound mark is zero, shared, or hidden behind proxy indirection

## UUID Execution Is Blocked

UUID blocks when live membership evidence is not concrete enough for safe shared-pool attachment.

Common reasons:

- missing attachable client IPs
- stale RoutingService evidence
- partial RoutingService evidence
- missing exact-user socket tuples for the current upload or download scope
- target-only routing context
- metadata-only routing context

That blocked result is intentional. RayLimit does not degrade UUID into a weaker shared identity just to force execution.

## Connection Apply Does Not Execute

That is expected today. The connection speed limiter has a real foundation for planning and cleanup, but it is not yet broadly developed as a concrete apply path.

## Remove Does Less Than Expected

Remove is conservative by design.

RayLimit only tears down backend state it can prove belongs to the current managed path. That means:

- a no-op remove can still be correct
- the root qdisc is removed only when the remaining state is clearly RayLimit-managed

## JSON Output Looks Different From Text Output

That is also expected. Text output is optimized for operators reading the terminal. JSON output is optimized for tools and automation. The underlying decision truth should still match.
