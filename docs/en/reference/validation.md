# Validation

This runbook is for disciplined validation on a real Linux host with `tc`, root access, and at least one Xray runtime.

The goal is not broad mutation. The goal is to confirm discovery, inspection, dry-run planning, and concrete execution boundaries in a controlled order.

## Prerequisites

Before you validate RayLimit on a host, confirm:

- the `raylimit` binary is installed and in `PATH`
- the Linux `tc` userspace tool is installed
- you have root access for live mutation
- you know which network device you are prepared to touch
- an Xray runtime is actually running

## Readiness Checks

```bash
command -v raylimit
command -v tc
sudo -n true
ip link show dev eth0
```

Expected outcome:

- each command succeeds
- the selected device exists
- `sudo -n true` exits successfully if you plan to validate live execution

## Safe Validation Order

### 1. Discover Candidate Runtimes

```bash
sudo raylimit discover
```

Confirm that the intended runtime is visible and selectable.

### 2. Inspect The Selected Runtime

```bash
sudo raylimit inspect --pid 1234
sudo raylimit inspect --pid 1234 --format json
```

Confirm that the runtime metadata renders cleanly and that API-capability hints appear when they are available.

### 3. Preview Speed Limiters In Dry-Run Mode

```bash
sudo raylimit limit --pid 1234 --ip 203.0.113.10 --device eth0 --direction upload --rate 2048
sudo raylimit limit --pid 1234 --uuid user-a --device eth0 --direction upload --rate 2048
sudo raylimit limit --pid 1234 --inbound api-in --device eth0 --direction upload --rate 2048
sudo raylimit limit --pid 1234 --outbound proxy-out --device eth0 --direction upload --rate 2048
```

At this point you are checking:

- runtime selection
- subject selection
- observed state visibility
- decision correctness
- blocked vs concrete reporting

### 4. Execute Only Concrete Paths

Move to `--execute` only when the dry-run report shows a concrete path and the host is suitable for live mutation.

Example:

```bash
sudo raylimit limit --pid 1234 --ip 203.0.113.10 --device eth0 --direction upload --rate 2048 --execute
```

## Speed Limiter Expectations

### IP

IP is the most direct reference path. If the selected client IP is valid and the host state is comparable, IP should be the easiest family to validate concretely.

### UUID

UUID is concrete only when the shared-pool membership can be attached safely:

- attachable client IPs for every live member, or
- the current exact-user RoutingService socket scopes

If not, blocked UUID output is the correct validation result.

### Inbound

Inbound can execute only when readable runtime configuration proves one concrete TCP listener for the selected inbound tag.

### Outbound

Outbound can execute only when readable runtime configuration proves one unique non-zero socket mark without proxy indirection.

### Connection

Connection apply is not yet broadly developed as a concrete execution path. Dry-run and conservative cleanup remain meaningful validation targets.

## Remove Validation

Validate remove separately from apply:

```bash
sudo raylimit limit --pid 1234 --ip 203.0.113.10 --device eth0 --direction upload --remove
sudo raylimit limit --pid 1234 --ip 203.0.113.10 --device eth0 --direction upload --remove --execute
```

Remove should stay conservative. A safe no-op is a valid result when no RayLimit-managed state is present.

## What Good Validation Looks Like

You have a strong validation result when:

- discovery shows the intended runtime clearly
- inspection is readable in text and JSON
- dry-run output explains the chosen subject and decision clearly
- concrete speed limiter families execute only in their current safe scopes
- blocked families explain why they are blocked
- remove cleans only RayLimit-managed state
