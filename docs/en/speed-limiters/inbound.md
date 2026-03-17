# Inbound Speed Limiter

The inbound speed limiter shapes traffic selected by one runtime-local inbound tag.

Use it when the operational question is “cap traffic for this inbound path” rather than “cap this one user identity” or “cap this one visible client IP.”

## What It Selects

The selected subject is one inbound tag on one chosen runtime target.

The speed limiter stays runtime-local:

- one runtime and one inbound tag produce one shaping subject
- another runtime with the same tag is a separate subject

## Concrete Execution Scope

Inbound execution is concrete when readable runtime configuration proves one concrete TCP listener for the selected inbound tag.

In that scope, RayLimit uses:

- `nftables` to classify the traffic
- `tc fw` to attach the traffic to the selected class

## Practical Example

Preview the current inbound path:

```bash
sudo raylimit limit --pid 1234 --inbound api-in --device eth0 --direction upload --rate 2048
```

Execute only when the dry-run report shows a concrete path:

```bash
sudo raylimit limit --pid 1234 --inbound api-in --device eth0 --direction upload --rate 2048 --execute
```

## What Blocks Execution

Execution remains blocked when the inbound selector is:

- unreadable
- ambiguous
- wildcard-only
- non-TCP

Those blocked states are part of the product contract. RayLimit reports them explicitly instead of collapsing them into a guessed attachment.

## Operational Guidance

Use inbound when the listener path is the operational identity you care about.

Prefer UUID when the real target is one user identity across live sessions.
