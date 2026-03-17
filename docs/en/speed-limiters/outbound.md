# Outbound Speed Limiter

The outbound speed limiter shapes traffic selected by one runtime-local outbound tag.

Use it when the operational question is “cap this egress path” rather than “cap this one visible client IP” or “cap this one UUID.”

## What It Selects

The selected subject is one outbound tag on one chosen runtime target.

The speed limiter stays runtime-local:

- one runtime and one outbound tag produce one shaping subject
- the same tag on another runtime is a separate subject

## Concrete Execution Scope

Outbound execution is concrete when readable runtime configuration proves one unique non-zero outbound socket mark for the selected tag and no proxy or dialer-proxy indirection is involved.

In that scope, RayLimit uses:

- `nftables` output matching to identify the path
- `tc fw` to attach the traffic to the selected class

## Practical Example

Preview the outbound path:

```bash
sudo raylimit limit --pid 1234 --outbound proxy-out --device eth0 --direction upload --rate 2048
```

Execute only after the report shows a concrete selector:

```bash
sudo raylimit limit --pid 1234 --outbound proxy-out --device eth0 --direction upload --rate 2048 --execute
```

## What Blocks Execution

Execution remains blocked when the selected outbound path depends on:

- unreadable configuration
- zero or shared marks
- proxy chaining
- dialer-proxy indirection

RayLimit keeps those cases conservative instead of guessing a shared or unstable selector.

## Operational Guidance

Use outbound when the egress path is the real control surface you want to manage.

Prefer UUID when the real target is one user identity and shared tunnel or proxy IPs would be misleading.
