# Connection Speed Limiter

The connection speed limiter has a real foundation in the product, but it is not yet broadly developed as a concrete execution path.

Use it today when you want:

- session-scoped planning
- honest dry-run reporting
- conservative cleanup of observed managed state

## What Exists Now

The current foundation includes:

- conservative planning for one runtime-local connection identity
- guarded reporting that makes the apply boundary explicit
- deterministic cleanup of observed RayLimit-managed state on remove

## What Still Stops Concrete Apply

Connection-scoped apply needs a trustworthy runtime-aware classifier that can map one live connection to a stable kernel-visible identity.

That broader support is planned for future releases.

## Practical Expectation

Previewing a connection speed limiter is still useful:

```bash
sudo raylimit limit --pid 1234 --connection conn-1 --device eth0 --direction upload --rate 2048
```

Remove execution is also meaningful when you need to clean observed managed state:

```bash
sudo raylimit limit --pid 1234 --connection conn-1 --device eth0 --direction upload --remove --execute
```

What you should not expect today is broad concrete apply execution for connection-scoped shaping.
