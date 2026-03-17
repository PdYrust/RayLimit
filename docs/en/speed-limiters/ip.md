# IP Speed Limiter

The IP speed limiter is the most direct packet-facing speed limiter in RayLimit.

Use it when one visible client address is the correct shaping identity for the traffic you want to control.

## What It Selects

The selected subject is one visible client IP on one chosen runtime target.

That makes IP a practical fit for:

- direct clients
- simple edge-facing topologies
- situations where visible client IP really is the identity you want to shape

## Concrete Scope

The IP speed limiter is concrete through the direct client-IP attachment path.

Current address support:

- IPv4 is supported
- IPv4-mapped IPv6 is canonicalized to IPv4 when appropriate
- native IPv6 is supported within the current no-extension-header direct-attachment assumption

## Practical Examples

Upload side:

```bash
sudo raylimit limit --pid 1234 --ip 203.0.113.10 --device eth0 --direction upload --rate 2048
```

Download side:

```bash
sudo raylimit limit --pid 1234 --ip 2001:db8::10 --device eth0 --direction download --rate 4096
```

## When To Prefer Another Speed Limiter

IP is concrete and useful, but it is not always the best identity model.

Prefer UUID when:

- many users can appear behind one shared or tunnel-facing IP
- the product question is really about one user identity rather than one visible network address

## Operational Notes

IP is the clearest reference implementation for concrete execution in RayLimit. If you need the most straightforward path to live traffic shaping, start here.
