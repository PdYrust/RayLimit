# Common Commands

These commands cover the normal operator workflow from discovery through dry-run planning and controlled execution.

## Choose Your Command Prefix

The examples below use the installed command:

```bash
raylimit ...
```

If you are running from source instead of an installed release package, replace that prefix with one of these:

```bash
go run ./cmd/raylimit ...
./bin/raylimit ...
```

The command behavior is the same. The difference is only how you launch the binary.

## Discover Runtimes

Start by listing the runtimes RayLimit can currently see:

```bash
sudo raylimit discover
```

Use JSON when you want a machine-readable list:

```bash
sudo raylimit discover --format json
```

## Inspect One Runtime

Inspect one selected runtime before you plan any speed limiter:

```bash
sudo raylimit inspect --pid 1234
sudo raylimit inspect --pid 1234 --format json
```

This gives you the current runtime identity, host-visible metadata, and API-capability hints when they are available.

If you are running from source, these are the direct equivalents:

```bash
go run ./cmd/raylimit --help
make build
./bin/raylimit --help
```

## Preview A Speed Limiter

Dry-run is the default. Start there:

```bash
sudo raylimit limit --pid 1234 --ip 203.0.113.10 --device eth0 --direction upload --rate 2048
```

For the preferred identity-oriented shared-pool path:

```bash
sudo raylimit limit --pid 1234 --uuid user-a --device eth0 --direction upload --rate 2048
```

## Apply A Concrete Speed Limiter

Add `--execute` only when the dry-run output shows a concrete execution path:

```bash
sudo raylimit limit --pid 1234 --outbound proxy-out --device eth0 --direction upload --rate 2048 --execute
```

## Remove Managed State Conservatively

Remove uses the same selection model and stays conservative:

```bash
sudo raylimit limit --pid 1234 --ip 203.0.113.10 --device eth0 --direction upload --remove --execute
```

## Work In JSON When You Need Automation

The same commands can be rendered in JSON:

```bash
sudo raylimit limit --pid 1234 --uuid user-a --device eth0 --direction upload --rate 2048 --format json
```

## Check Version And Build Metadata

```bash
raylimit version
```

Use the sidebar to continue into practical usage, speed limiter families, and troubleshooting.
