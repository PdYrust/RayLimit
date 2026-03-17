# Installation

RayLimit targets Linux hosts where traffic shaping is managed intentionally and conservatively.

This page covers the two supported ways to start using it:

1. install from a release package
2. run from source or a local build

Choose the first path when you want a normal host installation. Choose the second path when you want to evaluate, validate, or develop locally without downloading a prebuilt binary.

## Before You Start

RayLimit is most useful on a host that already has:

- a Linux `tc` userspace tool available in `PATH`
- at least one Xray runtime you can discover and inspect
- root access for live mutation when you move beyond dry-run

You can still build and run the CLI without those prerequisites, but realistic discovery and live traffic shaping depend on them.

## Path 1: Install From A Release Package

Use this path when you want the intended installed layout and a normal `raylimit` command in `PATH`.

```bash
tar -xzf raylimit_v0.1.0-beta_linux_amd64.tar.gz
cd raylimit_v0.1.0-beta_linux_amd64
sudo ./scripts/install.sh
```

This installs:

- the binary to `/usr/local/bin/raylimit`
- package metadata and helper scripts to `/usr/local/share/raylimit/`
- the configuration directory at `/etc/raylimit/`

### Verify The Installed Path

```bash
command -v raylimit
raylimit version
raylimit --help
```

## Path 2: Run From Source

Use this path when you want to work directly from a local checkout.

### Quick Check With `go run`

```bash
go run ./cmd/raylimit --help
```

This is the fastest way to confirm the CLI starts correctly from source.

### Build A Local Binary

```bash
make build
./bin/raylimit --help
```

This path gives you a local binary without installing RayLimit into a system path.

### Run Common Commands From The Local Build

```bash
sudo ./bin/raylimit discover
sudo ./bin/raylimit inspect --pid 1234
```

If you prefer, you can also run the same flows directly from source:

```bash
sudo go run ./cmd/raylimit discover
sudo go run ./cmd/raylimit inspect --pid 1234
```

## When To Choose Each Path

Choose the release-install path when:

- you want a clean host installation
- you want `raylimit` available in a standard system path
- you are preparing a production-like or long-lived validation host

Choose the source-run path when:

- you are evaluating the CLI locally
- you are developing or debugging
- you want to avoid installing the binary system-wide

## Update And Remove

For an installed release-package path:

```bash
sudo ./scripts/update.sh
sudo ./scripts/uninstall.sh
```

`update.sh` refreshes the managed installation from a release directory.
`uninstall.sh` removes RayLimit-managed files without deleting unrelated configuration.

Use the sidebar to continue into common commands, practical usage, and validation.
