SHELL := /bin/sh

APP := raylimit
CMD := ./cmd/$(APP)
GO ?= go
INSTALL ?= install
TAR ?= tar
SHA256SUM ?= sha256sum

VERSION_FILE ?= VERSION
VERSION ?= $(strip $(shell cat $(VERSION_FILE) 2>/dev/null || printf 'dev'))
VERSION_CORE := $(if $(filter v%,$(VERSION)),$(patsubst v%,%,$(VERSION)),$(VERSION))
VERSION_TAG := v$(VERSION_CORE)
COMMIT ?= $(shell git rev-parse --short HEAD 2>/dev/null || printf 'unknown')
# BUILD_TIME stamps the binary's build time. The -d argument is added only when
# SOURCE_DATE_EPOCH is set, so:
#   - set to a valid epoch -> that UTC instant is used (reproducible build);
#   - unset                -> the current UTC time is used (normal build);
#   - set but invalid (or date(1) lacks GNU -d, e.g. macOS/BSD) -> the first
#     date(1) fails and the `|| date -u` fallback yields the current UTC time so
#     the build never breaks.
# Reproducible builds via SOURCE_DATE_EPOCH require GNU date (the Linux target).
BUILD_TIME ?= $(shell date -u $${SOURCE_DATE_EPOCH:+-d @$$SOURCE_DATE_EPOCH} '+%Y-%m-%dT%H:%M:%SZ' 2>/dev/null || date -u '+%Y-%m-%dT%H:%M:%SZ')

BIN_DIR ?= bin
DIST_DIR ?= dist
CGO_ENABLED ?= 0
GO_BUILD_FLAGS ?= -trimpath -buildvcs=false

BUILDINFO_PKG := github.com/PdYrust/RayLimit/internal/buildinfo
GO_LDFLAGS := -X $(BUILDINFO_PKG).Version=$(VERSION_TAG) -X $(BUILDINFO_PKG).Commit=$(COMMIT) -X $(BUILDINFO_PKG).BuildTime=$(BUILD_TIME)

LINUX_AMD64_PACKAGE := $(DIST_DIR)/$(APP)_$(VERSION_TAG)_linux_amd64.tar.gz
LINUX_ARM64_PACKAGE := $(DIST_DIR)/$(APP)_$(VERSION_TAG)_linux_arm64.tar.gz
PACKAGE_MANIFEST := PACKAGE-MANIFEST.txt
CHECKSUM_MANIFEST := SHA256SUMS

.DEFAULT_GOAL := help

.PHONY: help fmt test test-race vet vuln build clean package package-linux-amd64 package-linux-arm64 check validate-version package-contract-check verify-packages shellcheck

help:
	@printf '%s\n' \
		'RayLimit maintainer targets:' \
		'  make fmt                 Run gofmt on cmd and internal packages' \
		'  make test                Run go vet then the full Go test suite' \
		'  make test-race           Run the Go test suite with the race detector (slower)' \
		'  make vet                 Run go vet across all packages' \
		'  make vuln                Run govulncheck across all packages' \
		'  make shellcheck          Run shellcheck on the release shell scripts' \
		'  make build               Build the host binary at bin/raylimit' \
		'  make package             Build Linux amd64 and arm64 release archives in dist/' \
		'  make package-linux-amd64 Build the Linux amd64 release archive' \
		'  make package-linux-arm64 Build the Linux arm64 release archive' \
		'  make verify-packages     Verify dist/ archives, manifests, and checksums for the current VERSION' \
		'  make clean               Remove bin/ and dist/ outputs' \
		'' \
		'Packaging contract:' \
		'  dist/raylimit_v<version>_linux_<arch>/' \
		'    raylimit' \
		'    PACKAGE-MANIFEST.txt' \
		'    SHA256SUMS' \
		'    README.md' \
		'    LICENSE' \
		'    VERSION' \
		'    scripts/install.sh' \
		'    scripts/update.sh' \
		'    scripts/uninstall.sh' \
		'    scripts/installer-common.sh' \
		'  dist/raylimit_v<version>_linux_<arch>.tar.gz' \
		'  dist/raylimit_v<version>_linux_<arch>.tar.gz.sha256' \
		'' \
		'Current version: $(VERSION_TAG)'

fmt:
	gofmt -w ./cmd ./internal

vet:
	$(GO) vet ./...

test: vet
	$(GO) test ./...

test-race:
	$(GO) test -race ./...

vuln:
	$(GO) run golang.org/x/vuln/cmd/govulncheck@latest ./...

shellcheck:
	shellcheck -x scripts/*.sh

build:
	mkdir -p $(BIN_DIR)
	CGO_ENABLED=$(CGO_ENABLED) $(GO) build $(GO_BUILD_FLAGS) -ldflags "$(GO_LDFLAGS)" -o $(BIN_DIR)/$(APP) $(CMD)

check: test build

package: package-linux-amd64 package-linux-arm64

package-linux-amd64:
	$(MAKE) package-one TARGET_OS=linux TARGET_ARCH=amd64

package-linux-arm64:
	$(MAKE) package-one TARGET_OS=linux TARGET_ARCH=arm64

.PHONY: package-one
validate-version:
	@case "$(VERSION_CORE)" in \
		''|*[!A-Za-z0-9._-]*) \
			echo "error: VERSION must contain only letters, digits, dot, underscore, or hyphen for stable artifact names" >&2; \
			exit 1; \
			;; \
	esac

package-contract-check:
	@test -f README.md || { echo "error: README.md is required for release packaging" >&2; exit 1; }
	@test -f LICENSE || { echo "error: LICENSE is required for release packaging" >&2; exit 1; }
	@test -f $(VERSION_FILE) || { echo "error: $(VERSION_FILE) is required for release packaging" >&2; exit 1; }
	@test -f scripts/install.sh || { echo "error: scripts/install.sh is required for release packaging" >&2; exit 1; }
	@test -f scripts/update.sh || { echo "error: scripts/update.sh is required for release packaging" >&2; exit 1; }
	@test -f scripts/uninstall.sh || { echo "error: scripts/uninstall.sh is required for release packaging" >&2; exit 1; }
	@test -f scripts/installer-common.sh || { echo "error: scripts/installer-common.sh is required for release packaging" >&2; exit 1; }

package-one: validate-version package-contract-check
	@test -n "$(TARGET_OS)" || { echo "TARGET_OS is required"; exit 1; }
	@test -n "$(TARGET_ARCH)" || { echo "TARGET_ARCH is required"; exit 1; }
	@pkg_name="$(APP)_$(VERSION_TAG)_$(TARGET_OS)_$(TARGET_ARCH)"; \
	pkg_dir="$(DIST_DIR)/$$pkg_name"; \
	archive="$(DIST_DIR)/$$pkg_name.tar.gz"; \
	archive_tmp="$(DIST_DIR)/.$$pkg_name.tar.gz.tmp"; \
	checksum="$$archive.sha256"; \
	checksum_tmp="$(DIST_DIR)/.$$pkg_name.tar.gz.sha256.tmp"; \
	manifest="$$pkg_dir/$(PACKAGE_MANIFEST)"; \
	echo "Packaging $$pkg_name"; \
	rm -rf "$$pkg_dir" "$$archive" "$$archive_tmp" "$$checksum" "$$checksum_tmp"; \
	mkdir -p "$$pkg_dir/scripts"; \
	CGO_ENABLED=$(CGO_ENABLED) GOOS="$(TARGET_OS)" GOARCH="$(TARGET_ARCH)" \
		$(GO) build $(GO_BUILD_FLAGS) -ldflags "$(GO_LDFLAGS)" -o "$$pkg_dir/$(APP)" $(CMD); \
	printf '%s\n' \
		"package=$$pkg_name" \
		"version=$(VERSION_TAG)" \
		"os=$(TARGET_OS)" \
		"arch=$(TARGET_ARCH)" \
		"binary=$(APP)" \
		"archive=$$pkg_name.tar.gz" \
		"checksum=$$pkg_name.tar.gz.sha256" \
		"readme=README.md" \
		"license=LICENSE" \
		"version_file=VERSION" \
		"installer=scripts/install.sh" \
		"updater=scripts/update.sh" \
		"uninstaller=scripts/uninstall.sh" \
		"helper=scripts/installer-common.sh" \
		"checksums=$(CHECKSUM_MANIFEST)" \
		> "$$manifest"; \
	$(INSTALL) -m 0644 README.md "$$pkg_dir/README.md"; \
	$(INSTALL) -m 0644 LICENSE "$$pkg_dir/LICENSE"; \
	$(INSTALL) -m 0644 $(VERSION_FILE) "$$pkg_dir/VERSION"; \
	$(INSTALL) -m 0755 scripts/install.sh "$$pkg_dir/scripts/install.sh"; \
	$(INSTALL) -m 0755 scripts/update.sh "$$pkg_dir/scripts/update.sh"; \
	$(INSTALL) -m 0755 scripts/uninstall.sh "$$pkg_dir/scripts/uninstall.sh"; \
	$(INSTALL) -m 0755 scripts/installer-common.sh "$$pkg_dir/scripts/installer-common.sh"; \
	( cd "$$pkg_dir" && find . -type f ! -name '$(CHECKSUM_MANIFEST)' | LC_ALL=C sort | sed 's|^\./||' | xargs $(SHA256SUM) > "$(CHECKSUM_MANIFEST)" ); \
	chmod 0644 "$$pkg_dir/$(CHECKSUM_MANIFEST)"; \
	$(TAR) -C "$(DIST_DIR)" -czf "$$archive_tmp" "$$pkg_name"; \
	mv "$$archive_tmp" "$$archive"; \
	(cd "$(DIST_DIR)" && $(SHA256SUM) "$$pkg_name.tar.gz" > "$$(basename "$$checksum_tmp")"); \
	mv "$$checksum_tmp" "$$checksum"; \
	echo "Created $$archive"; \
	echo "Created $$checksum"

verify-packages: validate-version
	@for arch in amd64 arm64; do \
		pkg_name="$(APP)_$(VERSION_TAG)_linux_$$arch"; \
		pkg_dir="$(DIST_DIR)/$$pkg_name"; \
		archive="$(DIST_DIR)/$$pkg_name.tar.gz"; \
		checksum="$$archive.sha256"; \
		test -f "$$archive" || { echo "error: missing $$archive" >&2; exit 1; }; \
		test -f "$$checksum" || { echo "error: missing $$checksum" >&2; exit 1; }; \
		test -x "$$pkg_dir/$(APP)" || { echo "error: missing $$pkg_dir/$(APP)" >&2; exit 1; }; \
		test -f "$$pkg_dir/$(PACKAGE_MANIFEST)" || { echo "error: missing $$pkg_dir/$(PACKAGE_MANIFEST)" >&2; exit 1; }; \
		test -f "$$pkg_dir/README.md" || { echo "error: missing $$pkg_dir/README.md" >&2; exit 1; }; \
		test -f "$$pkg_dir/LICENSE" || { echo "error: missing $$pkg_dir/LICENSE" >&2; exit 1; }; \
		test -f "$$pkg_dir/VERSION" || { echo "error: missing $$pkg_dir/VERSION" >&2; exit 1; }; \
		test -f "$$pkg_dir/scripts/install.sh" || { echo "error: missing $$pkg_dir/scripts/install.sh" >&2; exit 1; }; \
		test -f "$$pkg_dir/scripts/update.sh" || { echo "error: missing $$pkg_dir/scripts/update.sh" >&2; exit 1; }; \
		test -f "$$pkg_dir/scripts/uninstall.sh" || { echo "error: missing $$pkg_dir/scripts/uninstall.sh" >&2; exit 1; }; \
		test -f "$$pkg_dir/scripts/installer-common.sh" || { echo "error: missing $$pkg_dir/scripts/installer-common.sh" >&2; exit 1; }; \
		test -f "$$pkg_dir/$(CHECKSUM_MANIFEST)" || { echo "error: missing $$pkg_dir/$(CHECKSUM_MANIFEST)" >&2; exit 1; }; \
		( cd "$$pkg_dir" && $(SHA256SUM) -c "$(CHECKSUM_MANIFEST)" >/dev/null ) || { echo "error: $$pkg_dir/$(CHECKSUM_MANIFEST) verification failed" >&2; exit 1; }; \
		$(TAR) -tzf "$$archive" | grep -Fx "$$pkg_name/$(PACKAGE_MANIFEST)" >/dev/null || { echo "error: $$archive is missing $(PACKAGE_MANIFEST)" >&2; exit 1; }; \
		$(TAR) -tzf "$$archive" | grep -Fx "$$pkg_name/scripts/install.sh" >/dev/null || { echo "error: $$archive is missing scripts/install.sh" >&2; exit 1; }; \
		$(TAR) -tzf "$$archive" | grep -Fx "$$pkg_name/scripts/update.sh" >/dev/null || { echo "error: $$archive is missing scripts/update.sh" >&2; exit 1; }; \
		$(TAR) -tzf "$$archive" | grep -Fx "$$pkg_name/scripts/uninstall.sh" >/dev/null || { echo "error: $$archive is missing scripts/uninstall.sh" >&2; exit 1; }; \
		$(TAR) -tzf "$$archive" | grep -Fx "$$pkg_name/scripts/installer-common.sh" >/dev/null || { echo "error: $$archive is missing scripts/installer-common.sh" >&2; exit 1; }; \
		( cd "$(DIST_DIR)" && $(SHA256SUM) -c "$$(basename "$$checksum")" ); \
	done

clean:
	rm -rf $(BIN_DIR) $(DIST_DIR) coverage.out
