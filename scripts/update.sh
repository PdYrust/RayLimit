#!/bin/sh

# shellcheck disable=SC2034

set -eu
umask 022

show_help() {
    cat <<'EOF'
Usage: scripts/update.sh [options]

Update an existing RayLimit installation from a local Linux release directory.

Options:
  --package-dir PATH   Release directory to update from (default: parent of this scripts directory)
  --binary PATH        Explicit binary path inside the release directory
  --prefix PATH        Installation prefix (default: /usr/local)
  --bindir PATH        Binary directory (default: PREFIX/bin)
  --datadir PATH       Shared data directory (default: PREFIX/share)
  --sysconfdir PATH    Configuration root (default: /etc)
  --etc-dir PATH       RayLimit configuration directory (default: SYSCONFDIR/raylimit)
  --share-dir PATH     RayLimit shared metadata directory (default: DATADIR/raylimit)
  --destdir PATH       Staging root for packaging or local validation
  --no-sudo            Do not auto-reexec through sudo
  --help               Show this help

Notes:
  Run this script from a new release directory, or pass --package-dir when using
  the installed copy from share/raylimit/scripts.
EOF
}

RAYLIMIT_SELF_DIR=$(
    unset CDPATH
    cd -- "$(dirname -- "$0")" && pwd -P
)
RAYLIMIT_SELF_PATH=$RAYLIMIT_SELF_DIR/$(basename -- "$0")
RAYLIMIT_SCRIPT_DIR=$RAYLIMIT_SELF_DIR
RAYLIMIT_SCRIPT_ROOT=$(dirname "$RAYLIMIT_SCRIPT_DIR")
# shellcheck source=scripts/installer-common.sh
. "$RAYLIMIT_SCRIPT_DIR/installer-common.sh"

while [ "$#" -gt 0 ]; do
    case "$1" in
        --package-dir)
            [ "$#" -ge 2 ] || raylimit_die "--package-dir requires a value"
            RAYLIMIT_PACKAGE_DIR=$2
            shift 2
            ;;
        --binary)
            [ "$#" -ge 2 ] || raylimit_die "--binary requires a value"
            RAYLIMIT_BINARY_PATH=$2
            shift 2
            ;;
        --prefix)
            [ "$#" -ge 2 ] || raylimit_die "--prefix requires a value"
            PREFIX=$2
            shift 2
            ;;
        --bindir)
            [ "$#" -ge 2 ] || raylimit_die "--bindir requires a value"
            BINDIR=$2
            shift 2
            ;;
        --datadir)
            [ "$#" -ge 2 ] || raylimit_die "--datadir requires a value"
            DATADIR=$2
            shift 2
            ;;
        --sysconfdir)
            [ "$#" -ge 2 ] || raylimit_die "--sysconfdir requires a value"
            SYSCONFDIR=$2
            shift 2
            ;;
        --etc-dir)
            [ "$#" -ge 2 ] || raylimit_die "--etc-dir requires a value"
            RAYLIMIT_ETC_DIR=$2
            shift 2
            ;;
        --share-dir)
            [ "$#" -ge 2 ] || raylimit_die "--share-dir requires a value"
            RAYLIMIT_SHARE_DIR=$2
            shift 2
            ;;
        --destdir)
            [ "$#" -ge 2 ] || raylimit_die "--destdir requires a value"
            DESTDIR=$2
            shift 2
            ;;
        --no-sudo)
            RAYLIMIT_NO_SUDO=1
            shift
            ;;
        --help)
            show_help
            exit 0
            ;;
        *)
            raylimit_die "unknown option: $1"
            ;;
    esac
done

raylimit_finalize_layout_defaults
raylimit_detect_platform

MANIFEST_PATH=
if MANIFEST_PATH=$(raylimit_find_manifest_for_current_script 2>/dev/null); then
    raylimit_load_manifest "$MANIFEST_PATH"
    raylimit_apply_manifest_layout
fi

raylimit_finalize_layout_defaults
MANIFEST_PATH=$(raylimit_manifest_default_path)
[ -f "$MANIFEST_PATH" ] || raylimit_die "no existing RayLimit installation manifest found at $MANIFEST_PATH; use install.sh first"
raylimit_load_manifest "$MANIFEST_PATH"
raylimit_warn_if_manifest_platform_differs

raylimit_validate_release_package
PACKAGE_VERSION=$(raylimit_read_package_version)
PACKAGE_BINARY=$(raylimit_find_package_binary)
BINARY_DEST=$(raylimit_stage_path "$BINDIR/$RAYLIMIT_APP_NAME")
SHARE_DEST=$(raylimit_stage_path "$RAYLIMIT_SHARE_DIR")
SCRIPTS_DEST=$(raylimit_stage_path "$RAYLIMIT_SHARE_DIR/scripts")
ETC_DEST=$(raylimit_stage_path "$RAYLIMIT_ETC_DIR")

raylimit_maybe_reexec_with_sudo \
    "$BINARY_DEST" \
    "$SHARE_DEST" \
    "$SCRIPTS_DEST" \
    "$ETC_DEST"

OLD_VERSION=${RAYLIMIT_MANIFEST_VERSION:-unknown}
raylimit_log "Updating RayLimit from $OLD_VERSION to $PACKAGE_VERSION"
raylimit_log "  package:    $RAYLIMIT_PACKAGE_DIR"
raylimit_log "  binary:     $BINDIR/$RAYLIMIT_APP_NAME"
raylimit_log "  share dir:  $RAYLIMIT_SHARE_DIR"
raylimit_log "  config dir: $RAYLIMIT_ETC_DIR"

raylimit_install_file "$PACKAGE_BINARY" "$BINARY_DEST" 0755
raylimit_ensure_dir "$SHARE_DEST"
raylimit_ensure_dir "$ETC_DEST"
raylimit_install_file "$(raylimit_require_package_file README.md)" "$SHARE_DEST/README.md" 0644
raylimit_install_file "$(raylimit_require_package_file LICENSE)" "$SHARE_DEST/LICENSE" 0644
raylimit_install_file "$(raylimit_require_package_file VERSION)" "$SHARE_DEST/VERSION" 0644
raylimit_ensure_dir "$SCRIPTS_DEST"
raylimit_install_file "$(raylimit_require_package_file scripts/update.sh)" "$SCRIPTS_DEST/update.sh" 0755
raylimit_install_file "$(raylimit_require_package_file scripts/uninstall.sh)" "$SCRIPTS_DEST/uninstall.sh" 0755
raylimit_install_file "$(raylimit_require_package_file scripts/installer-common.sh)" "$SCRIPTS_DEST/installer-common.sh" 0755
raylimit_write_manifest "$MANIFEST_PATH" "$PACKAGE_VERSION"

raylimit_log "Update complete."
