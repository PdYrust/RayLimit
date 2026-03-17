#!/bin/sh

# shellcheck disable=SC2034

set -eu
umask 022

show_help() {
    cat <<'EOF'
Usage: scripts/uninstall.sh [options]

Remove a RayLimit installation that was created by install.sh or update.sh.

Options:
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
  This script removes only installer-managed files. The configuration directory is
  removed only when it is empty.
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
else
    MANIFEST_PATH=$(raylimit_manifest_default_path)
fi

[ -f "$MANIFEST_PATH" ] || raylimit_die "no RayLimit installation manifest found at $MANIFEST_PATH; refusing to remove an unknown installation"

raylimit_finalize_layout_defaults
MANIFEST_PATH=$(raylimit_manifest_default_path)
raylimit_load_manifest "$MANIFEST_PATH"
raylimit_warn_if_manifest_platform_differs

BINARY_DEST=$(raylimit_stage_path "$BINDIR/$RAYLIMIT_APP_NAME")
SHARE_DEST=$(raylimit_stage_path "$RAYLIMIT_SHARE_DIR")
SCRIPTS_DEST=$(raylimit_stage_path "$RAYLIMIT_SHARE_DIR/scripts")
ETC_DEST=$(raylimit_stage_path "$RAYLIMIT_ETC_DIR")

raylimit_maybe_reexec_with_sudo \
    "$BINARY_DEST" \
    "$SHARE_DEST" \
    "$SCRIPTS_DEST" \
    "$ETC_DEST"

raylimit_log "Removing RayLimit ${RAYLIMIT_MANIFEST_VERSION:-unknown}"
raylimit_log "  binary:     $BINDIR/$RAYLIMIT_APP_NAME"
raylimit_log "  share dir:  $RAYLIMIT_SHARE_DIR"
raylimit_log "  config dir: $RAYLIMIT_ETC_DIR"

raylimit_remove_file_if_present "$BINARY_DEST"
raylimit_remove_file_if_present "$SHARE_DEST/README.md"
raylimit_remove_file_if_present "$SHARE_DEST/LICENSE"
raylimit_remove_file_if_present "$SHARE_DEST/VERSION"
raylimit_remove_file_if_present "$SCRIPTS_DEST/update.sh"
raylimit_remove_file_if_present "$SCRIPTS_DEST/uninstall.sh"
raylimit_remove_file_if_present "$SCRIPTS_DEST/installer-common.sh"
raylimit_remove_file_if_present "$MANIFEST_PATH"
raylimit_remove_dir_if_empty "$SCRIPTS_DEST"
raylimit_remove_dir_if_empty "$SHARE_DEST"
raylimit_remove_dir_if_empty "$(dirname "$SHARE_DEST")"
raylimit_remove_dir_if_empty "$ETC_DEST"

raylimit_log "Uninstall complete."
