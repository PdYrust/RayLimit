#!/bin/sh

# Shared release installer helpers for RayLimit.
# The top-level release archive is expected to contain:
#   raylimit
#   README.md
#   LICENSE
#   VERSION
#   scripts/install.sh
#   scripts/update.sh
#   scripts/uninstall.sh
#   scripts/installer-common.sh

# shellcheck disable=SC2034

RAYLIMIT_APP_NAME=${RAYLIMIT_APP_NAME:-raylimit}
RAYLIMIT_MANIFEST_NAME=${RAYLIMIT_MANIFEST_NAME:-install.env}

raylimit_log() {
    printf '%s\n' "$*"
}

raylimit_warn() {
    printf 'warning: %s\n' "$*" >&2
}

raylimit_die() {
    printf 'error: %s\n' "$*" >&2
    exit 1
}

raylimit_resolve_self_path() {
    self_path=$1
    case "$self_path" in
        */*)
            candidate=$self_path
            ;;
        *)
            candidate=$(command -v "$self_path" 2>/dev/null || true)
            [ -n "$candidate" ] || candidate=$self_path
            ;;
    esac

    case "$candidate" in
        /*)
            printf '%s\n' "$candidate"
            ;;
        *)
            printf '%s/%s\n' "$(pwd -P)" "$candidate"
            ;;
    esac
}

raylimit_self_dir() {
    self_path=$1
    self_dir=$(dirname "$self_path")
    (
        cd "$self_dir" >/dev/null 2>&1 && pwd -P
    ) || raylimit_die "failed to resolve script directory for $self_path"
}

raylimit_finalize_layout_defaults() {
    : "${DESTDIR:=}"
    : "${PREFIX:=/usr/local}"
    : "${SYSCONFDIR:=/etc}"
    : "${DATADIR:=$PREFIX/share}"
    : "${BINDIR:=$PREFIX/bin}"
    : "${RAYLIMIT_ETC_DIR:=$SYSCONFDIR/raylimit}"
    : "${RAYLIMIT_SHARE_DIR:=$DATADIR/raylimit}"
    : "${RAYLIMIT_PACKAGE_DIR:=$RAYLIMIT_SCRIPT_ROOT}"
    : "${RAYLIMIT_BINARY_PATH:=}"
    : "${RAYLIMIT_NO_SUDO:=0}"
}

raylimit_stage_path() {
    logical_path=$1
    case "$logical_path" in
        /*)
            printf '%s%s\n' "$DESTDIR" "$logical_path"
            ;;
        *)
            if [ -n "$DESTDIR" ]; then
                printf '%s/%s\n' "$DESTDIR" "$logical_path"
            else
                printf '%s\n' "$logical_path"
            fi
            ;;
    esac
}

raylimit_detect_platform() {
    RAYLIMIT_PLATFORM=$(uname -s 2>/dev/null || printf 'unknown')
    RAYLIMIT_ARCH=$(uname -m 2>/dev/null || printf 'unknown')
    if [ "$RAYLIMIT_PLATFORM" != "Linux" ]; then
        raylimit_die "RayLimit release scripts currently support Linux only (detected $RAYLIMIT_PLATFORM/$RAYLIMIT_ARCH)"
    fi
}

raylimit_require_file() {
    path=$1
    [ -f "$path" ] || raylimit_die "required file is missing: $path"
}

raylimit_require_dir() {
    path=$1
    [ -d "$path" ] || raylimit_die "required directory is missing: $path"
}

raylimit_require_package_file() {
    name=$1
    path=$RAYLIMIT_PACKAGE_DIR/$name
    raylimit_require_file "$path"
    printf '%s\n' "$path"
}

raylimit_validate_release_package() {
    raylimit_require_dir "$RAYLIMIT_PACKAGE_DIR"
    raylimit_require_package_file README.md >/dev/null
    raylimit_require_package_file LICENSE >/dev/null
    raylimit_require_package_file VERSION >/dev/null
    raylimit_require_package_file scripts/update.sh >/dev/null
    raylimit_require_package_file scripts/uninstall.sh >/dev/null
    raylimit_require_package_file scripts/installer-common.sh >/dev/null
}

raylimit_read_package_version() {
    version_file=$(raylimit_require_package_file VERSION)
    version=$(sed -n '1p' "$version_file" | tr -d '\r')
    [ -n "$version" ] || version=unknown
    printf '%s\n' "$version"
}

raylimit_find_package_binary() {
    if [ -n "$RAYLIMIT_BINARY_PATH" ]; then
        candidate=$RAYLIMIT_BINARY_PATH
    elif [ -f "$RAYLIMIT_PACKAGE_DIR/$RAYLIMIT_APP_NAME" ]; then
        candidate=$RAYLIMIT_PACKAGE_DIR/$RAYLIMIT_APP_NAME
    elif [ -f "$RAYLIMIT_PACKAGE_DIR/bin/$RAYLIMIT_APP_NAME" ]; then
        candidate=$RAYLIMIT_PACKAGE_DIR/bin/$RAYLIMIT_APP_NAME
    else
        raylimit_die "could not find $RAYLIMIT_APP_NAME in $RAYLIMIT_PACKAGE_DIR; expected ./raylimit or ./bin/raylimit, or use --binary or --package-dir"
    fi

    raylimit_require_file "$candidate"
    [ -x "$candidate" ] || raylimit_die "binary is not executable: $candidate"
    printf '%s\n' "$candidate"
}

raylimit_nearest_existing_parent() {
    path=$1
    if [ -d "$path" ]; then
        candidate=$path
    else
        candidate=$(dirname "$path")
    fi

    while [ ! -e "$candidate" ] && [ "$candidate" != "/" ]; do
        candidate=$(dirname "$candidate")
    done

    printf '%s\n' "$candidate"
}

raylimit_target_writable() {
    target=$1
    parent=$(raylimit_nearest_existing_parent "$target")
    [ -w "$parent" ]
}

raylimit_maybe_reexec_with_sudo() {
    if [ "$(id -u)" -eq 0 ] || [ "$RAYLIMIT_NO_SUDO" = "1" ]; then
        return 0
    fi

    need_sudo=0
    while [ "$#" -gt 0 ]; do
        if ! raylimit_target_writable "$1"; then
            need_sudo=1
        fi
        shift
    done

    [ "$need_sudo" -eq 1 ] || return 0

    if command -v sudo >/dev/null 2>&1; then
        raylimit_log "Re-running with sudo for system installation paths."
        exec sudo env \
            DESTDIR="$DESTDIR" \
            PREFIX="$PREFIX" \
            SYSCONFDIR="$SYSCONFDIR" \
            DATADIR="$DATADIR" \
            BINDIR="$BINDIR" \
            RAYLIMIT_ETC_DIR="$RAYLIMIT_ETC_DIR" \
            RAYLIMIT_SHARE_DIR="$RAYLIMIT_SHARE_DIR" \
            RAYLIMIT_PACKAGE_DIR="$RAYLIMIT_PACKAGE_DIR" \
            RAYLIMIT_BINARY_PATH="$RAYLIMIT_BINARY_PATH" \
            RAYLIMIT_NO_SUDO=1 \
            sh "$RAYLIMIT_SELF_PATH"
    fi

    raylimit_die "write access is required for the selected install paths; rerun with sudo or choose writable directories"
}

raylimit_ensure_dir() {
    dir=$1
    mkdir -p "$dir" || raylimit_die "failed to create directory: $dir"
}

raylimit_install_file() {
    src=$1
    dst=$2
    mode=$3
    dst_dir=$(dirname "$dst")
    tmp=

    raylimit_require_file "$src"
    raylimit_ensure_dir "$dst_dir"

    tmp=$(mktemp "$dst_dir/.${RAYLIMIT_APP_NAME}.tmp.XXXXXX") || raylimit_die "failed to create temporary file in $dst_dir"
    if ! cp "$src" "$tmp"; then
        rm -f "$tmp"
        raylimit_die "failed to copy $src into $dst_dir"
    fi
    if ! chmod "$mode" "$tmp"; then
        rm -f "$tmp"
        raylimit_die "failed to set mode $mode on temporary file for $dst"
    fi
    if ! mv "$tmp" "$dst"; then
        rm -f "$tmp"
        raylimit_die "failed to move temporary file into place at $dst"
    fi
}

raylimit_write_manifest() {
    manifest_path=$1
    version=$2
    tmp=
    manifest_dir=$(dirname "$manifest_path")

    raylimit_ensure_dir "$manifest_dir"
    tmp=$(mktemp "$manifest_dir/.${RAYLIMIT_MANIFEST_NAME}.tmp.XXXXXX") || raylimit_die "failed to create temporary manifest"
    cat >"$tmp" <<EOF
RAYLIMIT_VERSION=$version
RAYLIMIT_PLATFORM=$RAYLIMIT_PLATFORM
RAYLIMIT_ARCH=$RAYLIMIT_ARCH
RAYLIMIT_BINARY=$BINDIR/$RAYLIMIT_APP_NAME
RAYLIMIT_SHARE_DIR=$RAYLIMIT_SHARE_DIR
RAYLIMIT_ETC_DIR=$RAYLIMIT_ETC_DIR
EOF
    chmod 0644 "$tmp" || {
        rm -f "$tmp"
        raylimit_die "failed to set manifest permissions"
    }
    mv "$tmp" "$manifest_path" || {
        rm -f "$tmp"
        raylimit_die "failed to install manifest at $manifest_path"
    }
}

raylimit_load_manifest() {
    manifest_path=$1
    RAYLIMIT_MANIFEST_VERSION=
    RAYLIMIT_MANIFEST_PLATFORM=
    RAYLIMIT_MANIFEST_ARCH=
    RAYLIMIT_MANIFEST_BINARY=
    RAYLIMIT_MANIFEST_SHARE_DIR=
    RAYLIMIT_MANIFEST_ETC_DIR=

    raylimit_require_file "$manifest_path"
    while IFS='=' read -r key value; do
        case "$key" in
            ''|\#*)
                continue
                ;;
            RAYLIMIT_VERSION)
                RAYLIMIT_MANIFEST_VERSION=$value
                ;;
            RAYLIMIT_PLATFORM)
                RAYLIMIT_MANIFEST_PLATFORM=$value
                ;;
            RAYLIMIT_ARCH)
                RAYLIMIT_MANIFEST_ARCH=$value
                ;;
            RAYLIMIT_BINARY)
                RAYLIMIT_MANIFEST_BINARY=$value
                ;;
            RAYLIMIT_SHARE_DIR)
                RAYLIMIT_MANIFEST_SHARE_DIR=$value
                ;;
            RAYLIMIT_ETC_DIR)
                RAYLIMIT_MANIFEST_ETC_DIR=$value
                ;;
        esac
    done <"$manifest_path"
}

raylimit_warn_if_manifest_platform_differs() {
    if [ -n "$RAYLIMIT_MANIFEST_PLATFORM" ] && [ "$RAYLIMIT_MANIFEST_PLATFORM" != "$RAYLIMIT_PLATFORM" ]; then
        raylimit_warn "installation manifest records platform $RAYLIMIT_MANIFEST_PLATFORM but current host reports $RAYLIMIT_PLATFORM"
    fi
    if [ -n "$RAYLIMIT_MANIFEST_ARCH" ] && [ "$RAYLIMIT_MANIFEST_ARCH" != "$RAYLIMIT_ARCH" ]; then
        raylimit_warn "installation manifest records architecture $RAYLIMIT_MANIFEST_ARCH but current host reports $RAYLIMIT_ARCH"
    fi
}

raylimit_apply_manifest_layout() {
    [ -n "$RAYLIMIT_MANIFEST_BINARY" ] || raylimit_die "installation manifest is missing RAYLIMIT_BINARY"
    [ -n "$RAYLIMIT_MANIFEST_SHARE_DIR" ] || raylimit_die "installation manifest is missing RAYLIMIT_SHARE_DIR"
    [ -n "$RAYLIMIT_MANIFEST_ETC_DIR" ] || raylimit_die "installation manifest is missing RAYLIMIT_ETC_DIR"

    BINDIR=$(dirname "$RAYLIMIT_MANIFEST_BINARY")
    PREFIX=$(dirname "$BINDIR")
    RAYLIMIT_SHARE_DIR=$RAYLIMIT_MANIFEST_SHARE_DIR
    DATADIR=$(dirname "$RAYLIMIT_SHARE_DIR")
    RAYLIMIT_ETC_DIR=$RAYLIMIT_MANIFEST_ETC_DIR
    SYSCONFDIR=$(dirname "$RAYLIMIT_ETC_DIR")
}

raylimit_remove_file_if_present() {
    path=$1
    if [ -e "$path" ] || [ -L "$path" ]; then
        rm -f "$path" || raylimit_die "failed to remove $path"
    fi
}

raylimit_remove_dir_if_empty() {
    path=$1
    if [ -d "$path" ]; then
        rmdir "$path" 2>/dev/null || true
    fi
}

raylimit_manifest_default_path() {
    printf '%s\n' "$(raylimit_stage_path "$RAYLIMIT_SHARE_DIR/$RAYLIMIT_MANIFEST_NAME")"
}

raylimit_find_manifest_for_current_script() {
    if [ -f "$RAYLIMIT_SCRIPT_DIR/$RAYLIMIT_MANIFEST_NAME" ]; then
        printf '%s\n' "$RAYLIMIT_SCRIPT_DIR/$RAYLIMIT_MANIFEST_NAME"
        return 0
    fi

    script_parent=$(dirname "$RAYLIMIT_SCRIPT_DIR")
    if [ -f "$script_parent/$RAYLIMIT_MANIFEST_NAME" ]; then
        printf '%s\n' "$script_parent/$RAYLIMIT_MANIFEST_NAME"
        return 0
    fi

    staged_manifest=$(raylimit_manifest_default_path)
    if [ -f "$staged_manifest" ]; then
        printf '%s\n' "$staged_manifest"
        return 0
    fi

    return 1
}
