#!/usr/bin/env bash
# Launcher for the Nix-packaged ChatGPT Desktop.
#
# Responsibilities, in order:
#   1. verify the kernel gives us unprivileged user namespaces, because that is
#      what Chromium's sandbox relies on here;
#   2. publish a writable copy of the bundled-plugin resources, since Electron
#      rewrites metadata under a path that is read-only in the Nix store;
#   3. put the package's own tools on PATH without displacing the user's;
#   4. hand every user-supplied argument through to Electron unchanged.
#
# Deliberate non-goals: this never sets a global library-path variable (each
# ELF carries its own RUNPATH, and leaking a library path into spawned
# git/node/python children breaks them), and it never disables Chromium's own
# sandbox.

set -uo pipefail

# @preamble@

self_name="$(basename "$0")"

die() {
    printf '%s: %s\n' "$self_name" "$1" >&2
    exit 1
}

warn() {
    printf '%s: %s\n' "$self_name" "$1" >&2
}

# ---------------------------------------------------------------------------
# 1. User namespaces
# ---------------------------------------------------------------------------
# The upstream package ships an AppArmor profile whose only rule is `userns,`.
# That is the whole sandbox story on Linux: there is no setuid chrome-sandbox
# helper in the payload, so if unprivileged user namespaces are unavailable,
# Chromium's zygote cannot start. We diagnose that precisely rather than
# papering over it by turning the sandbox off.

check_user_namespaces() {
    local knob
    for knob in /proc/sys/kernel/unprivileged_userns_clone \
                /proc/sys/user/max_user_namespaces; do
        [[ -r "$knob" ]] || continue
        local value
        value="$(cat "$knob" 2>/dev/null || echo)"
        case "$knob" in
            */unprivileged_userns_clone)
                if [[ "$value" == "0" ]]; then
                    die "unprivileged user namespaces are disabled ($knob = 0).

ChatGPT Desktop relies on them for Chromium's sandbox, and this package
deliberately offers no escape hatch that disables that sandbox.

On NixOS, enable them with:

    boot.kernel.sysctl.\"kernel.unprivileged_userns_clone\" = true;

then rebuild and log in again."
                fi
                ;;
            */max_user_namespaces)
                if [[ "$value" == "0" ]]; then
                    die "user namespaces are disabled ($knob = 0).

ChatGPT Desktop relies on them for Chromium's sandbox, and this package
deliberately offers no escape hatch that disables that sandbox.

On NixOS, raise the limit with:

    boot.kernel.sysctl.\"user.max_user_namespaces\" = 28633;

then rebuild and log in again."
                fi
                ;;
        esac
    done
}

# ---------------------------------------------------------------------------
# 2. Writable bundled-plugin resources
# ---------------------------------------------------------------------------
# The app resolves bundled plugins under
#   <resourcesPath>/plugins/openai-bundled/plugins/<name>/...
# and reconciles them on startup, which involves writing into that tree. In the
# Nix store that tree is read-only, so we publish a writable mirror and point
# the app at it with CODEX_ELECTRON_BUNDLED_PLUGINS_RESOURCES_PATH — the exact
# variable the shipped app.asar reads for this purpose.
#
# The mirror symlinks everything that stays immutable and copies only the
# plugins subtree. It is keyed by package version plus a hash of the upstream
# resources, so a new build gets a new cache and an unchanged build reuses one.

publish_plugin_cache() {
    local resources="$1" cache_root="$2" key="$3"
    local final="$cache_root/$key"
    local stamp="$final/.complete"

    if [[ -e "$stamp" ]]; then
        printf '%s' "$final"
        return 0
    fi

    mkdir -p "$cache_root" || {
        warn "cannot create $cache_root; falling back to the read-only store copy"
        printf '%s' "$resources"
        return 0
    }

    # Serialise concurrent launches. Without this, two instances starting
    # together would each stage a full copy and race on the final rename.
    local lock="$cache_root/.$key.lock"
    exec {lock_fd}>"$lock" || {
        warn "cannot open $lock; falling back to the read-only store copy"
        printf '%s' "$resources"
        return 0
    }

    if ! flock --exclusive --timeout 120 "$lock_fd"; then
        warn "timed out waiting for another instance to build the plugin cache"
        printf '%s' "$resources"
        return 0
    fi

    # Re-check: another launch may have finished while we waited.
    if [[ -e "$stamp" ]]; then
        exec {lock_fd}>&-
        printf '%s' "$final"
        return 0
    fi

    # A directory without the stamp is a partial or interrupted build. Discard
    # it; the stamp is only ever written after a successful, flushed publish.
    if [[ -e "$final" ]]; then
        chmod -R u+w "$final" 2>/dev/null || true
        rm -rf "$final"
    fi

    local staging
    staging="$(mktemp -d "$cache_root/.staging-$key.XXXXXX")" || {
        exec {lock_fd}>&-
        warn "cannot create a staging directory; using the read-only store copy"
        printf '%s' "$resources"
        return 0
    }

    local ok=1
    {
        # Symlink every immutable resource. app.asar alone is ~270 MB and codex
        # ~265 MB; copying them would cost a gigabyte per version for no reason.
        local entry base
        for entry in "$resources"/*; do
            base="$(basename "$entry")"
            [[ "$base" == "plugins" ]] && continue
            ln -s "$entry" "$staging/$base" || { ok=0; break; }
        done

        # Copy only the subtree the app actually rewrites.
        if (( ok )) && [[ -d "$resources/plugins" ]]; then
            cp -a --no-preserve=ownership "$resources/plugins" "$staging/plugins" \
                && chmod -R u+w "$staging/plugins" || ok=0
        fi
    } || ok=0

    if (( ! ok )); then
        rm -rf "$staging"
        exec {lock_fd}>&-
        warn "could not stage the plugin cache; using the read-only store copy"
        printf '%s' "$resources"
        return 0
    fi

    # Flush before publishing, so a crash or power loss cannot leave a
    # directory that is marked complete but contains truncated files.
    sync "$staging" 2>/dev/null || true
    : > "$staging/.complete"
    sync "$staging/.complete" 2>/dev/null || true

    if ! mv -T "$staging" "$final" 2>/dev/null; then
        # Lost a race against another publisher, or the rename failed. If a
        # complete cache is now there, use it; otherwise fall back.
        rm -rf "$staging"
        if [[ ! -e "$stamp" ]]; then
            exec {lock_fd}>&-
            warn "could not publish the plugin cache; using the read-only store copy"
            printf '%s' "$resources"
            return 0
        fi
    fi

    # Drop caches for versions we no longer run. Only entries that are complete
    # and not the current key are removed, and only under our own lock.
    local old
    for old in "$cache_root"/*; do
        [[ -d "$old" ]] || continue
        [[ "$(basename "$old")" == "$key" ]] && continue
        chmod -R u+w "$old" 2>/dev/null || true
        rm -rf "$old" 2>/dev/null || true
    done
    # Abandoned staging directories from a SIGKILLed launch: an EXIT trap never
    # runs for those, so sweep them here instead.
    for old in "$cache_root"/.staging-*; do
        [[ -d "$old" ]] || continue
        rm -rf "$old" 2>/dev/null || true
    done

    exec {lock_fd}>&-
    printf '%s' "$final"
}

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

check_user_namespaces

cache_home="${XDG_CACHE_HOME:-$HOME/.cache}"
resources_path="$(publish_plugin_cache \
    "@out@/lib/chatgpt/resources" \
    "$cache_home/chatgpt-desktop-nix/resources" \
    "@resourceKey@")"

export CODEX_ELECTRON_BUNDLED_PLUGINS_RESOURCES_PATH="$resources_path"

# Keep the user's PATH; only append what the app needs and might not find.
export PATH="${PATH:+$PATH:}@packageBins@"

# On NixOS, put our bwrap shim ahead of everything so Codex's command sandbox
# can run generic downloaded binaries. See nix/bwrap-shim.c for what it does.
if [[ -e /etc/NIXOS && -d "@bwrapShim@" ]]; then
    export PATH="@bwrapShim@:$PATH"
fi

# Graphics drivers live outside the package and are host-specific.
if [[ -d /run/opengl-driver ]]; then
    export LIBGL_DRIVERS_PATH="${LIBGL_DRIVERS_PATH:-/run/opengl-driver/lib/dri}"
    export LIBVA_DRIVERS_PATH="${LIBVA_DRIVERS_PATH:-/run/opengl-driver/lib/dri}"
    export __EGL_VENDOR_LIBRARY_DIRS="${__EGL_VENDOR_LIBRARY_DIRS:-/run/opengl-driver/share/glvnd/egl_vendor.d}"
    export VK_ICD_FILENAMES="${VK_ICD_FILENAMES:-/run/opengl-driver/share/vulkan/icd.d}"
fi

electron_args=()

# Native Wayland is experimental upstream and is opt-in only. We enable it when
# the user asks for it via NIXOS_OZONE_WL, and otherwise leave Electron on its
# default XWayland path.
#
# Note the explicit value test: NIXOS_OZONE_WL=0 means "no". Treating any
# non-empty value as true would turn an attempt to disable this into an
# instruction to enable it.
case "${NIXOS_OZONE_WL:-}" in
    1|true|yes|on)
        if [[ -n "${WAYLAND_DISPLAY:-}" ]]; then
            electron_args+=(
                --ozone-platform-hint=auto
                --enable-features=WaylandWindowDecorations
            )
        else
            warn "NIXOS_OZONE_WL is set but WAYLAND_DISPLAY is not; using XWayland"
        fi
        ;;
esac

# Optional user-controlled flags, one per line, '#' for comments.
flags_file="${XDG_CONFIG_HOME:-$HOME/.config}/chatgpt-flags.conf"
if [[ -r "$flags_file" ]]; then
    while IFS= read -r line; do
        line="${line%%#*}"
        line="${line#"${line%%[![:space:]]*}"}"
        line="${line%"${line##*[![:space:]]}"}"
        [[ -n "$line" ]] && electron_args+=("$line")
    done < "$flags_file"
fi

# The user's own arguments come last so they win over anything above, and are
# passed through verbatim, including an explicit ozone platform override for a
# native-Wayland session.
exec "@out@/lib/chatgpt/ChatGPT" "${electron_args[@]}" "$@"
