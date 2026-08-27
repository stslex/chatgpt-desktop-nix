#!/usr/bin/env bash
# Launcher for the Nix-packaged ChatGPT Desktop.
#
# Responsibilities, in order:
#   1. verify the kernel gives us unprivileged user namespaces, because that is
#      what Chromium's sandbox relies on here (skipped for `--version` and
#      `--help`, which never start a renderer);
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

# The package's own tools, ahead of whatever the caller had. This must be a
# real statement rather than a comment: everything below depends on it, and
# with it commented out the script relied entirely on the caller's PATH -- so
# under a stripped environment `basename` and `unshare` were both missing, and
# the namespace probe failed, making the launcher report that namespaces were
# unavailable on a host where they were fine.
#
# This prepends; the user's own PATH is appended to further down and is never
# replaced.
@preamble@

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
    # Actually try to create one.
    #
    # Reading sysctls tells you about two of the ways namespaces can be denied
    # and nothing about the rest. Ubuntu restricts them through AppArmor, a
    # container may drop the capability, seccomp may block the syscall, and a
    # hardened kernel may refuse for its own reasons -- in every one of those
    # cases the sysctls look fine and Chromium's zygote still dies with SIGTRAP
    # and no output at all. Only the attempt is conclusive.
    if unshare --user --map-root-user true 2>/dev/null; then
        return 0
    fi

    # It failed. Now read the sysctls, purely so the message can say something
    # actionable rather than "it did not work".
    local detail=""
    local knob value
    for knob in /proc/sys/kernel/unprivileged_userns_clone \
                /proc/sys/user/max_user_namespaces \
                /proc/sys/kernel/apparmor_restrict_unprivileged_userns; do
        [[ -r "$knob" ]] || continue
        value="$(cat "$knob" 2>/dev/null || echo)"
        detail+="
    $knob = $value"
    done

    die "unprivileged user namespaces are not available.

Chromium's sandbox needs them, the upstream package ships no setuid helper, and
this package deliberately offers no escape hatch that disables that sandbox.
Relevant kernel settings on this host:$detail

On NixOS, if you have turned them off:

    boot.kernel.sysctl.\"user.max_user_namespaces\" = 28633;

On a Debian or Ubuntu host, AppArmor may be the cause:

    sudo sysctl -w kernel.apparmor_restrict_unprivileged_userns=0

then log in again."
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

degrade() {
    # Falling back to the read-only store copy is a degradation, not a repair:
    # the app gets exactly what it would have had without this cache, so any
    # bundled-plugin feature that needs to write will still misbehave. Say so
    # rather than failing silently, and keep starting — a working chat window
    # is better than no application at all.
    warn "$1"
    warn "using the read-only store resources; bundled-plugin features that need to write may not work"
    printf '%s' "$2"
}

# Is a published cache actually usable?
#
# The completion marker says a publish finished, not that what it published is
# still intact. A cache can be damaged afterwards -- a partial disk, a stray
# rm, an interrupted copy by something else -- and the marker would still be
# there. Check the structure the app depends on before handing the path over.
cache_is_valid() {
    local dir="$1" resources="$2"
    [[ -e "$dir/.complete" ]] || return 1
    [[ -d "$dir/plugins" ]] || return 1
    # The bundled-plugin tree the app resolves against.
    [[ -d "$dir/plugins/openai-bundled/plugins" ]] || return 1
    # Every immutable resource must still be present as a symlink that
    # resolves; a dangling one means the store path it pointed at is gone.
    local entry base
    for entry in "$resources"/*; do
        base="$(basename "$entry")"
        [[ "$base" == "plugins" ]] && continue
        [[ -e "$dir/$base" ]] || return 1
    done
    # And the plugins that were copied must still be there.
    #
    # Checking only that the two directories above exist says nothing about
    # what is inside them: an emptied or half-deleted bundled-plugin tree
    # satisfied every test here while being exactly the damage this function is
    # supposed to catch. Compare against the source, which is the definition of
    # what a complete copy contains.
    local src="$resources/plugins/openai-bundled/plugins"
    if [[ -d "$src" ]]; then
        for entry in "$src"/*; do
            [[ -e "$entry" ]] || continue          # nothing matched the glob
            base="$(basename "$entry")"
            [[ -e "$dir/plugins/openai-bundled/plugins/$base" ]] || return 1
        done
    fi
    return 0
}

# Close whichever of the two locks publish_plugin_cache is holding.
#
# Bash scoping is dynamic, so this sees that function's locals. Having one
# place to do it matters because there are now two descriptors and eight exits,
# and leaking the exclusive in-use lock would make every later launch think the
# cache is busy forever.
release_cache_locks() {
    # Each `exec` is wrapped in a group so its redirection applies to the
    # group and not to this shell. `exec ... 2>/dev/null` on its own would
    # redirect the shell's stderr permanently -- silencing every later warning
    # and, past the final exec, the application's own diagnostics.
    if [[ -n "${destroy_fd:-}" ]]; then
        { exec {destroy_fd}>&-; } 2>/dev/null || true
        destroy_fd=""
    fi
    if [[ -n "${lock_fd:-}" ]]; then
        { exec {lock_fd}>&-; } 2>/dev/null || true
        lock_fd=""
    fi
    return 0
}

publish_plugin_cache() {
    local resources="$1" cache_root="$2" key="$3"
    local final="$cache_root/$key"
    local stamp="$final/.complete"
    local destroy_fd=""

    if cache_is_valid "$final" "$resources"; then
        printf '%s' "$final"
        return 0
    fi

    mkdir -p "$cache_root" || {
        degrade "cannot create $cache_root" "$resources"
        return 0
    }

    # Serialise concurrent launches. Without this, two instances starting
    # together would each stage a full copy and race on the final rename.
    local lock="$cache_root/.$key.build.lock"
    exec {lock_fd}>"$lock" || {
        degrade "cannot open $lock" "$resources"
        return 0
    }

    if ! flock --exclusive --timeout 120 "$lock_fd"; then
        release_cache_locks
        degrade "timed out waiting for another instance to build the plugin cache" "$resources"
        return 0
    fi

    # Re-check under the lock: another launch may have finished while we
    # waited, and it may equally have published something damaged.
    if cache_is_valid "$final" "$resources"; then
        release_cache_locks
        printf '%s' "$final"
        return 0
    fi

    # Anything else -- no marker, or a marker over a tree that no longer holds
    # what it should -- is rebuilt from scratch under this lock rather than
    # trusted.
    #
    # But rebuilding means deleting, and this entry may be the resources of an
    # application that is running right now. The build lock does not say
    # otherwise: it serialises builders, and a running instance is not a
    # builder -- it holds the *in-use* lock, shared, for its whole lifetime.
    # So ask that lock before destroying anything. An exclusive non-blocking
    # acquisition succeeds only if nobody holds it.
    if [[ -e "$final" ]]; then
        local inuse; inuse="$(inuse_lock "$cache_root" "$key")"
        local destroy_fd=""
        if : >> "$inuse" 2>/dev/null \
                && { exec {destroy_fd}>>"$inuse"; } 2>/dev/null \
                && flock --exclusive --nonblock "$destroy_fd" 2>/dev/null; then
            warn "discarding an incomplete or damaged plugin cache at $final"
            chmod -R u+w "$final" 2>/dev/null || true
            rm -rf "$final"
            # Kept for the rebuild below, so a launch starting now cannot claim
            # the entry while it is being replaced.
        else
            release_cache_locks
            degrade \
                "the plugin cache at $final is damaged, but another instance is using it" \
                "$resources"
            return 0
        fi
    fi

    local staging
    staging="$(mktemp -d "$cache_root/.staging-$key.XXXXXX")" || {
        release_cache_locks
        degrade "cannot create a staging directory" "$resources"
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
        release_cache_locks
        degrade "could not stage the plugin cache" "$resources"
        return 0
    fi

    # Flush before publishing, so a crash or power loss cannot leave a
    # directory that is marked complete but contains truncated files. If the
    # flush or the marker cannot be written we must NOT publish: an entry
    # carrying .complete is treated as trustworthy forever after.
    if ! sync "$staging" || ! : > "$staging/.complete" \
            || ! sync "$staging/.complete"; then
        rm -rf "$staging"
        release_cache_locks
        degrade "could not flush the staged plugin cache to disk" "$resources"
        return 0
    fi

    if ! mv -T "$staging" "$final" 2>/dev/null; then
        # Lost a race against another publisher, or the rename failed. If a
        # valid cache is now there, use it; otherwise fall back.
        rm -rf "$staging"
        if ! cache_is_valid "$final" "$resources"; then
            release_cache_locks
            degrade "could not publish the plugin cache" "$resources"
            return 0
        fi
    fi

    collect_unused_caches "$cache_root" "$key"

    release_cache_locks
    printf '%s' "$final"
}

# Remove caches for versions nothing is running any more.
#
# The build lock is per-key, so it says nothing about entries under a different
# key — and a different key is exactly what an older instance is using. Deleting
# by "not the current key" would pull the resources out from under a running
# application. Instead every launch holds a *shared* lock on its own entry for
# its whole lifetime, so an entry is provably unused only when an *exclusive*
# non-blocking lock on it succeeds.
collect_unused_caches() {
    local cache_root="$1" key="$2" old

    # Only this key's own abandoned staging directories are swept, and only
    # while this key's build lock is held — which the sole caller does hold.
    # A `.staging-<otherkey>.*` directory belongs to a different key's build
    # lock and may be actively being written right now, so it is not ours to
    # remove.
    for old in "$cache_root/.staging-$key."*; do
        [[ -d "$old" ]] || continue
        rm -rf "$old" 2>/dev/null || true
    done

    # Caches for other versions are deliberately NOT collected.
    #
    # Doing it safely requires proving no other process is using one, and the
    # obvious test does not prove that: `flock --nonblock <lock> --command
    # true` releases the lock the moment `true` exits, so between that check
    # and the `rm -rf` another launch can legitimately acquire it and start
    # using the cache we are about to delete. Holding the lock across the
    # deletion from a shell, for every candidate, while not deadlocking against
    # our own in-use lock, is more machinery than the problem justifies for a
    # first release.
    #
    # The cost of not collecting is bounded and visible: roughly 50 MB of
    # copied plugin files per upstream version under
    # $XDG_CACHE_HOME/chatgpt-desktop-nix/resources. Deleting that directory is
    # always safe when the app is not running. The cost of collecting wrongly
    # is pulling resources out from under a running application, which is not a
    # trade worth making to save disk.
    :
}

inuse_lock() {
    printf '%s/.%s.inuse.lock' "$1" "$2"
}

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

# `--version` alone is answered by Electron in the browser process, before any
# renderer or zygote exists, so it does not depend on the sandbox the check
# below is about. Refusing it on a host without user namespaces protects
# nothing and makes the package unusable for the things that legitimately ask a
# binary what it is: a packaging check, `nix run . -- --version`, a container
# build, a CI job on a runner where AppArmor restricts unprivileged namespaces.
#
# Exactly one flag is exempt, and that is not tidiness -- it is what the
# behaviour supports. Measured against this build:
#
#   --version   prints the version, exits 0, touches no display
#   -v          initialises Ozone/X11 and starts the app (exit 1 with no
#               display). It is NOT an abbreviation of --version.
#   --help, -h  exec `man ChatGPT`, which has no manual entry (exit 16)
#
# So `-v` must go through the check like any other argument: exempting it would
# skip the sandbox precheck for a genuine application start, which is the one
# thing this must never do. --help is harmless but pointless to exempt.
#
# The whole argument list has to be exactly `--version`; any other argument,
# and any combination with other arguments, goes through the check.
needs_sandbox=1
if (( $# == 1 )) && [[ "$1" == "--version" ]]; then
    needs_sandbox=0
fi

if (( needs_sandbox )); then
    check_user_namespaces
fi

# Under `set -u` a bare $HOME would abort the launcher outright when HOME is
# unset — which happens in systemd units, some containers and `env -i`. Fall
# back rather than refusing to start.
if [[ -n "${XDG_CACHE_HOME:-}" ]]; then
    cache_home="$XDG_CACHE_HOME"
elif [[ -n "${HOME:-}" ]]; then
    cache_home="$HOME/.cache"
else
    # A fixed path under a world-writable directory is a name another user can
    # create first. Use a private directory we make ourselves, and refuse to
    # reuse one we do not own.
    cache_home="$(mktemp -d "${TMPDIR:-/tmp}/chatgpt-desktop-nix.XXXXXXXX")" || {
        die "neither XDG_CACHE_HOME nor HOME is set, and no temporary
directory could be created. Set HOME or XDG_CACHE_HOME and try again."
    }
    chmod 700 "$cache_home"
    warn "neither XDG_CACHE_HOME nor HOME is set; caching under $cache_home"
    warn "this cache is per-launch and will not be reused"
fi

cache_root="$cache_home/chatgpt-desktop-nix/resources"
resources_path="$(publish_plugin_cache \
    "@out@/lib/chatgpt/resources" \
    "$cache_root" \
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
    # VK_ICD_FILENAMES is a colon-separated list of manifest FILES; pointing it
    # at a directory makes the loader find nothing, which is worse than leaving
    # it unset since the loader scans the standard directories on its own.
    # Only set it if we can build a real list.
    if [[ -z "${VK_ICD_FILENAMES:-}" ]]; then
        _icds=""
        for _icd in /run/opengl-driver/share/vulkan/icd.d/*.json; do
            [[ -f "$_icd" ]] || continue
            _icds="${_icds:+$_icds:}$_icd"
        done
        [[ -n "$_icds" ]] && export VK_ICD_FILENAMES="$_icds"
        unset _icd _icds
    fi
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
#
# A line is split on whitespace, so both `--flag=value` and `--flag value`
# behave the way someone writing a command line would expect. Quoting is not
# interpreted: a value containing spaces must use the `--flag=value` form.
if [[ -n "${XDG_CONFIG_HOME:-}" ]]; then
    flags_file="$XDG_CONFIG_HOME/chatgpt-flags.conf"
elif [[ -n "${HOME:-}" ]]; then
    flags_file="$HOME/.config/chatgpt-flags.conf"
else
    flags_file=""
fi

if [[ -n "$flags_file" && -r "$flags_file" ]]; then
    while IFS= read -r line || [[ -n "$line" ]]; do
        line="${line%%#*}"
        read -ra fields <<< "$line"
        (( ${#fields[@]} )) && electron_args+=("${fields[@]}")
    done < "$flags_file"
fi

# The user's own arguments come last so they win over anything above, and are
# passed through verbatim, including an explicit ozone platform override for a
# native-Wayland session.
#
# When we published a writable cache, hold a shared lock on it for the whole
# life of the application, so another launch's garbage collection can tell the
# entry is still in use.
#
# The descriptor is opened with a fixed number and inherited across the exec
# below, which keeps the lock held for exactly as long as the app runs and adds
# no process to the tree. Note that `flock <lock> <command>` would NOT do this:
# it forks rather than execs, leaving an extra process between the desktop
# entry and Electron.
if [[ "$resources_path" != "@out@/lib/chatgpt/resources" ]]; then
    lock_path="$(inuse_lock "$cache_root" "@resourceKey@")"
    held=0
    # The braces matter. `exec 9>>"$lock_path" 2>/dev/null` attaches BOTH
    # redirections to this shell permanently, so the 2>/dev/null would follow
    # the process through the final exec below and discard every diagnostic the
    # application ever writes -- every Chromium warning, every crash message.
    if : >> "$lock_path" 2>/dev/null && { exec 9>>"$lock_path"; } 2>/dev/null; then
        if flock --shared --nonblock 9 2>/dev/null; then
            held=1
        fi
    fi
    if (( ! held )); then
        # We could not mark this cache as in use. Nothing collects other
        # versions' caches today, so this is not currently dangerous — but
        # continuing to use a cache we cannot claim is exactly the shape of
        # bug that would bite the moment collection is added. Fall back to the
        # read-only store copy, which is always safe.
        warn "could not take the in-use lock on $resources_path"
        resources_path="@out@/lib/chatgpt/resources"
        export CODEX_ELECTRON_BUNDLED_PLUGINS_RESOURCES_PATH="$resources_path"
        warn "using the read-only store resources instead"
    fi
fi

exec "@out@/lib/chatgpt/ChatGPT" "${electron_args[@]}" "$@"
