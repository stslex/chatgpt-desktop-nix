#!/usr/bin/env bash
# Bounded graphical start-up check for a built package.
#
# Launches the packaged app against a headless X server, waits for it to map a
# window, and then looks for the failures that matter: a loader error, an
# unusable sandbox, or SIGILL from the glibc-detection path.
#
# This lives in a file rather than inline in the workflow because it needs an
# X server, a background process and a log scan, and expressing that through
# three levels of YAML and shell quoting is how mistakes get in.
#
# Usage: graphical-smoke.sh <package-path> [log-directory]

set -euo pipefail

package="${1:?usage: graphical-smoke.sh <package-path> [log-dir]}"
logdir="${2:-${RUNNER_TEMP:-/tmp}/chatgpt-graphical-smoke}"

launcher="$package/bin/chatgpt"
[[ -x "$launcher" ]] || {
    echo "no launcher at $launcher" >&2
    exit 1
}

mkdir -p "$logdir"
log="$logdir/startup.log"
: > "$log"

echo "launching $launcher under Xvfb, log: $log"

# xvfb-run picks a free display and tears the server down when we return.
xvfb-run --auto-servernum --server-args="-screen 0 1280x1024x24" \
    bash -euo pipefail -c '
        launcher="$1"; log="$2"
        "$launcher" > "$log" 2>&1 &
        app=$!

        mapped=0
        for _ in $(seq 1 90); do
            if ! kill -0 "$app" 2>/dev/null; then
                echo "the application exited before mapping a window" >&2
                break
            fi
            if xdotool search --name ChatGPT >/dev/null 2>&1; then
                mapped=1
                break
            fi
            sleep 1
        done

        # A mapped window is not yet a working application. Chromium maps its
        # window early and can still die seconds later -- a SIGILL from the
        # glibc-detection path is exactly that shape. Killing the moment a
        # window appears would leave no interval in which such a crash could
        # be observed, so dwell first and require it to still be alive.
        survived=0
        if (( mapped )); then
            for _ in $(seq 1 15); do
                sleep 1
                if ! kill -0 "$app" 2>/dev/null; then
                    echo "the application exited $survived s after mapping" >&2
                    break
                fi
                survived=$(( survived + 1 ))
            done
        fi

        # Always stop the app, whether or not it mapped anything.
        kill "$app" 2>/dev/null || true
        wait "$app" 2>/dev/null || true

        if (( mapped && survived >= 15 )); then exit 0; fi
        exit 1
    ' _ "$launcher" "$log" || {
        echo "the application did not map a window" >&2
        if [[ -s "$log" ]]; then
            echo "--- last 60 log lines ---" >&2
            tail -60 "$log" >&2
        else
            # Chromium dying in its zygote produces no output at all, so an
            # empty log is itself the diagnosis rather than a missing one.
            echo "--- the application produced no output ---" >&2
            echo "That usually means Chromium's zygote could not start." >&2
            echo "user.max_user_namespaces = $(cat /proc/sys/user/max_user_namespaces 2>/dev/null || echo '?')" >&2
            echo "apparmor_restrict_unprivileged_userns = $(cat /proc/sys/kernel/apparmor_restrict_unprivileged_userns 2>/dev/null || echo 'n/a')" >&2
        fi
        exit 1
    }

echo "window mapped and still running 15s later"

fatal='SIGILL|Illegal instruction|error while loading shared libraries'
fatal="$fatal"'|cannot open shared object file|symbol lookup error'
fatal="$fatal"'|Failed to move to new namespace|No usable sandbox'

if grep -nE "$fatal" "$log"; then
    echo "fatal pattern in the startup log (shown above)" >&2
    exit 1
fi

echo "graphical startup clean"
