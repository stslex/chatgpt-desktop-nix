#!/usr/bin/env bash
# Behavioural tests for the base-metadata recovery, against real repositories.
#
# The rule being tested has two halves that pull in opposite directions:
#
#   * the bootstrap pull request -- the one that introduces sources.json -- has
#     nothing to compare against and must be allowed to proceed;
#   * once the protected branch carries the packaging, a missing sources.json
#     must fail the run, because otherwise deleting one file from that branch
#     would switch the version policy off.
#
# Getting only the first half right is what the original code did in reverse:
# it failed closed on everything, including the bootstrap, so the very first
# pull request could never go green.

set -uo pipefail

SCRIPT="$(cd "$(dirname "$0")/../tools" && pwd)/recover_base_sources.sh"

passed=0
failed=0
ok()  { printf '  ok    %s\n' "$1"; passed=$(( passed + 1 )); }
bad() { printf '  FAIL  %s\n     %s\n' "$1" "$2" >&2; failed=$(( failed + 1 )); }

# A clone with an origin/main that has whatever files the caller names.
setup() {
    local root; root="$(mktemp -d)"
    git init -q --bare "$root/remote.git"
    git init -q "$root/seed"
    (
        cd "$root/seed"
        git config user.email t@t; git config user.name t
        git checkout -q -b main
        for f in "$@"; do
            mkdir -p "$(dirname "$f")"
            case "$f" in
                sources.json) printf '{"version":"1.0"}' > "$f" ;;
                *)            printf 'x\n' > "$f" ;;
            esac
        done
        # Always something to commit, even with no files named.
        printf 'readme\n' > README.md
        git add -A; git commit -q -m base
        git remote add origin "$root/remote.git"
        git push -q origin main
    )
    git clone -q "$root/remote.git" "$root/work" 2>/dev/null
    printf '%s' "$root"
}

# Invoked through bash rather than by shebang: the Nix build sandbox this runs
# in has no /usr/bin/env, and the script must not depend on one.
run() { ( cd "$1/work" && bash "$SCRIPT" main out.json 2>"$1/err" ); }

echo "== a base branch with sources.json is recovered =="
root="$(setup sources.json flake.nix)"
if outp="$(run "$root")" \
   && [ "$(printf '%s' "$outp" | grep -c 'bootstrap=false')" -eq 1 ] \
   && printf '%s' "$outp" | grep -q 'path=out.json' \
   && grep -q '"version":"1.0"' "$root/work/out.json"; then
    ok "sources.json present -> recovered, bootstrap=false"
else
    bad "sources.json present" "got: $outp; err: $(cat "$root/err")"
fi
rm -rf "$root"

echo "== a base branch with NO packaging at all is the bootstrap =="
root="$(setup)"
if outp="$(run "$root")" && printf '%s' "$outp" | grep -q 'bootstrap=true'; then
    ok "empty base -> bootstrap=true, exit 0"
else
    bad "empty base" "expected bootstrap=true, got: $outp; err: $(cat "$root/err")"
fi
rm -rf "$root"

echo "== packaging present but sources.json deleted is REFUSED =="
for marker in flake.nix nix/package.nix tools/verify_sources.py; do
    root="$(setup "$marker")"
    if run "$root" >/dev/null; then
        bad "base has $marker, no sources.json" \
            "accepted as a bootstrap; deleting one file would disable the policy"
    elif grep -q "has $marker but no sources.json" "$root/err"; then
        ok "base has $marker, no sources.json -> refused"
    else
        bad "base has $marker, no sources.json" "wrong diagnostic: $(cat "$root/err")"
    fi
    rm -rf "$root"
done

echo "== an unresolvable base ref is REFUSED, not treated as a bootstrap =="
root="$(setup sources.json flake.nix)"
( cd "$root/work" && git update-ref -d refs/remotes/origin/main )
if run "$root" >/dev/null; then
    bad "origin/main missing" "an incomplete checkout was read as an absent file"
elif grep -q 'does not resolve to a commit' "$root/err"; then
    ok "origin/main unresolvable -> refused as indeterminate"
else
    bad "origin/main missing" "wrong diagnostic: $(cat "$root/err")"
fi
rm -rf "$root"

echo "== an empty sources.json is REFUSED =="
root="$(setup flake.nix)"
(
    cd "$root/seed"
    : > sources.json; git add sources.json; git commit -q -m empty
    git push -q origin main
)
( cd "$root/work" && git fetch -q origin main:refs/remotes/origin/main )
if run "$root" >/dev/null; then
    bad "empty sources.json" "accepted an empty file as base metadata"
elif grep -q 'is empty' "$root/err"; then
    ok "empty sources.json -> refused"
else
    bad "empty sources.json" "wrong diagnostic: $(cat "$root/err")"
fi
rm -rf "$root"

printf '\n%d passed, %d failed\n' "$passed" "$failed"
[ "$failed" -eq 0 ]
