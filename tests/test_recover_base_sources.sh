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

echo "== an unobtainable blob is REFUSED, not read as an absent file =="
# The dangerous shape, and the reason existence is decided with `git ls-tree`
# rather than `git cat-file -e`.
#
# `cat-file -e <ref>:<path>` needs the blob object. In a partial (blobless)
# clone that means fetching it from the promisor remote, which can fail for
# reasons that have nothing to do with whether the file exists. Reading that
# failure as "the file is not there" would report a bootstrap for a base branch
# that plainly has sources.json -- silently switching off the downgrade and
# drift rules.
#
# The state is built directly rather than by clone-and-filter, because a small
# local clone keeps the blob anyway and the fixture would prove nothing: the
# tree object stays, the blob goes.
root="$(mktemp -d)"
git init -q "$root/work"
(
    cd "$root/work"
    git config user.email t@t; git config user.name t
    git checkout -q -b main
    printf '{"version":"9.9"}' > sources.json
    printf 'x\n' > flake.nix
    git add -A; git commit -q -m base
    git update-ref refs/remotes/origin/main HEAD
    sha="$(git ls-tree origin/main -- sources.json | awk '{print $3}')"
    rm -f ".git/objects/${sha:0:2}/${sha:2}"
)
# Assert the fixture really is in the state being tested. Without this the
# whole case can pass for the wrong reason.
precondition_ok=1
( cd "$root/work" && git cat-file -e origin/main:sources.json 2>/dev/null ) \
    && precondition_ok=0
[ -n "$( cd "$root/work" && git ls-tree --name-only origin/main -- sources.json )" ] \
    || precondition_ok=0

if [ "$precondition_ok" -ne 1 ]; then
    bad "unobtainable blob" \
        "fixture broken: the blob is still readable, or the tree lost the path"
else
    outp="$( cd "$root/work" && bash "$SCRIPT" main out.json 2>&1 )"
    if printf '%s' "$outp" | grep -q 'bootstrap=true'; then
        bad "unobtainable blob" \
            "a base branch WITH sources.json was reported as a bootstrap, which
     silently disables the downgrade and drift rules"
    elif printf '%s' "$outp" | grep -q 'in the tree but could not be'; then
        ok "unobtainable blob -> refused as damage, not read as absent"
    else
        bad "unobtainable blob" "unexpected output: $outp"
    fi
fi
rm -rf "$root"

echo "== a DIRECTORY named sources.json is REFUSED, not read as metadata =="
# `git show` on a tree prints a listing, and that listing would have been
# written out and compared as though it were the base metadata.
root="$(mktemp -d)"
git init -q "$root/work"
(
    cd "$root/work"
    git config user.email t@t; git config user.name t
    git checkout -q -b main
    mkdir -p sources.json && printf 'inner\n' > sources.json/inner.txt
    printf 'x\n' > flake.nix
    git add -A; git commit -q -m base
    git update-ref refs/remotes/origin/main HEAD
)
outp="$( cd "$root/work" && bash "$SCRIPT" main out.json 2>&1 )"
if printf '%s' "$outp" | grep -q 'bootstrap=false'; then
    bad "directory named sources.json" \
        "accepted a tree as the base metadata; out.json would hold a git
     listing, not JSON"
elif printf '%s' "$outp" | grep -q 'is a tree, not a file'; then
    ok "a directory named sources.json -> refused"
else
    bad "directory named sources.json" "unexpected: $outp"
fi
rm -rf "$root"

echo "== a marker whose listing FAILS must not be read as absent =="
# Writing the marker test as [ -n "$(git ls-tree ...)" ] reads a failed listing
# as an absent marker: git's error goes to stderr, the substitution is empty,
# and the loop concludes the base carries no packaging -- reporting a bootstrap
# for a broken object store, which switches the version policy off.
root="$(mktemp -d)"
git init -q "$root/work"
(
    cd "$root/work"
    git config user.email t@t; git config user.name t
    git checkout -q -b main
    mkdir -p nix && printf 'x\n' > nix/package.nix
    printf 'y\n' > README
    git add -A; git commit -q -m base
    git update-ref refs/remotes/origin/main HEAD
    # Remove the tree object for nix/, so listing nix/package.nix fails.
    sub="$(git rev-parse 'HEAD:nix')"
    rm -f ".git/objects/${sub:0:2}/${sub:2}"
)
# Assert the fixture is in the state being tested.
if ( cd "$root/work" && git ls-tree --full-tree origin/main -- nix/package.nix ) \
        >/dev/null 2>&1; then
    bad "unreadable marker" "fixture broken: the marker listing still succeeds"
else
    outp="$( cd "$root/work" && bash "$SCRIPT" main out.json 2>&1 )"
    if printf '%s' "$outp" | grep -q 'bootstrap=true'; then
        bad "unreadable marker" \
            "reported a bootstrap while a marker listing was failing, which
     disables the downgrade and drift rules"
    elif printf '%s' "$outp" | grep -q 'refusing to draw'; then
        ok "an unreadable marker -> refused as indeterminate"
    else
        bad "unreadable marker" "unexpected: $outp"
    fi
fi
rm -rf "$root"

printf '\n%d passed, %d failed\n' "$passed" "$failed"
[ "$failed" -eq 0 ]
