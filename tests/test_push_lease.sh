#!/usr/bin/env bash
# Behavioural tests for the updater's push lease, against real repositories.
#
# The updater force-updates its automation branch. A bare --force-with-lease
# compares against the remote-tracking ref, and the step used to `git fetch`
# that ref immediately beforehand -- which refreshes it to whatever is there
# *now*, so the lease was taken against a state nothing had verified and a
# concurrent update would be clobbered silently.
#
# Naming the expected object id makes the lease mean what it says. These tests
# drive real `git push` invocations to prove it.

set -uo pipefail

passed=0
failed=0
ok()  { printf '  ok    %s\n' "$1"; passed=$(( passed + 1 )); }
bad() { printf '  FAIL  %s\n     %s\n' "$1" "$2" >&2; failed=$(( failed + 1 )); }

BRANCH='automation/chatgpt-26.820.71523'

setup() {
    local root; root="$(mktemp -d)"
    git init -q --bare "$root/remote.git"
    git init -q "$root/a"
    (
        cd "$root/a"
        git config user.email t@t; git config user.name t
        git checkout -q -b main
        echo base > f; git add f; git commit -q -m base
        git remote add origin "$root/remote.git"
        git push -q origin main:refs/heads/main
    )
    printf '%s' "$root"
}

echo "== creating a branch that is still absent succeeds =="
root="$(setup)"
(
    cd "$root/a"
    git checkout -q -B "$BRANCH"
    echo candidate > sources.json; git add sources.json
    git commit -q -m candidate
    git push -q --force-with-lease="refs/heads/$BRANCH:" origin "HEAD:refs/heads/$BRANCH"
) && ok "absent branch -> create succeeds" \
  || bad "absent branch" "push failed but the branch was absent"
rm -rf "$root"

echo "== creating a branch another run already made is REFUSED =="
root="$(setup)"
(
    cd "$root/a"
    # Another run creates it first.
    git checkout -q -B other
    echo theirs > sources.json; git add sources.json; git commit -q -m theirs
    git push -q origin "HEAD:refs/heads/$BRANCH"
    # We still believe it is absent, and have a real commit to push.
    git checkout -q -B "$BRANCH" main
    echo ours > sources.json; git add sources.json; git commit -q -m ours
    git rev-parse --verify HEAD >/dev/null || exit 99
    git push -q --force-with-lease="refs/heads/$BRANCH:" origin "HEAD:refs/heads/$BRANCH" 2>/dev/null
)
rc=$?
if [ "$rc" -eq 99 ]; then
    bad "branch appeared meanwhile" "fixture broken: no commit to push"
elif [ "$rc" -ne 0 ]; then
    ok "branch appeared meanwhile -> create refused"
else
    bad "branch appeared meanwhile" "the push succeeded and clobbered another run"
fi
rm -rf "$root"

echo "== updating a branch still at the observed oid succeeds =="
root="$(setup)"
(
    cd "$root/a"
    git checkout -q -B "$BRANCH"
    echo first > sources.json; git add sources.json; git commit -q -m first
    git push -q origin "HEAD:refs/heads/$BRANCH"
    observed="$(git rev-parse HEAD)"
    echo second > sources.json; git add sources.json; git commit -q -m second
    git push -q --force-with-lease="refs/heads/$BRANCH:$observed" \
        origin "HEAD:refs/heads/$BRANCH"
) && ok "branch unchanged since observation -> update succeeds" \
  || bad "branch unchanged" "push refused despite a correct lease"
rm -rf "$root"

echo "== updating a branch that MOVED since observation is REFUSED =="
root="$(setup)"
(
    cd "$root/a"
    git checkout -q -B "$BRANCH"
    echo first > sources.json; git add sources.json; git commit -q -m first
    git push -q origin "HEAD:refs/heads/$BRANCH"
    observed="$(git rev-parse HEAD)"

    # Somebody else advances the branch after we observed it.
    git clone -q --branch main "$root/remote.git" "$root/b" 2>/dev/null
    (
        cd "$root/b"
        git config user.email t@t; git config user.name t
        git checkout -q "$BRANCH"
        echo theirs > sources.json; git add sources.json; git commit -q -m theirs
        git push -q origin "HEAD:refs/heads/$BRANCH"
    )

    echo ours > sources.json; git add sources.json; git commit -q -m ours
    # Refresh the remote-tracking ref, exactly as a `git fetch` before the push
    # would. A BARE lease would now pass; naming the observed oid must not.
    git fetch -q origin "$BRANCH" || true
    git push -q --force-with-lease="refs/heads/$BRANCH:$observed" \
        origin "HEAD:refs/heads/$BRANCH" 2>/dev/null
)
if [ $? -ne 0 ]; then
    ok "branch moved since observation -> update refused, even after a fetch"
else
    bad "branch moved" "the push clobbered a concurrent update"
fi
rm -rf "$root"

echo "== the bare lease this replaced would NOT have caught that =="
root="$(setup)"
(
    cd "$root/a"
    git checkout -q -B "$BRANCH"
    echo first > sources.json; git add sources.json; git commit -q -m first
    git push -q origin "HEAD:refs/heads/$BRANCH"
    git clone -q --branch main "$root/remote.git" "$root/b" 2>/dev/null
    (
        cd "$root/b"
        git config user.email t@t; git config user.name t
        git checkout -q "$BRANCH"
        echo theirs > sources.json; git add sources.json; git commit -q -m theirs
        git push -q origin "HEAD:refs/heads/$BRANCH"
    )
    echo ours > sources.json; git add sources.json; git commit -q -m ours
    git fetch -q origin "$BRANCH" || true
    git push -q --force-with-lease origin "HEAD:refs/heads/$BRANCH" 2>/dev/null
)
if [ $? -eq 0 ]; then
    ok "confirmed the old bare-lease form did clobber (regression documented)"
else
    ok "bare lease also refused here (git version is stricter; no harm)"
fi
rm -rf "$root"

printf '\n%d passed, %d failed\n' "$passed" "$failed"
[ "$failed" -eq 0 ]
