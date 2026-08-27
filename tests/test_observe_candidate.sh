#!/usr/bin/env bash
# Behavioural tests for tools/observe_candidate.sh against real repositories.
#
# The bug these exist for could not be caught by reading: writing
#
#     if git ls-remote --exit-code ...; then ...; fi
#     rc=$?
#
# reads $? from the *if statement*, which succeeds whenever neither branch
# runs. rc was therefore 0 for a missing ref, the exit-2 case was never
# reached, and the updater aborted on every run where the automation branch did
# not yet exist -- which is every first run.
#
# So each case here drives the real script against a real git remote and
# asserts on its actual exit status and output.

set -uo pipefail

SCRIPT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/tools/observe_candidate.sh"
[[ -x "$SCRIPT" || -r "$SCRIPT" ]] || { echo "missing $SCRIPT" >&2; exit 1; }

passed=0
failed=0

ok()   { printf '  ok    %s\n' "$1"; passed=$(( passed + 1 )); }
bad()  { printf '  FAIL  %s\n     %s\n' "$1" "$2" >&2; failed=$(( failed + 1 )); }

SOURCES='{
  "version": "26.820.71523",
  "architectures": {
    "amd64": {"debianArchitecture":"amd64","filename":"pool/main/c/chatgpt/a.deb",
              "url":"https://example.invalid/a.deb","size":123,
              "sha256":"'"$(printf 'a%.0s' $(seq 64))"'","hash":"sha256-x"},
    "arm64": {"debianArchitecture":"arm64","filename":"pool/main/c/chatgpt/b.deb",
              "url":"https://example.invalid/b.deb","size":456,
              "sha256":"'"$(printf 'b%.0s' $(seq 64))"'","hash":"sha256-y"}
  }
}'

setup_remote() {
    # Returns a path to a bare remote that has main, and optionally an
    # automation branch carrying $1 as sources.json.
    local root; root="$(mktemp -d)"
    git init -q --bare "$root/remote.git"
    git init -q "$root/work"
    (
        cd "$root/work"
        git config user.email t@t; git config user.name t
        echo x > README
        git add README
        git commit -q -m init
        git remote add origin "$root/remote.git"
        git push -q origin HEAD:refs/heads/main
        if [ "$#" -gt 0 ]; then
            git checkout -q -b 'automation/chatgpt-26.820.71523'
            printf '%s' "$1" > sources.json
            git add sources.json
            git commit -q -m candidate
            git push -q origin HEAD:'refs/heads/automation/chatgpt-26.820.71523'
        fi
    )
    printf '%s' "$root"
}

run_observe() {
    # run_observe <remote> <branch> <version> ; sets OUT and RC
    local work; work="$(mktemp -d)"
    OUT="$(cd "$work" && git init -q . && OBSERVE_ATTEMPTS=2 OBSERVE_BACKOFF=0 \
        bash "$SCRIPT" "$1" "$2" "$3" "$work/observed.json" 2>&1)"
    RC=$?
    OBSERVED="$work/observed.json"
}

echo "== an absent branch is reported as absent, not as a failure =="
root="$(setup_remote)"
run_observe "$root/remote.git" 'automation/chatgpt-26.820.71523' '26.820.71523'
if [ "$RC" -eq 0 ] && grep -q '^state=absent$' <<<"$OUT"; then
    ok "absent branch -> state=absent, exit 0"
else
    bad "absent branch" "exit=$RC output=$OUT"
fi
rm -rf "$root"

echo "== an existing branch is recovered, with its object id =="
root="$(setup_remote "$SOURCES")"
run_observe "$root/remote.git" 'automation/chatgpt-26.820.71523' '26.820.71523'
if [ "$RC" -eq 0 ] && grep -q '^state=exists$' <<<"$OUT" \
   && grep -qE '^oid=[0-9a-f]{40}$' <<<"$OUT" \
   && grep -q '"version": "26.820.71523"' "$OBSERVED"; then
    ok "existing branch -> state=exists, oid captured, sources.json recovered"
else
    bad "existing branch" "exit=$RC output=$OUT"
fi
rm -rf "$root"

echo "== a transport failure is indeterminate, never 'absent' =="
run_observe 'https://nonexistent-host-for-tests.invalid/x.git' \
            'automation/chatgpt-26.820.71523' '26.820.71523'
if [ "$RC" -eq 30 ] && ! grep -q 'state=absent' <<<"$OUT"; then
    ok "transport failure -> exit 30, not absent"
else
    bad "transport failure" "exit=$RC output=$OUT"
fi

echo "== a branch whose sources.json records a different version fails closed =="
root="$(setup_remote "${SOURCES/26.820.71523/26.820.60940}")"
run_observe "$root/remote.git" 'automation/chatgpt-26.820.71523' '26.820.71523'
if [ "$RC" -eq 1 ] && grep -q 'records version' <<<"$OUT"; then
    ok "version mismatch -> exit 1"
else
    bad "version mismatch" "exit=$RC output=$OUT"
fi
rm -rf "$root"

echo "== an empty sources.json fails closed =="
root="$(setup_remote "")"
run_observe "$root/remote.git" 'automation/chatgpt-26.820.71523' '26.820.71523'
if [ "$RC" -eq 1 ]; then
    ok "empty sources.json -> exit 1"
else
    bad "empty sources.json" "exit=$RC output=$OUT"
fi
rm -rf "$root"

echo "== a malformed sources.json fails closed =="
root="$(setup_remote '{ this is not json')"
run_observe "$root/remote.git" 'automation/chatgpt-26.820.71523' '26.820.71523'
if [ "$RC" -eq 1 ] && grep -q 'not valid JSON' <<<"$OUT"; then
    ok "malformed sources.json -> exit 1"
else
    bad "malformed sources.json" "exit=$RC output=$OUT"
fi
rm -rf "$root"

echo "== an incomplete architecture entry fails closed =="
root="$(setup_remote '{"version":"26.820.71523","architectures":{"amd64":{"filename":"x"}}}')"
run_observe "$root/remote.git" 'automation/chatgpt-26.820.71523' '26.820.71523'
if [ "$RC" -eq 1 ] && grep -q 'missing' <<<"$OUT"; then
    ok "incomplete metadata -> exit 1"
else
    bad "incomplete metadata" "exit=$RC output=$OUT"
fi
rm -rf "$root"

echo "== a branch with no sources.json at all fails closed =="
root="$(mktemp -d)"
git init -q --bare "$root/remote.git"
git init -q "$root/work"
(
    cd "$root/work"
    git config user.email t@t; git config user.name t
    echo x > README; git add README; git commit -q -m init
    git remote add origin "$root/remote.git"
    git push -q origin HEAD:'refs/heads/automation/chatgpt-26.820.71523'
)
run_observe "$root/remote.git" 'automation/chatgpt-26.820.71523' '26.820.71523'
if [ "$RC" -eq 1 ] && grep -q 'no sources.json' <<<"$OUT"; then
    ok "branch without sources.json -> exit 1"
else
    bad "branch without sources.json" "exit=$RC output=$OUT"
fi
rm -rf "$root"

printf '\n%d passed, %d failed\n' "$passed" "$failed"
[ "$failed" -eq 0 ]
