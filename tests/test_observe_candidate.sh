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

echo "== a lookalike branch elsewhere must not hijack the observation =="
# `git ls-remote --heads <remote> automation/chatgpt-X` matches any head whose
# name ENDS with that path, so an ordinary branch like
# `wip/automation/chatgpt-X` also matches -- and sorts first, so reading line
# one takes the wrong branch's object id and sources.json. The query must name
# the fully-qualified ref.
root="$(setup_remote "$SOURCES")"
(
    cd "$root/work"
    git checkout -q -B decoy main 2>/dev/null || git checkout -q -B decoy
    # A decoy whose sources.json is valid but records a different package, so
    # picking it up would be visible rather than silently equivalent.
    printf '%s' "${SOURCES/pool\/main\/c\/chatgpt\/a.deb/pool\/main\/c\/chatgpt\/EVIL.deb}" \
        > sources.json
    git add sources.json; git commit -q -m decoy
    git push -q origin 'HEAD:refs/heads/AAA/automation/chatgpt-26.820.71523'
)
real_oid="$(git ls-remote "$root/remote.git" \
    'refs/heads/automation/chatgpt-26.820.71523' | awk '{print $1}')"
decoy_oid="$(git ls-remote "$root/remote.git" \
    'refs/heads/AAA/automation/chatgpt-26.820.71523' | awk '{print $1}')"

# Assert the fixture actually creates the ambiguity, or the case proves nothing.
matches="$(git ls-remote --heads "$root/remote.git" \
    'automation/chatgpt-26.820.71523' | wc -l)"
if [ "$matches" -lt 2 ] || [ "$real_oid" = "$decoy_oid" ]; then
    bad "lookalike branch" \
        "fixture broken: --heads matched $matches ref(s); the ambiguity this
     case exists for is not present"
else
    run_observe "$root/remote.git" 'automation/chatgpt-26.820.71523' '26.820.71523'
    if grep -q "oid=$decoy_oid" <<<"$OUT"; then
        bad "lookalike branch" \
            "observed the DECOY branch ($decoy_oid); its sources.json would be
     compared as this candidate's record and its oid bound into the push lease"
    elif [ "$RC" -eq 0 ] && grep -q "oid=$real_oid" <<<"$OUT"; then
        ok "lookalike branch present -> the exact ref is still observed"
    else
        bad "lookalike branch" "exit=$RC output=$OUT"
    fi
fi
rm -rf "$root"

echo "== a diagnostic on stderr must not be parsed as an object id =="
# The oid is extracted from this stream, so anything merged into it is input to
# that parser.
root="$(setup_remote "$SOURCES")"
run_observe "$root/remote.git" 'automation/chatgpt-26.820.71523' '26.820.71523'
if [ "$RC" -eq 0 ] \
   && [ "$(grep -c '^oid=' <<<"$OUT")" -eq 1 ] \
   && grep -qE '^oid=[0-9a-f]{40}$' <<<"$OUT"; then
    ok "exactly one well-formed oid line is emitted"
else
    bad "oid line" "exit=$RC output=$OUT"
fi
rm -rf "$root"

printf '\n%d passed, %d failed\n' "$passed" "$failed"
[ "$failed" -eq 0 ]
