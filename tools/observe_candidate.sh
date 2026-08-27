#!/usr/bin/env bash
# Determine what candidate, if any, is already recorded for a version.
#
# The updater force-updates its automation branch. Before it may do that it has
# to know what that branch currently holds, because a same-version republish
# with different bytes is a manual-review event and the branch is the only
# record of what was seen first.
#
# The distinction this script exists to preserve is between:
#
#   absent  - the branch demonstrably does not exist; there is nothing to
#             compare against and the caller may proceed
#   exists  - the branch is there, and its sources.json is the record
#   unknown - the question was not answered
#
# "unknown" must never be collapsed into "absent". Doing so skips the drift
# guard entirely, which is how a transient network failure would silently
# reopen the gap that guard closes.
#
# Usage: observe_candidate.sh <remote> <branch> <expected-version> <out-file>
#
# Prints "state=<absent|exists>" and, when it exists, "oid=<sha>" on stdout for
# the caller to consume. Exit 0 determinate, 30 indeterminate, 1 malformed.

set -uo pipefail

remote="${1:?usage: observe_candidate.sh <remote> <branch> <version> <out>}"
branch="${2:?missing branch}"
version="${3:?missing expected version}"
out="${4:?missing output path}"

attempts="${OBSERVE_ATTEMPTS:-5}"
backoff="${OBSERVE_BACKOFF:-5}"

state=""
oid=""

for attempt in $(seq 1 "$attempts"); do
    # Capture the status directly from the command. Writing this as
    #   if git ls-remote ...; then ...; fi
    #   rc=$?
    # reads $? from the *if statement*, which succeeds whenever no branch runs
    # -- so rc is 0 for a missing ref and the exit-2 case is never seen.
    listing="$(git ls-remote --exit-code --heads "$remote" "$branch" 2>&1)"
    rc=$?

    case "$rc" in
        0)
            state=exists
            oid="$(printf '%s\n' "$listing" | awk 'NR==1 {print $1}')"
            break
            ;;
        2)
            state=absent
            break
            ;;
        *)
            echo "ls-remote could not answer (exit $rc): $listing" >&2
            if [ "$attempt" -lt "$attempts" ]; then
                echo "  retry $attempt/$((attempts - 1))" >&2
                sleep $(( attempt * backoff ))
            fi
            ;;
    esac
done

if [ -z "$state" ]; then
    echo "could not determine whether $branch exists on $remote." >&2
    echo "Proceeding would skip the same-version drift guard, so this run" >&2
    echo "stops. A later scheduled run will retry the same candidate." >&2
    exit 30
fi

if [ "$state" = "absent" ]; then
    echo "no automation branch exists for $version"
    echo "state=absent"
    exit 0
fi

if ! printf '%s' "$oid" | grep -qE '^[0-9a-f]{40}$'; then
    echo "ls-remote reported $branch exists but gave no usable object id" >&2
    exit 30
fi

# The branch exists, so everything from here is a hard requirement. A failure
# is a failure, never an absence.
if ! git fetch --quiet --depth=1 "$remote" "+$oid:refs/observed/candidate" \
        2>/dev/null \
   && ! git fetch --quiet --depth=1 "$remote" "+$branch:refs/observed/candidate"; then
    echo "$branch exists but could not be fetched" >&2
    exit 30
fi

if ! git cat-file -e "refs/observed/candidate:sources.json" 2>/dev/null; then
    echo "$branch carries no sources.json." >&2
    echo "This automation never creates a branch without one; review it." >&2
    exit 1
fi

if ! git show "refs/observed/candidate:sources.json" > "$out"; then
    echo "could not read sources.json from $branch" >&2
    exit 30
fi

if [ ! -s "$out" ]; then
    echo "$branch has an empty sources.json" >&2
    exit 1
fi

# Validate it before the caller compares against it. An unparsable or
# different-version observation is not a usable record, and treating it as one
# would mean comparing a candidate against nothing.
if ! python3 - "$out" "$version" <<'PY'
import json, sys

path, expected = sys.argv[1], sys.argv[2]
try:
    with open(path, encoding="utf-8") as fh:
        doc = json.load(fh)
except (OSError, ValueError) as exc:
    print(f"observed sources.json is not valid JSON: {exc}", file=sys.stderr)
    raise SystemExit(1)

if not isinstance(doc, dict):
    print("observed sources.json is not an object", file=sys.stderr)
    raise SystemExit(1)

if doc.get("version") != expected:
    print(
        f"observed branch records version {doc.get('version')!r}, but this run "
        f"resolved {expected!r}.\n"
        f"The branch name is derived from the version, so these must agree; a "
        f"mismatch means the branch is not the record for this candidate.",
        file=sys.stderr,
    )
    raise SystemExit(1)

architectures = doc.get("architectures")
if not isinstance(architectures, dict) or not architectures:
    print("observed sources.json has no architectures", file=sys.stderr)
    raise SystemExit(1)

for arch, entry in architectures.items():
    if not isinstance(entry, dict):
        print(f"observed {arch} entry is not an object", file=sys.stderr)
        raise SystemExit(1)
    for field in ("filename", "url", "size", "sha256", "hash",
                  "debianArchitecture"):
        if field not in entry:
            print(f"observed {arch} entry is missing {field}", file=sys.stderr)
            raise SystemExit(1)
    if not isinstance(entry["size"], int) or entry["size"] <= 0:
        print(f"observed {arch} size is not a positive integer", file=sys.stderr)
        raise SystemExit(1)
    if not isinstance(entry["sha256"], str) or len(entry["sha256"]) != 64:
        print(f"observed {arch} sha256 is malformed", file=sys.stderr)
        raise SystemExit(1)
PY
then
    echo "the observed candidate is not a complete record; review $branch" >&2
    exit 1
fi

echo "recovered the candidate already recorded on $branch at $oid"
echo "state=exists"
echo "oid=$oid"
