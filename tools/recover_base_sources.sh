#!/usr/bin/env bash
# Recover the protected branch's sources.json, or prove it is legitimately absent.
#
# The no-downgrade and no-drift rules are applied against the base branch's
# metadata. If that metadata cannot be obtained the rules cannot be enforced,
# and quietly carrying on would let a run report success having checked less
# than it claims.
#
# But "cannot be obtained" and "is not there" are different situations, and to
# `git show` they look identical -- both are just a non-zero exit. Only one of
# them may be tolerated, so this determines which it is positively rather than
# inferring it from a failure.
#
# Usage: recover_base_sources.sh <base-ref> <output-path>
#
# Prints `bootstrap=true|false` and, when false, `path=<output-path>` on stdout
# in the key=value form GitHub Actions step outputs use.
#
# Exit codes
# ----------
# 0   determinate: either the metadata was recovered, or its absence is the
#     bootstrap case and no comparison is possible yet
# 1   indeterminate or wrong: the caller must not proceed

set -uo pipefail

if [ "$#" -ne 2 ]; then
    echo "usage: $0 <base-ref> <output-path>" >&2
    exit 1
fi

base_ref="$1"
out_path="$2"

# Start from the ref itself. If origin/<base> does not resolve, the checkout is
# incomplete, and nothing whatsoever may be concluded from a missing file --
# least of all that it is missing upstream.
if ! git rev-parse --verify --quiet "origin/$base_ref^{commit}" >/dev/null; then
    echo "origin/$base_ref does not resolve to a commit in this checkout," >&2
    echo "so the policy comparison cannot be made and the absence of the" >&2
    echo "metadata cannot be interpreted." >&2
    exit 1
fi

# Decide existence from the TREE, not from the blob.
#
# `git cat-file -e <ref>:<path>` needs the blob object itself, and in a partial
# (blobless) clone that means a fetch from the promisor remote. If that remote
# is momentarily unreachable the command fails -- and reading that failure as
# "the file is not there" would turn a network problem into a silently disabled
# version policy, which is the exact outcome this script exists to prevent.
# `git ls-tree` answers from the tree object, which is always local.
if ! listing="$(git ls-tree --name-only "origin/$base_ref" -- sources.json)"; then
    echo "could not list the tree of origin/$base_ref" >&2
    exit 1
fi

if [ -n "$listing" ]; then
    # The path is in the tree, so it must be readable. A failure here is a real
    # failure -- a missing blob, a broken object store -- and never a bootstrap.
    if ! git show "origin/$base_ref:sources.json" > "$out_path"; then
        echo "origin/$base_ref:sources.json is in the tree but could not be" >&2
        echo "read. This is a damaged or incomplete object store, not an" >&2
        echo "absent file; refusing to treat it as one." >&2
        exit 1
    fi
    if [ ! -s "$out_path" ]; then
        echo "origin/$base_ref:sources.json is empty" >&2
        exit 1
    fi
    echo "bootstrap=false"
    echo "path=$out_path"
    exit 0
fi

# The ref resolves and the file is genuinely absent. That is legitimate in
# exactly one situation: the pull request that introduces the packaging, where
# there is no previous version to compare against.
#
# Once the base branch carries the packaging, a missing sources.json is damage
# or an attack rather than a bootstrap -- and treating it as a bootstrap would
# turn "delete one file from the protected branch" into "switch the version
# policy off". So require the base to carry no packaging at all.
for marker in flake.nix nix/package.nix tools/verify_sources.py; do
    if [ -n "$(git ls-tree --name-only "origin/$base_ref" -- "$marker")" ]; then
        echo "origin/$base_ref has $marker but no sources.json." >&2
        echo "That is not a bootstrap: the branch is missing metadata the" >&2
        echo "update policy depends on. Refusing to verify without it." >&2
        exit 1
    fi
done

echo "bootstrap=true"
exit 0
