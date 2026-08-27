#!/usr/bin/env python3
"""Enforce what an automated update pull request is allowed to change.

The updater's pull requests merge without human review, so the set of files
they may touch has to be narrow and enforced by CI rather than by convention.
An automation branch may change ``sources.json`` and nothing else — no
packaging code, no workflow files, no ELF baselines, no tests, no flake.lock.

Ordinary human pull requests are unconstrained; they are gated by review
instead. This job only tightens the rules for branches that claim to be
automation.

Exit codes
----------
0   the pull request is allowed
1   an automation branch changed something it must not
"""

from __future__ import annotations

import argparse
import re
import subprocess
import sys

sys.path.insert(0, __file__.rsplit("/", 1)[0])

import apt_trust as T  # noqa: E402

#: Automation branches are named `automation/chatgpt-<encoded-version>`, where
#: the encoding is :func:`apt_trust.encode_version_for_ref`. The pattern is
#: derived from that function's own safe-character set rather than written out
#: by hand, because the two drifting apart is silent and one-directional: a
#: branch this does not recognise is treated as an ordinary human pull request
#: and the strict file policy is skipped entirely.
#:
#: Hand-writing it is exactly how '%' came to be missing here, which meant any
#: upstream version with a Debian revision, epoch, tilde or plus -- `26.1.0-1`
#: encodes to `26.1.0%2D1` -- produced a real automation branch that this file
#: silently waved through.
_SAFE = "".join(sorted(T._REF_SAFE))
AUTOMATION_BRANCH = re.compile(
    r"^automation/chatgpt-(?:[" + re.escape(_SAFE) + r"]|%[0-9A-F]{2})+$")

#: The only path an automation pull request may modify.
ALLOWED = frozenset({"sources.json"})

#: Paths that must never appear in an automation pull request, called out
#: separately so the failure message can say why.
FORBIDDEN_REASONS = [
    (re.compile(r"^\.github/"),
     "workflow and CI configuration changes must be reviewed by a human"),
    (re.compile(r"^nix/"), "packaging code must be reviewed by a human"),
    (re.compile(r"^tools/"), "updater code must be reviewed by a human"),
    (re.compile(r"^tests/"), "test changes must be reviewed by a human"),
    (re.compile(r"^trust/"),
     "the signing key is a fixed anchor; rotation is a manual-review event"),
    (re.compile(r"^elf-baseline/"),
     "ELF baselines encode a reviewed payload shape and must not widen "
     "automatically"),
    (re.compile(r"^flake\.lock$"),
     "the nixpkgs pin must be updated deliberately, not as a side effect"),
    (re.compile(r"^flake\.nix$"), "the flake interface must be reviewed"),
]


def changed_files(base: str) -> list[str]:
    proc = subprocess.run(
        ["git", "diff", "--name-only", f"{base}...HEAD"],
        capture_output=True, text=True,
    )
    if proc.returncode != 0:
        # Fall back to a two-dot diff when the merge base is unavailable.
        proc = subprocess.run(
            ["git", "diff", "--name-only", base, "HEAD"],
            capture_output=True, text=True, check=True,
        )
    return [line for line in proc.stdout.splitlines() if line.strip()]


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--base", required=True)
    parser.add_argument("--head-ref", required=True)
    parser.add_argument("--head-repo", default="")
    parser.add_argument("--this-repo", default="")
    args = parser.parse_args()

    files = changed_files(args.base)
    print(f"pull request head: {args.head_ref}")
    print(f"changed files ({len(files)}):")
    for path in files:
        print(f"  {path}")

    if not AUTOMATION_BRANCH.match(args.head_ref):
        print("\nnot an automation branch; the changed-file policy does not "
              "apply and review gates this pull request instead")
        return 0

    print(f"\n{args.head_ref} claims to be an automated update; "
          "applying the strict policy")

    problems: list[str] = []

    # An automation branch must come from this repository. A fork could
    # otherwise present a branch with the right name to a workflow that treats
    # the name as meaningful.
    if args.head_repo and args.this_repo and args.head_repo != args.this_repo:
        problems.append(
            f"automation branches must originate in {args.this_repo}, but this "
            f"one comes from {args.head_repo}"
        )

    if not files:
        problems.append("an automated update must change sources.json, but "
                        "this pull request changes nothing")

    for path in files:
        if path in ALLOWED:
            continue
        reason = next(
            (why for pattern, why in FORBIDDEN_REASONS if pattern.match(path)),
            "only sources.json may be changed by an automated update",
        )
        problems.append(f"{path}: {reason}")

    if problems:
        print("\nthis automated pull request is not eligible to merge:",
              file=sys.stderr)
        for problem in problems:
            print(f"  - {problem}", file=sys.stderr)
        print(
            "\nIf this change is legitimate, open it as an ordinary reviewed "
            "pull request from a non-automation branch.",
            file=sys.stderr,
        )
        return 1

    print("\nchanged-file policy satisfied: only sources.json was modified")
    return 0


if __name__ == "__main__":
    sys.exit(main())
