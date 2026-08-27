#!/usr/bin/env python3
"""Decide whether a pull request may have auto-merge enabled.

Auto-merge lets a pull request land with no human looking at it, so before it
is enabled every property that makes this particular request safe has to be
checked explicitly. Nothing here is inferred from the title or from the fact
that the updater workflow is the caller: each property is read back from the
GitHub API and compared against what was expected.

If any check fails the pull request is left open, unmerged, for a human.

Exit codes
----------
0   the pull request is eligible for auto-merge
1   it is not
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys

sys.path.insert(0, __file__.rsplit("/", 1)[0])

import apt_trust as T  # noqa: E402

#: The only file an automated update may touch.
ALLOWED_FILES = {"sources.json"}


def _consistent_snapshot(repo: str, pr_number: str, attempts: int = 3):
    """Read the mutable PR state, and prove it did not move while reading.

    Returns ``(pr, files, head_sha)`` or ``(None, None, None)`` if the head
    moved on every attempt.
    """
    for _ in range(attempts):
        before = gh_api(f"repos/{repo}/pulls/{pr_number}")
        head = before.get("head", {}).get("sha")
        files = gh_api(f"repos/{repo}/pulls/{pr_number}/files")
        after = gh_api(f"repos/{repo}/pulls/{pr_number}")
        if head and after.get("head", {}).get("sha") == head:
            # Labels and base come from the same object, so they are part of
            # this snapshot too.
            return after, files, head
    return None, None, None


def gh_api(path: str) -> dict:
    proc = subprocess.run(
        ["gh", "api", path], capture_output=True, text=True, check=False
    )
    if proc.returncode != 0:
        raise SystemExit(f"gh api {path} failed: {proc.stderr.strip()}")
    return json.loads(proc.stdout)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo", required=True)
    parser.add_argument("--pr", required=True)
    parser.add_argument("--expected-branch", required=True)
    parser.add_argument("--expected-base", required=True)
    parser.add_argument("--expected-version", required=True)
    parser.add_argument("--expected-label", required=True)
    parser.add_argument("--expected-author", required=True)
    parser.add_argument(
        "--emit-head",
        help="write the exact head SHA every check was made against here, so "
             "the caller can bind the merge to it",
    )
    args = parser.parse_args()

    # Take one internally consistent snapshot of everything mutable.
    #
    # The pull request object, its file list, its labels and the base branch's
    # own contents are separate reads. Checking them independently means a push
    # landing between two of them leaves an old head validated against a new
    # diff. So: read, re-read the head, and require it unmoved across the whole
    # inspection. Any movement means no single state was ever observed whole,
    # and the honest response is to decline rather than pick a half.
    pr, files, head_sha = _consistent_snapshot(args.repo, args.pr)
    if pr is None:
        print(
            f"{args.repo}#{args.pr}: the pull request kept changing while it "
            f"was being inspected; refusing to enable auto-merge on a state "
            f"that was never observed whole.",
            file=sys.stderr,
        )
        return 1

    problems: list[str] = []
    checks: list[tuple[str, bool, str]] = []

    def record(name: str, ok: bool, detail: str) -> None:
        checks.append((name, ok, detail))
        if not ok:
            problems.append(f"{name}: {detail}")

    # 1. The author must be exactly the updater App.
    author = pr.get("user", {}).get("login", "")
    record(
        "author is the updater App",
        author == args.expected_author,
        f"expected {args.expected_author!r}, got {author!r}",
    )

    # 2. The base must be the protected default branch.
    base = pr.get("base", {}).get("ref", "")
    record(
        "base is the protected branch",
        base == args.expected_base,
        f"expected {args.expected_base!r}, got {base!r}",
    )

    # 3. The head must live in this repository, never a fork. A fork could
    #    otherwise present a branch with a name that looks like automation.
    head_repo = pr.get("head", {}).get("repo", {}).get("full_name", "")
    record(
        "head is in this repository",
        head_repo == args.repo,
        f"expected {args.repo!r}, got {head_repo!r}",
    )

    # 4. The branch name must match the exact automation pattern.
    head_ref = pr.get("head", {}).get("ref", "")
    record(
        "branch matches automation/chatgpt-<version>",
        head_ref == args.expected_branch,
        f"expected {args.expected_branch!r}, got {head_ref!r}",
    )

    # 5. The update label must be present.
    labels = {label["name"] for label in pr.get("labels", [])}
    record(
        "carries the automated-update label",
        args.expected_label in labels,
        f"expected {args.expected_label!r} among {sorted(labels)}",
    )

    # 6. Only sources.json may change.
    changed = {entry["filename"] for entry in files}
    record(
        "changes only sources.json",
        changed == ALLOWED_FILES,
        f"expected {sorted(ALLOWED_FILES)}, got {sorted(changed)}",
    )

    # 7. Called out separately because these are the changes that would be
    #    most damaging to let through unreviewed.
    record(
        "touches nothing under .github/",
        not any(f.startswith(".github/") for f in changed),
        f"workflow files changed: {sorted(f for f in changed if f.startswith('.github/'))}",
    )
    sensitive = {"flake.lock", "flake.nix"}
    record(
        "touches no packaging code, flake.lock or tests",
        not any(
            f in sensitive or f.startswith(("nix/", "tools/", "tests/",
                                            "trust/", "elf-baseline/"))
            for f in changed
        ),
        f"sensitive paths changed: {sorted(changed - ALLOWED_FILES)}",
    )

    # 8. The pull request must be open and mergeable in principle.
    record("is open", pr.get("state") == "open", f"state is {pr.get('state')!r}")
    record("is not a draft", not pr.get("draft", False), "pull request is a draft")

    # 9. The candidate version must actually be newer than what the protected
    #    branch has, compared with Debian ordering rather than as a string.
    try:
        base_json = gh_api(
            f"repos/{args.repo}/contents/sources.json?ref={args.expected_base}")
        import base64
        base_sources = json.loads(
            base64.b64decode(base_json["content"]).decode("utf-8"))
        base_version = base_sources.get("version", "")
        newer = T.compare_debian_versions(args.expected_version, base_version) > 0
        record(
            "candidate version is newer than the base branch",
            newer,
            f"{args.expected_version} is not newer than {base_version}",
        )
    except Exception as exc:  # noqa: BLE001 - any failure here must block
        record("candidate version is newer than the base branch", False,
               f"could not compare versions: {exc}")

    # 10. The head SHA must still be the one we just pushed, so nothing was
    #     appended between opening the pull request and enabling auto-merge.
    #     head_sha comes from the consistent snapshot above.
    local = subprocess.run(
        ["git", "rev-parse", "HEAD"], capture_output=True, text=True, check=False
    ).stdout.strip()
    record(
        "head SHA matches the verified candidate",
        bool(head_sha) and head_sha == local,
        f"pull request head is {head_sha!r}, local HEAD is {local!r}",
    )

    # 11. The diff must contain the version we verified.
    version_in_diff = any(
        args.expected_version in entry.get("patch", "")
        for entry in files if entry["filename"] == "sources.json"
    )
    record(
        "diff contains the verified version",
        version_in_diff,
        f"{args.expected_version} does not appear in the sources.json diff",
    )

    width = max(len(name) for name, _, _ in checks)
    print(f"auto-merge eligibility for {args.repo}#{args.pr}:")
    for name, ok, detail in checks:
        mark = "ok  " if ok else "FAIL"
        print(f"  [{mark}] {name.ljust(width)}"
              + ("" if ok else f"  — {detail}"))

    if problems:
        print(
            f"\n{len(problems)} eligibility check(s) failed; auto-merge will "
            "NOT be enabled. The pull request stays open for a human.",
            file=sys.stderr,
        )
        return 1

    print("\nevery eligibility check passed; auto-merge may be enabled")

    # Hand the caller the exact SHA every check above was made against, so the
    # merge can be bound to it. Enabling auto-merge without that binding would
    # let a push between this check and the merge carry different content in
    # under a decision made about the old one.
    if args.emit_head:
        with open(args.emit_head, "w", encoding="utf-8") as fh:
            fh.write(head_sha)
    print(f"verified head: {head_sha}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
