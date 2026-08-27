#!/usr/bin/env python3
"""Open or update exactly one issue per failing upstream version.

The updater retries on a schedule, so a candidate that fails today will be
retried tomorrow and the day after. Filing a fresh issue each time would bury
the signal, so this keeps one issue per upstream version and appends a comment
on each subsequent failure.

The issue is keyed on the version alone, deliberately. Keying it on version
plus failure class would file a second issue the moment the same candidate
failed a different way — which is exactly what happens as a broken version
moves from "trust failure" to "build failure" and back, and is the opposite of
deduplication.
"""

from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys

KIND_DESCRIPTIONS = {
    "trust": (
        "Trust verification",
        "A signature, digest, size, version or architecture check failed. "
        "This is a fail-closed breakpoint: the signing key may have rotated, "
        "an already-known version may have been republished with different "
        "bytes, or the repository layout may have changed. **Do not add a "
        "waiver.** A human must establish what happened before anything "
        "merges.",
    ),
    "network": (
        "Upstream availability",
        "The OpenAI CDN could not be reached within the retry budget. This is "
        "usually transient — the origin intermittently aborts TLS handshakes — "
        "and the next scheduled run will retry the same candidate. No action "
        "is needed unless it persists.",
    ),
    "build": (
        "Packaging drift",
        "The signed sources verified, but the package did not build or the "
        "ELF inventory no longer matches the reviewed baseline. The upstream "
        "payload has probably changed shape. Review the new inventory by hand "
        "and update the baseline in a reviewed commit.",
    ),
    "runtime": (
        "Runtime regression",
        "The package built but a runtime gate failed — the graphical smoke "
        "test, the interpreter-window regression, a bundled helper, or the "
        "sandbox bridge. Review the logs before allowing this version.",
    ),
    "timeout": (
        "Job timeout",
        "A CI job exceeded its time limit or failed to start. That is usually "
        "infrastructure rather than this package, but a build that has grown "
        "past its budget looks the same, so it is worth a glance.",
    ),
    "unknown": (
        "Unclassified failure",
        "The updater failed in a way it could not classify. See the run log.",
    ),
}

#: The updater sanitises versions to this shape before they reach a branch
#: name, and the branch name is where this value comes from.
VERSION_RE = re.compile(r"^[A-Za-z0-9._-]{1,64}$")


def gh(*args: str) -> str:
    proc = subprocess.run(["gh", *args], capture_output=True, text=True)
    if proc.returncode != 0:
        raise SystemExit(f"gh {' '.join(args)} failed: {proc.stderr.strip()}")
    return proc.stdout


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo", required=True)
    parser.add_argument("--version", required=True)
    parser.add_argument("--kind", default="unknown")
    parser.add_argument("--run-url", required=True)
    args = parser.parse_args()

    version = args.version.strip()
    if not VERSION_RE.match(version):
        # Never let an unconstrained string reach an issue title.
        raise SystemExit(f"refusing to report on version {version!r}")

    kind = args.kind if args.kind in KIND_DESCRIPTIONS else "unknown"
    heading, explanation = KIND_DESCRIPTIONS[kind]

    # Keyed on the version only. The failure class goes in the body, where it
    # can change between runs without splitting the thread.
    title = f"Upstream update {version} cannot land"
    label = "automated-update-failure"

    existing = json.loads(
        gh("issue", "list", "--repo", args.repo, "--state", "open",
           "--json", "number,title", "--limit", "100") or "[]"
    )
    match = next((i for i in existing if i["title"] == title), None)

    body = f"""Automated updates for `{version}` are not landing.

**Latest failure:** {heading}

{explanation}

| | |
| --- | --- |
| Upstream version | `{version}` |
| Failure class | `{kind}` |
| Workflow run | {args.run_url} |

The protected branch and the current release are unchanged. If an automation
pull request was opened for this version it is still open and unmerged.

A later scheduled run will retry the same candidate. This issue is keyed on the
version, so repeated failures — including failures of a different kind — appear
as comments below rather than as new issues.
"""

    if match is None:
        subprocess.run(
            ["gh", "label", "create", label, "--repo", args.repo,
             "--description", "The signed updater could not land a version",
             "--color", "d73a4a"],
            capture_output=True, text=True,
        )
        url = gh("issue", "create", "--repo", args.repo,
                 "--title", title, "--body", body,
                 "--label", label).strip()
        print(f"opened issue for {version}: {url}")
    else:
        gh("issue", "comment", str(match["number"]), "--repo", args.repo,
           "--body", f"Failed again — **{heading}**.\n\n"
                     f"- Workflow run: {args.run_url}\n"
                     f"- Failure class: `{kind}`")
        print(f"updated existing issue #{match['number']} for {version}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
