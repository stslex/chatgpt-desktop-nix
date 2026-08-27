#!/usr/bin/env python3
"""Open or update exactly one issue per failing upstream version.

The updater retries on a schedule, so a candidate that fails today will be
retried tomorrow and the day after. Filing a fresh issue each time would bury
the signal in noise, so this keeps one issue per upstream version and appends a
comment to it on each subsequent failure.

The issue title carries the version, which is what makes deduplication work
across runs.
"""

from __future__ import annotations

import argparse
import json
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
    "unknown": (
        "Unclassified failure",
        "The updater failed in a way it could not classify. See the run log.",
    ),
}


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

    kind = args.kind if args.kind in KIND_DESCRIPTIONS else "unknown"
    heading, explanation = KIND_DESCRIPTIONS[kind]
    title = f"Upstream update {args.version} failed: {heading.lower()}"
    label = "automated-update-failure"

    # One issue per version. Search by exact title among open issues.
    existing = json.loads(
        gh("issue", "list", "--repo", args.repo, "--state", "open",
           "--json", "number,title", "--limit", "100") or "[]"
    )
    match = next((i for i in existing if i["title"] == title), None)

    body = f"""**Failure class:** {heading}

{explanation}

| | |
| --- | --- |
| Upstream version | `{args.version}` |
| Failure class | `{kind}` |
| Workflow run | {args.run_url} |

The protected branch and the current release are unchanged. If an automation
pull request was opened for this version it is still open and unmerged.

A later scheduled run will retry the same candidate. This issue is updated
rather than duplicated, so repeated failures appear as comments below.
"""

    if match is None:
        # The label may already exist; that is not an error.
        subprocess.run(
            ["gh", "label", "create", label, "--repo", args.repo,
             "--description", "The signed updater could not land a version",
             "--color", "d73a4a"],
            capture_output=True, text=True,
        )
        number = gh("issue", "create", "--repo", args.repo,
                    "--title", title, "--body", body,
                    "--label", label).strip()
        print(f"opened issue for {args.version}: {number}")
    else:
        gh("issue", "comment", str(match["number"]), "--repo", args.repo,
           "--body", f"Retried and failed again.\n\n"
                     f"- Workflow run: {args.run_url}\n"
                     f"- Failure class: `{kind}`")
        print(f"updated existing issue #{match['number']} for {args.version}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
