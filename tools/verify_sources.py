#!/usr/bin/env python3
"""Independently re-derive the signed sources and compare them to what is committed.

CI runs this instead of trusting ``sources.json``. It repeats the whole trust
chain against the live OpenAI repository and then asserts that the committed
file is exactly what that chain produces.

The distinction matters: a check that merely re-hashed the committed file would
prove the file is internally consistent, not that it describes what OpenAI
actually publishes. This one starts from the pinned key and works forward.

Exit codes
----------
0   the committed metadata matches the signed chain
20  trust/verification failure
21  the committed metadata does not match what the chain produced
30  network failure after bounded retries
"""

from __future__ import annotations

import argparse
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import apt_trust as T  # noqa: E402
import update as U  # noqa: E402


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--strict", action="store_true",
        help="also download and verify each .deb body and its control fields",
    )
    parser.add_argument(
        "--base-sources",
        help="the protected branch's sources.json; when given, the committed "
             "metadata is additionally held to the no-downgrade and "
             "no-same-version-drift rules against it",
    )
    args = parser.parse_args()

    committed = U.load_sources()
    if not committed:
        print("sources.json is missing", file=sys.stderr)
        return 21

    try:
        print(f"Re-deriving signed metadata from {T.APT_ORIGIN}")
        print(f"  trust anchor: {T.EXPECTED_KEY_FINGERPRINT}")
        print("  (the committed sources.json is NOT consulted for this)")

        T.assert_keyring_identity(U.KEYRING_PATH)
        print("  committed keyring matches the reviewed bytes and fingerprint")

        release = T.resolve_signed_release(
            lambda url: U.fetch(url, max_bytes=T.MAX_INDEX_BYTES),
            U.KEYRING_PATH,
        )
        print(f"  InRelease verified; upstream version {release.version}")

        derived = U.render_sources(release)

    except T.TrustError as exc:
        print(f"\nTRUST FAILURE: {exc}", file=sys.stderr)
        return 20
    except U.NetworkError as exc:
        print(f"\nNETWORK FAILURE: {exc}", file=sys.stderr)
        return 30

    if committed.get("version") != derived["version"]:
        # This is the expected state between an upstream release and the
        # updater's PR merging. It is only an error for CI, which must not
        # green-light metadata that disagrees with the origin.
        print(
            f"\nCommitted version {committed.get('version')} differs from the "
            f"currently published {derived['version']}.",
            file=sys.stderr,
        )
        print(
            "If this is a pull request that predates an upstream release, "
            "rebase it. Otherwise the updater has not run yet.",
            file=sys.stderr,
        )
        return 21

    if committed != derived:
        print("\nCommitted sources.json does not match the signed chain:",
              file=sys.stderr)
        for key in sorted(set(committed) | set(derived)):
            if committed.get(key) != derived.get(key):
                print(f"  {key}:", file=sys.stderr)
                print(f"    committed: {json.dumps(committed.get(key))}",
                      file=sys.stderr)
                print(f"    derived  : {json.dumps(derived.get(key))}",
                      file=sys.stderr)
        return 21

    print("\ncommitted sources.json matches the independently derived metadata")

    if args.base_sources:
        # CI must apply the same policy the updater does, not merely check that
        # the committed file matches what the origin currently serves. A
        # downgrade, or a same-version republish under different digests, is
        # perfectly consistent with the live origin and still must not merge.
        print(f"\nApplying update policy against {args.base_sources}")
        try:
            with open(args.base_sources, encoding="utf-8") as fh:
                base = json.load(fh)
        except (OSError, ValueError) as exc:
            print(f"cannot read the base metadata: {exc}", file=sys.stderr)
            return 21
        try:
            U.guard_downgrade(base, committed)
            U.guard_same_version_drift(base, committed)
        except T.TrustError as exc:
            print(f"\nPOLICY FAILURE: {exc}", file=sys.stderr)
            return 20
        if base.get("version") == committed.get("version"):
            print(f"  unchanged at {committed.get('version')}")
        else:
            print(f"  {base.get('version')} -> {committed.get('version')}: "
                  f"a permitted upgrade with no digest drift")

    if args.strict:
        import tempfile
        print("\nVerifying package bodies against the signed index")
        try:
            with tempfile.TemporaryDirectory(prefix="chatgpt-verify-") as work:
                U.verify_debs(release, work)
        except T.TrustError as exc:
            print(f"\nTRUST FAILURE: {exc}", file=sys.stderr)
            return 20
        except U.NetworkError as exc:
            print(f"\nNETWORK FAILURE: {exc}", file=sys.stderr)
            return 30
        print("package bodies, debsigs signatures and control fields all verify")

    return 0


if __name__ == "__main__":
    sys.exit(main())
