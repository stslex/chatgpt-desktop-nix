#!/usr/bin/env python3
"""Verify the pinned ChatGPT packages independently of the latest APT release.

The APT index only describes the current release. CI must continue to verify a
pin after that index moves on, so it checks each pinned .deb's OpenAI signature,
size, SHA-256 and signed control fields. A matching hash alone is not proof of
authenticity: the debsigs signature must verify against the committed key too.

Discovering new versions through the fresh signed APT index belongs to
``update.py``. This command never requires the pinned version to be the latest.

Exit codes
----------
0   both pinned packages and their signatures verify
20  trust/verification failure
21  source metadata could not be read
30  network failure after bounded retries
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import apt_trust as T  # noqa: E402
import update as U  # noqa: E402


def release_from_sources(document: dict) -> T.VerifiedRelease:
    """Validate the manifest before using any of its fields for a download.

    URLs and trust anchors are derived from our constants, never accepted from
    the manifest. This establishes shape and consistency only; the caller must
    still verify both package bodies and their signatures.
    """
    if not isinstance(document, dict):
        raise T.TrustError("sources.json must be an object")
    version = document.get("version")
    if not isinstance(version, str):
        raise T.TrustError("sources.json must contain a version string")
    T.validate_version(version)

    architectures = document.get("architectures")
    if not isinstance(architectures, dict) or set(architectures) != set(
        T.SUPPORTED_ARCHITECTURES
    ):
        raise T.TrustError("sources.json must contain exactly amd64 and arm64")

    records = {}
    for arch, entry in architectures.items():
        if not isinstance(entry, dict):
            raise T.TrustError(f"{arch}: source entry must be an object")
        filename = entry.get("filename")
        if not isinstance(filename, str):
            raise T.TrustError(f"{arch}: Filename must be a string")
        T.sanitize_filename(filename)
        size = entry.get("size")
        if type(size) is not int or not 0 < size <= T.MAX_DEB_BYTES:
            raise T.TrustError(f"{arch}: invalid package size {size!r}")
        digest = entry.get("sha256")
        if not isinstance(digest, str) or not re.fullmatch(r"[0-9a-f]{64}", digest):
            raise T.TrustError(f"{arch}: invalid SHA-256 digest")
        records[arch] = T.PackageRecord(
            package=T.PACKAGE_NAME, version=version, architecture=arch,
            filename=filename, size=size, sha256=digest,
        )

    release = T.VerifiedRelease(version=version, records=records)
    expected = U.render_sources(release)
    if document != expected:
        changed = sorted(k for k in set(document) | set(expected)
                         if document.get(k) != expected.get(k))
        raise T.TrustError(
            "sources.json differs from the canonical metadata in: "
            + ", ".join(changed)
        )
    return release


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--strict", action="store_true",
        help="compatibility option; both package bodies are always verified",
    )
    parser.add_argument(
        "--base-sources",
        help="the protected branch's sources.json; when given, the committed "
             "metadata is additionally held to the no-downgrade and "
             "no-same-version-drift rules against it",
    )
    args = parser.parse_args(argv)

    try:
        committed = U.load_sources()
        base = None
        if args.base_sources:
            with open(args.base_sources, encoding="utf-8") as fh:
                base = json.load(fh)
    except (OSError, ValueError) as exc:
        print(f"cannot read source metadata: {exc}", file=sys.stderr)
        return 21
    if not committed:
        print("sources.json is missing", file=sys.stderr)
        return 21

    try:
        release = release_from_sources(committed)
        print(f"Verifying pinned ChatGPT {release.version} from {T.APT_ORIGIN}")
        print(f"  trust anchor: {T.EXPECTED_KEY_FINGERPRINT}")

        T.assert_keyring_identity(U.KEYRING_PATH)
        print("  committed keyring matches the reviewed bytes and fingerprint")

        if args.base_sources:
            release_from_sources(base)
            print(f"Applying update policy against {args.base_sources}")
            U.guard_downgrade(base, committed)
            U.guard_same_version_drift(base, committed)
            print(f"  {base['version']} -> {release.version}: policy checks passed")

        print("Verifying both package bodies and their OpenAI signatures")
        with tempfile.TemporaryDirectory(prefix="chatgpt-verify-") as work:
            U.verify_debs(release, work)

    except T.TrustError as exc:
        print(f"\nTRUST FAILURE: {exc}", file=sys.stderr)
        return 20
    except U.NetworkError as exc:
        print(f"\nNETWORK FAILURE: {exc}", file=sys.stderr)
        return 30

    print("\nPinned package hashes, signatures and control fields all verify")
    return 0


if __name__ == "__main__":
    sys.exit(main())
