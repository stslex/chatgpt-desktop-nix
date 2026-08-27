#!/usr/bin/env python3
"""Signed updater for stslex/chatgpt-desktop-nix.

Resolves the current upstream ChatGPT Desktop release through the full signed
APT trust chain and, only if every check passes, rewrites ``sources.json``.

This program touches exactly one file. It never edits packaging code, workflow
files, ELF allowlists, tests or ``flake.lock``.

Exit codes
----------
0   sources.json is already current, or was updated successfully
10  a newer verified version exists and ``--check`` was requested
20  trust/verification failure (fail closed; needs manual review)
30  network/availability failure after bounded retries
"""

from __future__ import annotations

import argparse
import contextlib
import hashlib
import json
import os
import ssl
import sys
import tempfile
import time
import urllib.error
import urllib.request

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import apt_trust as T  # noqa: E402

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SOURCES_PATH = os.path.join(REPO_ROOT, "sources.json")
KEYRING_PATH = os.path.join(
    REPO_ROOT, "trust", "openai-chatgpt-archive-keyring.gpg"
)

USER_AGENT = "chatgpt-desktop-nix-updater/1 (+https://github.com/stslex/chatgpt-desktop-nix)"

#: The origin's CDN intermittently aborts TLS handshakes. Retry transport
#: failures only. A verification failure is never retried.
MAX_ATTEMPTS = 6
BASE_BACKOFF = 2.0


class NetworkError(Exception):
    """Transport-level failure that survived the bounded retry budget."""


def fetch(url: str, *, max_bytes: int = T.MAX_DEB_BYTES) -> bytes:
    """Fetch a URL with bounded retries and exponential backoff.

    Retries cover transport faults only (TLS aborts, resets, 5xx, timeouts).
    Nothing here relaxes a signature, size or hash check on retry: the returned
    bytes always go back through the same verification.
    """
    last: Exception | None = None
    for attempt in range(1, MAX_ATTEMPTS + 1):
        try:
            request = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
            with urllib.request.urlopen(request, timeout=120) as response:
                if response.status != 200:
                    raise NetworkError(f"HTTP {response.status} for {url}")
                chunks: list[bytes] = []
                total = 0
                while True:
                    chunk = response.read(1024 * 1024)
                    if not chunk:
                        break
                    total += len(chunk)
                    if total > max_bytes:
                        raise NetworkError(f"{url}: response exceeds {max_bytes} bytes")
                    chunks.append(chunk)
                return b"".join(chunks)
        except (urllib.error.URLError, ssl.SSLError, TimeoutError, OSError,
                NetworkError) as exc:
            if isinstance(exc, urllib.error.HTTPError) and 400 <= exc.code < 500:
                raise NetworkError(f"HTTP {exc.code} for {url}") from exc
            last = exc
            if attempt < MAX_ATTEMPTS:
                delay = BASE_BACKOFF * (2 ** (attempt - 1))
                print(
                    f"  transient fetch failure ({exc}); retry {attempt}/"
                    f"{MAX_ATTEMPTS - 1} in {delay:.0f}s",
                    file=sys.stderr,
                )
                time.sleep(delay)
    raise NetworkError(f"{url}: failed after {MAX_ATTEMPTS} attempts: {last}")


def fetch_to_file(url: str, path: str, expected_size: int) -> None:
    """Stream a large artefact to disk with the same bounded retry policy."""
    last: Exception | None = None
    for attempt in range(1, MAX_ATTEMPTS + 1):
        try:
            request = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
            with urllib.request.urlopen(request, timeout=300) as response, \
                    open(path, "wb") as out:
                if response.status != 200:
                    raise NetworkError(f"HTTP {response.status} for {url}")
                total = 0
                while True:
                    chunk = response.read(4 * 1024 * 1024)
                    if not chunk:
                        break
                    total += len(chunk)
                    if total > expected_size:
                        raise NetworkError(
                            f"{url}: body longer than the signed size "
                            f"{expected_size}"
                        )
                    out.write(chunk)
            return
        except (urllib.error.URLError, ssl.SSLError, TimeoutError, OSError,
                NetworkError) as exc:
            if isinstance(exc, urllib.error.HTTPError) and 400 <= exc.code < 500:
                raise NetworkError(f"HTTP {exc.code} for {url}") from exc
            last = exc
            with contextlib.suppress(FileNotFoundError):
                os.unlink(path)
            if attempt < MAX_ATTEMPTS:
                delay = BASE_BACKOFF * (2 ** (attempt - 1))
                print(
                    f"  transient download failure ({exc}); retry {attempt}/"
                    f"{MAX_ATTEMPTS - 1} in {delay:.0f}s",
                    file=sys.stderr,
                )
                time.sleep(delay)
    raise NetworkError(f"{url}: failed after {MAX_ATTEMPTS} attempts: {last}")


def load_sources() -> dict:
    if not os.path.exists(SOURCES_PATH):
        return {}
    with open(SOURCES_PATH, encoding="utf-8") as fh:
        return json.load(fh)


def render_sources(release: T.VerifiedRelease) -> dict:
    """Build the deterministic source metadata document.

    Key order is fixed and the file is written with a trailing newline so
    repeated runs on an unchanged upstream produce a byte-identical file.
    """
    return {
        "_comment": (
            "Generated by tools/update.py after full signed-APT verification. "
            "Do not edit by hand."
        ),
        "origin": T.APT_ORIGIN,
        "suite": T.APT_SUITE,
        "component": T.APT_COMPONENT,
        "package": T.PACKAGE_NAME,
        "version": release.version,
        "signingKeyFingerprint": T.EXPECTED_KEY_FINGERPRINT,
        "architectures": {
            arch: {
                "debianArchitecture": rec.architecture,
                "filename": rec.filename,
                "url": rec.url,
                "size": rec.size,
                "sha256": rec.sha256,
                "hash": T.sha256_to_sri(rec.sha256),
            }
            for arch, rec in sorted(release.records.items())
        },
    }


def write_sources(document: dict) -> None:
    text = json.dumps(document, indent=2, ensure_ascii=False) + "\n"
    directory = os.path.dirname(SOURCES_PATH)
    with tempfile.NamedTemporaryFile(
        "w", encoding="utf-8", dir=directory, delete=False
    ) as tmp:
        tmp.write(text)
        staged = tmp.name
    os.replace(staged, SOURCES_PATH)


def guard_same_version_drift(previous: dict, candidate: dict) -> None:
    """Refuse a silent digest change for an already-known version.

    If upstream republishes the same version number with different bytes, that
    is either a rebuild we must notice or a compromise. Either way it is a
    manual-review breakpoint, never an automatic update.
    """
    if not previous or previous.get("version") != candidate["version"]:
        return
    for arch, new in candidate["architectures"].items():
        old = previous.get("architectures", {}).get(arch)
        if old is None:
            raise T.TrustError(
                f"version {candidate['version']} previously had no {arch} entry "
                "but now does — structural change, review manually"
            )
        for field in ("sha256", "size", "filename"):
            if old.get(field) != new.get(field):
                raise T.TrustError(
                    f"same-version digest drift for {candidate['version']} "
                    f"({arch}.{field}): committed {old.get(field)!r} vs upstream "
                    f"{new.get(field)!r} — refusing to overwrite a known version. "
                    "This requires manual engineering review."
                )


def guard_downgrade(previous: dict, candidate: dict) -> None:
    old_version = previous.get("version")
    if not old_version:
        return
    order = T.compare_debian_versions(candidate["version"], old_version)
    if order < 0:
        raise T.TrustError(
            f"upstream version {candidate['version']} is older than the pinned "
            f"{old_version} — refusing a downgrade (repository rollback?)"
        )


def verify_debs(release: T.VerifiedRelease, workdir: str) -> None:
    """Download each .deb and verify size, digest, debsigs and control fields."""
    for arch, record in sorted(release.records.items()):
        path = os.path.join(workdir, os.path.basename(record.filename))
        print(f"  downloading {arch}: {record.filename} ({record.size} bytes)")
        fetch_to_file(record.url, path, record.size)

        actual_size = os.path.getsize(path)
        if actual_size != record.size:
            raise T.TrustError(
                f"{arch}: downloaded size {actual_size} != signed {record.size}"
            )
        digest = hashlib.sha256()
        with open(path, "rb") as fh:
            for chunk in iter(lambda: fh.read(4 * 1024 * 1024), b""):
                digest.update(chunk)
        if digest.hexdigest() != record.sha256:
            raise T.TrustError(
                f"{arch}: SHA-256 mismatch — signed {record.sha256}, got "
                f"{digest.hexdigest()}"
            )
        print(f"    size + SHA-256 match the signed index")

        T.verify_deb_gpgorigin(path, KEYRING_PATH)
        print(f"    debsigs _gpgorigin verified against the pinned key")

        T.verify_deb_control(path, record)
        print(f"    control Package/Version/Architecture match the signed index")
        os.unlink(path)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--check", action="store_true",
        help="report whether an update exists without writing sources.json",
    )
    parser.add_argument(
        "--skip-deb-verification", action="store_true",
        help=argparse.SUPPRESS,  # used only by the fast no-op discovery path
    )
    parser.add_argument(
        "--github-output", action="store_true",
        help="emit key=value lines to $GITHUB_OUTPUT",
    )
    args = parser.parse_args()

    previous = load_sources()

    try:
        print(f"Verifying signed release metadata from {T.APT_ORIGIN}")
        print(f"  pinned key {T.EXPECTED_KEY_FINGERPRINT}")
        release = T.resolve_signed_release(
            lambda url: fetch(url, max_bytes=T.MAX_INDEX_BYTES),
            KEYRING_PATH,
        )
        print(f"  InRelease signature verified")
        print(f"  upstream version {release.version} "
              f"({', '.join(sorted(release.records))})")

        candidate = render_sources(release)
        guard_downgrade(previous, candidate)
        guard_same_version_drift(previous, candidate)

        current = previous == candidate
        if current:
            print(f"sources.json is already current at {release.version}")
            _emit_output(args, updated=False, version=release.version,
                         previous=previous.get("version", ""))
            return 0

        if args.check:
            print(f"update available: {previous.get('version', '(none)')} -> "
                  f"{release.version}")
            _emit_output(args, updated=True, version=release.version,
                         previous=previous.get("version", ""))
            return 10

        if not args.skip_deb_verification:
            print("Verifying package bodies")
            with tempfile.TemporaryDirectory(prefix="chatgpt-deb-") as workdir:
                verify_debs(release, workdir)

        write_sources(candidate)
        print(f"sources.json updated to {release.version}")
        _emit_output(args, updated=True, version=release.version,
                     previous=previous.get("version", ""))
        return 0

    except T.TrustError as exc:
        print(f"\nTRUST FAILURE: {exc}", file=sys.stderr)
        print(
            "\nThis is a fail-closed breakpoint. sources.json was not modified. "
            "Resolve this by manual engineering review; do not add a waiver.",
            file=sys.stderr,
        )
        _emit_output(args, updated=False, version="", previous=previous.get("version", ""),
                     failure="trust")
        return 20
    except NetworkError as exc:
        print(f"\nNETWORK FAILURE: {exc}", file=sys.stderr)
        _emit_output(args, updated=False, version="", previous=previous.get("version", ""),
                     failure="network")
        return 30


def _emit_output(args, *, updated: bool, version: str, previous: str,
                 failure: str = "") -> None:
    if not args.github_output:
        return
    target = os.environ.get("GITHUB_OUTPUT")
    if not target:
        return
    sanitized = version.replace("/", "-").replace(" ", "")
    with open(target, "a", encoding="utf-8") as fh:
        fh.write(f"updated={'true' if updated else 'false'}\n")
        fh.write(f"version={version}\n")
        fh.write(f"sanitized_version={sanitized}\n")
        fh.write(f"previous_version={previous}\n")
        fh.write(f"failure={failure}\n")


if __name__ == "__main__":
    sys.exit(main())
