"""Signed-APT trust chain for the official OpenAI ChatGPT Desktop repository.

This module implements the verification chain used both by the updater and by
CI's independent re-verification gate. It is deliberately import-safe and free
of side effects so the fixture tests can drive every branch.

The chain, in order, is:

    committed key -> InRelease -> Packages.gz -> .deb -> control fields

Every step fails closed. There is no path through this module that accepts
unverified data, and no flag that weakens a check.
"""

from __future__ import annotations

import dataclasses
import gzip
import hashlib
import os
import re
import shutil
import subprocess
import tempfile
import urllib.parse
from typing import Callable, Iterable, Mapping, Sequence

# --------------------------------------------------------------------------
# Constants that define the trust anchor and the origin. Changing any of these
# is a reviewed, human-only edit.
# --------------------------------------------------------------------------

APT_ORIGIN = "https://persistent.oaistatic.com/codex-app-prod/linux/deb"
APT_SUITE = "stable"
APT_COMPONENT = "main"
PACKAGE_NAME = "chatgpt"
SUPPORTED_ARCHITECTURES = ("amd64", "arm64")

#: Full 40-hex fingerprint of the OpenAI signing key. See trust/KEY-PROVENANCE.md.
EXPECTED_KEY_FINGERPRINT = "3BFA0E4AE8B8CC16A2D9BA684A3B4A566C4660E4"

#: SHA-256 of the committed binary keyring, asserted before use.
EXPECTED_KEYRING_SHA256 = (
    "23e2cfbdef6afe95505f9e95a2cb63585da7ffe9b06a51ec08a32407c847d596"
)

#: Upper bounds. These exist so a hostile or broken origin cannot make the
#: updater allocate unbounded memory. They are far above real values.
MAX_INDEX_BYTES = 8 * 1024 * 1024
MAX_DEB_BYTES = 4 * 1024 * 1024 * 1024


class TrustError(Exception):
    """Raised when any step of the trust chain fails.

    Every raise site is a fail-closed breakpoint. Callers must not catch this
    to continue with degraded verification.
    """


# --------------------------------------------------------------------------
# Debian version comparison (dpkg semantics, never lexical)
# --------------------------------------------------------------------------


def _order(char: str) -> int:
    """Debian's character collation for the non-digit runs of a version."""
    if char.isdigit():
        return 0
    if char.isalpha():
        return ord(char)
    if char == "~":
        return -1
    return ord(char) + 256


def _compare_fragment(a: str, b: str) -> int:
    ia = ib = 0
    while ia < len(a) or ib < len(b):
        first_diff = 0
        # Compare the non-digit prefix using Debian collation.
        while (ia < len(a) and not a[ia].isdigit()) or (
            ib < len(b) and not b[ib].isdigit()
        ):
            ca = _order(a[ia]) if ia < len(a) else 0
            cb = _order(b[ib]) if ib < len(b) else 0
            if ca != cb:
                return -1 if ca < cb else 1
            ia += 1
            ib += 1
        # Skip leading zeros, then compare the digit run numerically.
        while ia < len(a) and a[ia] == "0":
            ia += 1
        while ib < len(b) and b[ib] == "0":
            ib += 1
        while ia < len(a) and a[ia].isdigit() and ib < len(b) and b[ib].isdigit():
            if first_diff == 0:
                first_diff = (ord(a[ia]) > ord(b[ib])) - (ord(a[ia]) < ord(b[ib]))
            ia += 1
            ib += 1
        if ia < len(a) and a[ia].isdigit():
            return 1
        if ib < len(b) and b[ib].isdigit():
            return -1
        if first_diff:
            return first_diff
    return 0


def compare_debian_versions(a: str, b: str) -> int:
    """Return -1/0/1 comparing two Debian versions using dpkg ordering.

    Never compare Debian versions lexically: ``26.820.9`` sorts *after*
    ``26.820.71523`` as a string but *before* it as a version.
    """

    def split(v: str) -> tuple[int, str, str]:
        epoch = 0
        if ":" in v:
            head, _, rest = v.partition(":")
            if not head.isdigit():
                raise TrustError(f"malformed epoch in Debian version {v!r}")
            epoch, v = int(head), rest
        if "-" in v:
            upstream, _, revision = v.rpartition("-")
        else:
            upstream, revision = v, ""
        return epoch, upstream, revision

    ea, ua, ra = split(a)
    eb, ub, rb = split(b)
    if ea != eb:
        return -1 if ea < eb else 1
    result = _compare_fragment(ua, ub)
    if result:
        return result
    return _compare_fragment(ra, rb)


VERSION_RE = re.compile(r"^[0-9][A-Za-z0-9.+~:-]*$")


def validate_version(version: str) -> str:
    if not VERSION_RE.match(version) or len(version) > 128:
        raise TrustError(f"refusing implausible upstream version {version!r}")
    return version


# --------------------------------------------------------------------------
# RFC822-ish control-file parsing
# --------------------------------------------------------------------------


def parse_control_paragraph(text: str) -> dict[str, str]:
    """Parse one Debian control paragraph into a field mapping.

    Continuation lines (leading space/tab) are folded into the previous field.
    """
    fields: dict[str, str] = {}
    current: str | None = None
    for raw in text.splitlines():
        if not raw.strip():
            continue
        if raw[0] in " \t":
            if current is None:
                raise TrustError("continuation line before any field")
            fields[current] += "\n" + raw.strip()
            continue
        name, sep, value = raw.partition(":")
        if not sep:
            raise TrustError(f"malformed control line: {raw!r}")
        current = name.strip()
        if current in fields:
            raise TrustError(f"duplicate control field {current!r}")
        fields[current] = value.strip()
    return fields


def split_paragraphs(text: str) -> list[str]:
    return [p for p in re.split(r"\n[ \t]*\n", text) if p.strip()]


# --------------------------------------------------------------------------
# Signature verification
# --------------------------------------------------------------------------


def assert_keyring_identity(keyring_path: str) -> None:
    """Assert the committed keyring is exactly the reviewed bytes and key."""
    data = _read_file(keyring_path)
    digest = hashlib.sha256(data).hexdigest()
    if digest != EXPECTED_KEYRING_SHA256:
        raise TrustError(
            "committed keyring bytes changed: expected SHA-256 "
            f"{EXPECTED_KEYRING_SHA256}, got {digest}. Signing-key rotation is a "
            "manual-review event; the updater must never accept a new key."
        )
    fingerprints = keyring_fingerprints(keyring_path)
    if fingerprints != [EXPECTED_KEY_FINGERPRINT]:
        raise TrustError(
            f"committed keyring must contain exactly the pinned key "
            f"{EXPECTED_KEY_FINGERPRINT}, found {fingerprints}"
        )


def keyring_fingerprints(keyring_path: str) -> list[str]:
    """Return the primary-key fingerprints inside a binary keyring."""
    gpg = shutil.which("gpg")
    if gpg is None:
        raise TrustError("gpg is required to inspect the keyring")
    with tempfile.TemporaryDirectory() as home:
        os.chmod(home, 0o700)
        proc = subprocess.run(
            [gpg, "--homedir", home, "--batch", "--with-colons",
             "--show-keys", "--with-fingerprint", keyring_path],
            capture_output=True, text=True, check=False,
        )
    if proc.returncode != 0:
        raise TrustError(f"could not read keyring {keyring_path}: {proc.stderr}")
    out: list[str] = []
    primary = False
    for line in proc.stdout.splitlines():
        parts = line.split(":")
        if parts[0] == "pub":
            primary = True
        elif parts[0] == "fpr" and primary:
            out.append(parts[9])
            primary = False
    return out


def verify_inrelease(inrelease_bytes: bytes, keyring_path: str) -> str:
    """Verify a clearsigned InRelease and return its verified payload.

    The returned text is the payload *as extracted by gpgv itself*, never the
    result of stripping the armor by hand. Anything outside the signed region
    is discarded.
    """
    assert_keyring_identity(keyring_path)
    gpgv = shutil.which("gpgv")
    if gpgv is None:
        raise TrustError("gpgv is required for signature verification")

    with tempfile.TemporaryDirectory() as tmp:
        signed = os.path.join(tmp, "InRelease")
        payload = os.path.join(tmp, "Release.payload")
        with open(signed, "wb") as fh:
            fh.write(inrelease_bytes)
        proc = subprocess.run(
            [gpgv, "--keyring", keyring_path, "--status-fd", "1",
             "--output", payload, signed],
            capture_output=True, text=True, check=False,
        )
        status = proc.stdout
        if proc.returncode != 0:
            raise TrustError(
                "InRelease signature verification failed against the pinned "
                f"key:\n{proc.stderr.strip()}"
            )
        # gpgv exit 0 is necessary but we still assert the explicit status
        # tokens, so a future gpgv cannot report success for a key we did not
        # pin.
        if "[GNUPG:] GOODSIG" not in status and "[GNUPG:] VALIDSIG" not in status:
            raise TrustError(f"gpgv reported no good signature:\n{status}")
        signer = None
        for line in status.splitlines():
            if line.startswith("[GNUPG:] VALIDSIG"):
                signer = line.split()[2]
        if signer is None:
            raise TrustError("gpgv did not report a VALIDSIG fingerprint")
        if signer.upper() != EXPECTED_KEY_FINGERPRINT:
            raise TrustError(
                f"InRelease signed by unexpected key {signer}, "
                f"expected {EXPECTED_KEY_FINGERPRINT}"
            )
        return _read_file(payload).decode("utf-8")


def check_valid_until(release_text: str, now: "int | None" = None) -> None:
    """Reject stale metadata when the origin publishes ``Valid-Until``.

    The current OpenAI origin does not emit this field. When it is absent there
    is nothing to enforce; when it appears, it becomes binding immediately.
    """
    fields = parse_control_paragraph(release_text.split("\nMD5Sum:")[0])
    raw = fields.get("Valid-Until")
    if not raw:
        return
    import email.utils
    parsed = email.utils.parsedate_to_datetime(raw)
    if parsed is None:
        raise TrustError(f"unparsable Valid-Until: {raw!r}")
    expiry = int(parsed.timestamp())
    current = int(now if now is not None else _now())
    if current > expiry:
        raise TrustError(
            f"signed repository metadata expired at {raw} — refusing to use it"
        )


def _now() -> float:
    import time
    return time.time()


# --------------------------------------------------------------------------
# Release index parsing
# --------------------------------------------------------------------------


@dataclasses.dataclass(frozen=True)
class IndexEntry:
    sha256: str
    size: int
    path: str


def parse_release_sha256(release_text: str) -> dict[str, IndexEntry]:
    """Extract the SHA-256 section of a Release/InRelease payload.

    Only SHA-256 is honoured. MD5Sum and SHA1 are present upstream but are not
    used for any decision here.
    """
    lines = release_text.splitlines()
    entries: dict[str, IndexEntry] = {}
    in_section = False
    for line in lines:
        if not line.startswith((" ", "\t")):
            in_section = line.strip() == "SHA256:"
            continue
        if not in_section:
            continue
        parts = line.split()
        if len(parts) != 3:
            raise TrustError(f"malformed SHA256 index line: {line!r}")
        digest, size, path = parts
        if not re.fullmatch(r"[0-9a-f]{64}", digest):
            raise TrustError(f"malformed SHA-256 digest for {path}")
        if not size.isdigit():
            raise TrustError(f"malformed size for {path}")
        if path in entries:
            raise TrustError(f"duplicate SHA256 entry for {path}")
        entries[path] = IndexEntry(digest, int(size), path)
    if not entries:
        raise TrustError("signed Release contains no SHA256 section")
    return entries


def verify_blob(data: bytes, expected: IndexEntry, what: str) -> None:
    if len(data) != expected.size:
        raise TrustError(
            f"{what}: size mismatch — signed metadata says {expected.size} "
            f"bytes, got {len(data)}"
        )
    digest = hashlib.sha256(data).hexdigest()
    if digest != expected.sha256:
        raise TrustError(
            f"{what}: SHA-256 mismatch — signed metadata says "
            f"{expected.sha256}, got {digest}"
        )


# --------------------------------------------------------------------------
# Packages stanza handling
# --------------------------------------------------------------------------


@dataclasses.dataclass(frozen=True)
class PackageRecord:
    package: str
    version: str
    architecture: str
    filename: str
    size: int
    sha256: str

    @property
    def url(self) -> str:
        return f"{APT_ORIGIN}/{self.filename}"


def sanitize_filename(filename: str) -> str:
    """Constrain a ``Filename:`` field to a safe relative pool path.

    Rejects absolute URLs, scheme prefixes, absolute paths, traversal, empty
    components, backslashes and anything that could escape the origin.
    """
    if not filename:
        raise TrustError("empty Filename field")
    if len(filename) > 512:
        raise TrustError("implausibly long Filename field")
    if "\\" in filename:
        raise TrustError(f"backslash in Filename: {filename!r}")
    if "://" in filename or urllib.parse.urlparse(filename).scheme:
        raise TrustError(f"Filename must be origin-relative, got URL: {filename!r}")
    if filename.startswith("/"):
        raise TrustError(f"Filename must be relative, got absolute: {filename!r}")
    if filename.startswith("//"):
        raise TrustError(f"protocol-relative Filename rejected: {filename!r}")
    parts = filename.split("/")
    for part in parts:
        if part in ("", ".", ".."):
            raise TrustError(f"unsafe path component in Filename: {filename!r}")
        if part.startswith("%2e") or part.startswith("%2E"):
            raise TrustError(f"encoded traversal in Filename: {filename!r}")
    if not filename.startswith("pool/"):
        raise TrustError(
            f"Filename must live under the pool/ prefix, got {filename!r}"
        )
    # Belt and braces: the joined URL must still be inside the origin.
    joined = urllib.parse.urljoin(APT_ORIGIN + "/", filename)
    if not joined.startswith(APT_ORIGIN + "/"):
        raise TrustError(f"Filename escapes the origin: {filename!r}")
    return filename


def parse_packages(packages_text: str, architecture: str) -> PackageRecord:
    """Return the single ``chatgpt`` stanza for ``architecture``.

    Exactly one matching stanza must exist. Zero is an error; more than one is
    an error (an origin offering two records for one architecture is
    structurally unexpected and must go to manual review).
    """
    matches: list[PackageRecord] = []
    for paragraph in split_paragraphs(packages_text):
        fields = parse_control_paragraph(paragraph)
        if fields.get("Package") != PACKAGE_NAME:
            continue
        if fields.get("Architecture") != architecture:
            continue
        for required in ("Version", "Filename", "Size", "SHA256"):
            if required not in fields:
                raise TrustError(
                    f"{architecture}: stanza missing required field {required}"
                )
        size = fields["Size"]
        if not size.isdigit():
            raise TrustError(f"{architecture}: malformed Size {size!r}")
        digest = fields["SHA256"].lower()
        if not re.fullmatch(r"[0-9a-f]{64}", digest):
            raise TrustError(f"{architecture}: malformed SHA256 {digest!r}")
        if int(size) > MAX_DEB_BYTES:
            raise TrustError(f"{architecture}: refusing implausible Size {size}")
        matches.append(
            PackageRecord(
                package=PACKAGE_NAME,
                version=validate_version(fields["Version"]),
                architecture=architecture,
                filename=sanitize_filename(fields["Filename"]),
                size=int(size),
                sha256=digest,
            )
        )
    if not matches:
        raise TrustError(
            f"no Package: {PACKAGE_NAME} stanza for architecture {architecture}"
        )
    if len(matches) > 1:
        raise TrustError(
            f"expected exactly one {PACKAGE_NAME} stanza for {architecture}, "
            f"found {len(matches)} — structural repository change, review manually"
        )
    return matches[0]


def require_architecture_agreement(records: Mapping[str, PackageRecord]) -> str:
    """All supported architectures must publish the same upstream version."""
    versions = {arch: rec.version for arch, rec in records.items()}
    distinct = set(versions.values())
    if len(distinct) != 1:
        raise TrustError(
            "architecture version skew: " +
            ", ".join(f"{a}={v}" for a, v in sorted(versions.items())) +
            " — refusing to publish a partial release"
        )
    return distinct.pop()


# --------------------------------------------------------------------------
# .deb control extraction
# --------------------------------------------------------------------------


def read_deb_control(deb_path: str) -> dict[str, str]:
    """Extract the control paragraph from a .deb without maintainer scripts.

    This reads ``control.tar.*`` out of the ``ar`` archive directly. It never
    runs ``dpkg``, never unpacks ``data.tar.*``, and never executes anything
    from the package.
    """
    members = _ar_members(deb_path)
    if "debian-binary" not in members:
        raise TrustError(f"{deb_path}: not a Debian archive (no debian-binary)")
    control_name = next(
        (n for n in members if n.startswith("control.tar")), None
    )
    if control_name is None:
        raise TrustError(f"{deb_path}: no control.tar member")
    blob = members[control_name]
    raw = _decompress(control_name, blob)
    import io
    import tarfile
    with tarfile.open(fileobj=io.BytesIO(raw), mode="r:") as tar:
        for member in tar.getmembers():
            if member.name.lstrip("./") == "control":
                fh = tar.extractfile(member)
                if fh is None:
                    raise TrustError(f"{deb_path}: unreadable control file")
                return parse_control_paragraph(fh.read().decode("utf-8"))
    raise TrustError(f"{deb_path}: control.tar has no control file")


def deb_gpgorigin(deb_path: str) -> "bytes | None":
    """Return the debsigs ``_gpgorigin`` signature member, if present."""
    return _ar_members(deb_path).get("_gpgorigin")


def verify_deb_gpgorigin(deb_path: str, keyring_path: str) -> None:
    """Verify the debsigs signature over debian-binary||control||data.

    This is defence in depth. It is signed by the same key as ``InRelease``, so
    it is not an independent trust anchor and never substitutes for the
    committed key -> InRelease -> Packages.gz -> .deb chain. It is mandatory
    because it is consistently present on every supported architecture.
    """
    assert_keyring_identity(keyring_path)
    members = _ar_members(deb_path, ordered=True)
    signature = dict(members).get("_gpgorigin")
    if signature is None:
        raise TrustError(
            f"{deb_path}: expected a debsigs _gpgorigin member and found none"
        )
    gpgv = shutil.which("gpgv")
    if gpgv is None:
        raise TrustError("gpgv is required for debsigs verification")
    with tempfile.TemporaryDirectory() as tmp:
        sig_path = os.path.join(tmp, "_gpgorigin")
        payload_path = os.path.join(tmp, "payload")
        with open(sig_path, "wb") as fh:
            fh.write(signature)
        with open(payload_path, "wb") as fh:
            for name, blob in members:
                if name == "_gpgorigin":
                    continue
                fh.write(blob)
        proc = subprocess.run(
            [gpgv, "--keyring", keyring_path, "--status-fd", "1",
             sig_path, payload_path],
            capture_output=True, text=True, check=False,
        )
        if proc.returncode != 0:
            raise TrustError(
                f"{os.path.basename(deb_path)}: debsigs _gpgorigin signature "
                f"failed against the pinned key:\n{proc.stderr.strip()}"
            )
        signer = None
        for line in proc.stdout.splitlines():
            if line.startswith("[GNUPG:] VALIDSIG"):
                signer = line.split()[2]
        if signer is None or signer.upper() != EXPECTED_KEY_FINGERPRINT:
            raise TrustError(
                f"{os.path.basename(deb_path)}: debsigs signed by unexpected "
                f"key {signer}"
            )


def verify_deb_control(
    deb_path: str, record: PackageRecord
) -> None:
    """Assert the package's own control fields match the signed index."""
    control = read_deb_control(deb_path)
    if control.get("Package") != PACKAGE_NAME:
        raise TrustError(
            f"{deb_path}: control Package is {control.get('Package')!r}, "
            f"expected {PACKAGE_NAME!r}"
        )
    if control.get("Version") != record.version:
        raise TrustError(
            f"{deb_path}: control Version {control.get('Version')!r} does not "
            f"match signed index version {record.version!r}"
        )
    if control.get("Architecture") != record.architecture:
        raise TrustError(
            f"{deb_path}: control Architecture {control.get('Architecture')!r} "
            f"does not match signed index architecture {record.architecture!r}"
        )


def _ar_members(path: str, ordered: bool = False):
    """Minimal `ar` reader returning member name -> bytes (or an ordered list).

    Implemented locally so the trust chain does not depend on `binutils` or
    `dpkg` being present, and so CI can run it on a bare Python.
    """
    out: list[tuple[str, bytes]] = []
    with open(path, "rb") as fh:
        if fh.read(8) != b"!<arch>\n":
            raise TrustError(f"{path}: not an ar archive")
        long_names = b""
        while True:
            header = fh.read(60)
            if len(header) == 0:
                break
            if len(header) < 60:
                raise TrustError(f"{path}: truncated ar header")
            name = header[0:16].decode("ascii", "replace").rstrip()
            size_field = header[48:58].decode("ascii", "replace").strip()
            if not size_field.isdigit():
                raise TrustError(f"{path}: malformed ar member size")
            size = int(size_field)
            data = fh.read(size)
            if len(data) != size:
                raise TrustError(f"{path}: truncated ar member {name!r}")
            if size % 2:
                fh.read(1)
            if name == "//":
                long_names = data
                continue
            if name.startswith("/") and name[1:].isdigit() and long_names:
                offset = int(name[1:])
                end = long_names.find(b"/\n", offset)
                if end == -1:
                    end = long_names.find(b"\n", offset)
                name = long_names[offset:end].decode("ascii", "replace")
            name = name.rstrip("/")
            out.append((name, data))
    if ordered:
        return out
    return dict(out)


def _decompress(name: str, blob: bytes) -> bytes:
    if name.endswith(".gz"):
        return gzip.decompress(blob)
    if name.endswith(".xz"):
        import lzma
        return lzma.decompress(blob)
    if name.endswith(".zst"):
        try:
            import zstandard  # type: ignore
        except ImportError as exc:  # pragma: no cover - environment dependent
            raise TrustError("zstd control member requires the zstandard module") from exc
        return zstandard.ZstdDecompressor().stream_reader(blob).read()
    if name.endswith(".tar"):
        return blob
    raise TrustError(f"unsupported control member compression: {name}")


def _read_file(path: str) -> bytes:
    with open(path, "rb") as fh:
        return fh.read()


# --------------------------------------------------------------------------
# SRI conversion
# --------------------------------------------------------------------------


def sha256_to_sri(hex_digest: str) -> str:
    """Convert a lowercase hex SHA-256 into Nix SRI form."""
    import base64
    if not re.fullmatch(r"[0-9a-f]{64}", hex_digest):
        raise TrustError(f"not a hex SHA-256 digest: {hex_digest!r}")
    raw = bytes.fromhex(hex_digest)
    return "sha256-" + base64.b64encode(raw).decode("ascii")


# --------------------------------------------------------------------------
# Full chain
# --------------------------------------------------------------------------


Fetcher = Callable[[str], bytes]


@dataclasses.dataclass(frozen=True)
class VerifiedRelease:
    version: str
    records: dict[str, PackageRecord]


def resolve_signed_release(
    fetch: Fetcher,
    keyring_path: str,
    architectures: Sequence[str] = SUPPORTED_ARCHITECTURES,
    now: "int | None" = None,
) -> VerifiedRelease:
    """Run the signed chain and return the verified per-architecture records.

    ``fetch`` maps an absolute URL to bytes. Injecting it keeps this function
    pure enough to drive from fixtures with no network.

    This deliberately stops before downloading the ``.deb`` bodies; the caller
    decides whether it needs them (the updater does, to verify control fields).
    """
    inrelease = fetch(f"{APT_ORIGIN}/dists/{APT_SUITE}/InRelease")
    if len(inrelease) > MAX_INDEX_BYTES:
        raise TrustError("InRelease is implausibly large")
    release_text = verify_inrelease(inrelease, keyring_path)
    check_valid_until(release_text, now=now)
    index = parse_release_sha256(release_text)

    records: dict[str, PackageRecord] = {}
    for arch in architectures:
        rel = f"{APT_COMPONENT}/binary-{arch}/Packages.gz"
        entry = index.get(rel)
        if entry is None:
            raise TrustError(f"signed Release does not list {rel}")
        if entry.size > MAX_INDEX_BYTES:
            raise TrustError(f"{rel} is implausibly large")
        blob = fetch(f"{APT_ORIGIN}/dists/{APT_SUITE}/{rel}")
        verify_blob(blob, entry, rel)
        text = gzip.decompress(blob).decode("utf-8")
        records[arch] = parse_packages(text, arch)

    version = require_architecture_agreement(records)
    return VerifiedRelease(version=version, records=records)
