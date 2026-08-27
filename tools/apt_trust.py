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

#: How stale signed metadata may be before it is refused. A valid signature
#: does not establish freshness, so without a bound a CDN could replay a
#: genuine old snapshot indefinitely. The origin publishes far more often than
#: this, so the limit is generous while still making a freeze conspicuous.
MAX_METADATA_AGE = 30 * 86400

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


#: Characters that are safe in a Git ref component and need no encoding.
#: Everything VERSION_RE admits but this does not is percent-encoded.
_REF_SAFE = frozenset(
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789._")


def encode_version_for_ref(version: str) -> str:
    """Encode a Debian version into a Git-ref-safe, *injective* component.

    Replacing unsafe characters with '-' loses information, and Debian versions
    differ in exactly those characters: `1.0~rc1`, `1.0-rc1`, `1.0+rc1` and
    `1.0:rc1` all collapse to the same string. Two different upstream versions
    would then share one automation branch, and the second would be compared
    against -- and force-pushed over -- the first one's record.

    Percent-encoding is reversible, so distinct versions always give distinct
    refs. '%' itself is encoded first, so the mapping stays one-to-one.

    Git also forbids a component that begins or ends with '.', contains '..',
    or ends '.lock'; VERSION_RE already requires a leading digit, and '.' is
    the only one of those characters left unencoded, so only the '..' and
    '.lock' cases need handling.
    """
    validate_version(version)
    out = []
    for char in version:
        if char in _REF_SAFE:
            out.append(char)
        else:
            out.append(f"%{ord(char):02X}")
    encoded = "".join(out)

    # '..' is not a legal ref component. Encode the second dot so the result
    # stays distinct from a single dot.
    while ".." in encoded:
        encoded = encoded.replace("..", ".%2E", 1)
    if encoded.endswith(".lock"):
        encoded = encoded[:-5] + "%2Elock"
    return encoded


def decode_version_from_ref(encoded: str) -> str:
    """Inverse of :func:`encode_version_for_ref`."""
    import urllib.parse
    return urllib.parse.unquote(encoded)


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


def _parse_rfc822_date(raw: str, field: str) -> int:
    import email.utils
    parsed = email.utils.parsedate_to_datetime(raw)
    if parsed is None:
        raise TrustError(f"unparsable {field}: {raw!r}")
    return int(parsed.timestamp())


def release_date(release_text: str) -> "int | None":
    """The signed ``Date`` of a Release payload, as a Unix timestamp."""
    fields = parse_control_paragraph(release_text.split("\nMD5Sum:")[0])
    raw = fields.get("Date")
    return _parse_rfc822_date(raw, "Date") if raw else None


def check_freshness(release_text: str, now: "int | None" = None) -> None:
    """Reject metadata that is stale, however well it is signed.

    A valid signature says the bytes came from OpenAI. It says nothing about
    *when*. Someone who controls the CDN but not the private key can keep
    replaying a genuine older snapshot forever: every hash matches, the
    signature verifies, and the updater simply concludes it is already current
    and exits successfully. The client would sit on a superseded release and
    never notice.

    APT's usual defence is ``Valid-Until``, but this origin does not publish
    it. It does publish a signed ``Date``, which is enough: it is inside the
    signed region, so replaying an old snapshot necessarily replays an old
    ``Date`` too.
    """
    fields = parse_control_paragraph(release_text.split("\nMD5Sum:")[0])
    current = int(now if now is not None else _now())

    raw_until = fields.get("Valid-Until")
    if raw_until:
        expiry = _parse_rfc822_date(raw_until, "Valid-Until")
        if current > expiry:
            raise TrustError(
                f"signed repository metadata expired at {raw_until} — "
                f"refusing to use it"
            )

    raw_date = fields.get("Date")
    if not raw_date:
        raise TrustError(
            "signed Release has neither Valid-Until nor Date, so its age "
            "cannot be established. Refusing rather than accepting metadata "
            "that could be an arbitrarily old replay."
        )

    published = _parse_rfc822_date(raw_date, "Date")
    age = current - published

    if age > MAX_METADATA_AGE:
        raise TrustError(
            f"signed repository metadata is {age // 86400} days old (published "
            f"{raw_date}), beyond the {MAX_METADATA_AGE // 86400}-day limit.\n"
            f"Either upstream has genuinely stopped publishing, or something "
            f"between here and the origin is replaying an old snapshot. Both "
            f"need a human to look; neither is something to wave through."
        )

    # A little tolerance for clock skew between us and the publisher.
    if age < -86400:
        raise TrustError(
            f"signed repository metadata is dated {raw_date}, which is in the "
            f"future — refusing to trust it"
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


def check_distribution_identity(release_text: str,
                                architectures: Sequence[str]) -> None:
    """Assert the signed Release describes the distribution we asked for.

    The signature proves OpenAI published these bytes. It does not prove they
    are the bytes for `stable`/`main` — a signed index for some other suite
    would verify just as well. Where the origin states its identity, hold it to
    it.
    """
    fields = parse_control_paragraph(release_text.split("\nMD5Sum:")[0])

    for field, expected in (("Suite", APT_SUITE), ("Codename", APT_SUITE)):
        actual = fields.get(field)
        if actual is not None and actual != expected:
            raise TrustError(
                f"signed Release declares {field}: {actual!r}, expected "
                f"{expected!r}. This index is not for the distribution this "
                f"package tracks."
            )

    components = fields.get("Components")
    if components is not None and APT_COMPONENT not in components.split():
        raise TrustError(
            f"signed Release declares Components: {components!r}, which does "
            f"not include {APT_COMPONENT!r}"
        )

    declared = fields.get("Architectures")
    if declared is not None:
        listed = set(declared.split())
        missing = sorted(set(architectures) - listed)
        if missing:
            raise TrustError(
                f"signed Release declares Architectures: {declared!r}, which "
                f"omits {missing}"
            )


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
    # Reject control characters and anything non-ASCII explicitly, rather than
    # relying on some later layer to happen to raise on them.
    for char in filename:
        if ord(char) < 0x20 or ord(char) == 0x7F or ord(char) > 0x7E:
            raise TrustError(
                f"Filename contains a control or non-ASCII character "
                f"(U+{ord(char):04X}): {filename!r}"
            )
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
    control_names = [n for n in members if n.startswith("control.tar")]
    if not control_names:
        raise TrustError(f"{deb_path}: no control.tar member")
    if len(control_names) > 1:
        raise TrustError(
            f"{deb_path}: {len(control_names)} control.tar members "
            f"({control_names}); exactly one is expected")
    control_name = control_names[0]
    raw = _decompress(control_name, members[control_name])

    import io
    import tarfile
    try:
        with tarfile.open(fileobj=io.BytesIO(raw), mode="r:") as tar:
            found = None
            for member in tar.getmembers():
                # Check the name as it actually appears, BEFORE any
                # normalisation. `"../control".lstrip("./")` is `"control"` --
                # lstrip removes a character *set*, not a prefix, so
                # normalising first erases the very component being looked for.
                raw = member.name
                if raw.startswith("/") or ".." in raw.split("/"):
                    raise TrustError(
                        f"{deb_path}: control.tar member {raw!r} has a "
                        f"traversal-shaped name")
                # Only then strip a leading "./", one prefix at a time.
                normalised = raw
                while normalised.startswith("./"):
                    normalised = normalised[2:]
                if normalised != "control":
                    continue
                if not member.isfile():
                    raise TrustError(
                        f"{deb_path}: control.tar entry 'control' is not a "
                        f"regular file (type {member.type!r})")
                if found is not None:
                    raise TrustError(
                        f"{deb_path}: control.tar has more than one 'control'")
                found = member
            if found is None:
                raise TrustError(f"{deb_path}: control.tar has no control file")
            fh = tar.extractfile(found)
            if fh is None:
                raise TrustError(f"{deb_path}: unreadable control file")
            return parse_control_paragraph(fh.read().decode("utf-8"))
    except TrustError:
        raise
    except tarfile.TarError as exc:
        raise TrustError(f"{deb_path}: malformed control.tar ({exc})") from exc
    except UnicodeDecodeError as exc:
        raise TrustError(
            f"{deb_path}: control file is not valid UTF-8 ({exc})") from exc


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
    signatures = [blob for name, blob in members if name == "_gpgorigin"]
    if not signatures:
        raise TrustError(
            f"{deb_path}: expected a debsigs _gpgorigin member and found none"
        )
    if len(signatures) > 1:
        # Selecting one signature while excluding all of them from the signed
        # payload would verify a different byte sequence than the archive
        # actually contains.
        raise TrustError(
            f"{deb_path}: {len(signatures)} _gpgorigin members; a Debian "
            f"archive has exactly one. Refusing to guess which is authoritative."
        )
    signature = signatures[0]
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
            if header[58:60] != b"`\n":
                raise TrustError(
                    f"{path}: ar header is missing its magic terminator")
            name = header[0:16].decode("ascii", "replace").rstrip()
            size_field = header[48:58].decode("ascii", "replace").strip()
            if not size_field.isdigit():
                raise TrustError(f"{path}: malformed ar member size")
            size = int(size_field)
            if size > MAX_DEB_BYTES:
                raise TrustError(
                    f"{path}: ar member {name!r} declares an implausible size")
            data = fh.read(size)
            if len(data) != size:
                raise TrustError(f"{path}: truncated ar member {name!r}")
            if size % 2:
                fh.read(1)
            if name == "//":
                long_names = data
                continue
            if name.startswith("/") and name[1:].isdigit():
                offset = int(name[1:])
                if not long_names or offset >= len(long_names):
                    raise TrustError(
                        f"{path}: ar member references extended-filename "
                        f"offset {offset}, outside the name table"
                    )
                end = long_names.find(b"/\n", offset)
                if end == -1:
                    end = long_names.find(b"\n", offset)
                if end == -1:
                    raise TrustError(
                        f"{path}: unterminated extended filename at offset "
                        f"{offset}"
                    )
                name = long_names[offset:end].decode("ascii", "replace")
            name = name.rstrip("/")
            if any(existing == name for existing, _ in out):
                # Duplicate names make "which member is the control archive?"
                # ambiguous, and let a signature cover different bytes than a
                # reader selects.
                raise TrustError(
                    f"{path}: duplicate ar member {name!r}; a Debian archive "
                    f"has unique member names")
            out.append((name, data))
    if ordered:
        return out
    return dict(out)


def _gunzip_bounded(blob: bytes, limit: int, what: str) -> bytes:
    """Decompress, refusing to allocate more than ``limit`` bytes.

    ``gzip.decompress`` has no bound, so a small verified index whose
    compressed form expands enormously would still exhaust memory. The digest
    check upstream of this does not help: a compression bomb can be signed.
    """
    import io
    out = bytearray()
    try:
        with gzip.GzipFile(fileobj=io.BytesIO(blob)) as fh:
            while True:
                chunk = fh.read(1 << 20)
                if not chunk:
                    break
                out += chunk
                if len(out) > limit:
                    raise TrustError(
                        f"{what}: decompresses to more than {limit} bytes")
    except TrustError:
        raise
    except (OSError, EOFError, gzip.BadGzipFile) as exc:
        raise TrustError(f"{what}: malformed gzip data ({exc})") from exc
    return bytes(out)


def _decompress(name: str, blob: bytes) -> bytes:
    if name.endswith(".gz"):
        return _gunzip_bounded(blob, MAX_INDEX_BYTES, name)
    if name.endswith(".xz"):
        import lzma
        try:
            decompressor = lzma.LZMADecompressor()
            out = decompressor.decompress(blob, MAX_INDEX_BYTES + 1)
        except lzma.LZMAError as exc:
            raise TrustError(f"{name}: malformed xz data ({exc})") from exc
        if len(out) > MAX_INDEX_BYTES:
            raise TrustError(
                f"{name}: decompresses to more than {MAX_INDEX_BYTES} bytes")
        # A truncated stream decompresses to short output and raises nothing,
        # so without this the caller would parse a partial control archive as
        # though it were whole. This is the format the origin actually ships.
        if not decompressor.eof:
            raise TrustError(f"{name}: truncated or incomplete xz stream")
        return out
    if name.endswith(".zst"):
        try:
            import zstandard  # type: ignore
        except ImportError as exc:  # pragma: no cover - environment dependent
            raise TrustError(
                "zstd control member requires the zstandard module") from exc
        # Two properties are needed and no single API gives both.
        #
        # stream_reader can be read in bounded chunks, so a compression bomb
        # never gets to allocate -- but on a truncated frame it returns zero
        # bytes and raises nothing, which is indistinguishable from an empty
        # archive. decompressobj reports frame completion through .eof, but
        # takes no length cap.
        #
        # So: bound with the reader first, and only once the output is known
        # to be within the limit, re-run the same (now provably small) blob
        # through decompressobj purely to ask whether the frame was whole.
        # Control archives are a few kilobytes; the second pass costs nothing.
        try:
            reader = zstandard.ZstdDecompressor().stream_reader(blob)
            out = bytearray()
            while True:
                chunk = reader.read(1 << 20)
                if not chunk:
                    break
                out += chunk
                if len(out) > MAX_INDEX_BYTES:
                    raise TrustError(
                        f"{name}: decompresses to more than "
                        f"{MAX_INDEX_BYTES} bytes")

            decompressor = zstandard.ZstdDecompressor().decompressobj()
            decompressor.decompress(blob)
            if not decompressor.eof:
                raise TrustError(f"{name}: truncated or incomplete zstd frame")
        except TrustError:
            raise
        except zstandard.ZstdError as exc:
            raise TrustError(f"{name}: malformed zstd data ({exc})") from exc
        return bytes(out)
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
    published: "int | None" = None


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
    check_freshness(release_text, now=now)
    check_distribution_identity(release_text, architectures)
    published = release_date(release_text)
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
        text = _gunzip_bounded(blob, MAX_INDEX_BYTES, rel).decode("utf-8")
        records[arch] = parse_packages(text, arch)

    version = require_architecture_agreement(records)
    return VerifiedRelease(version=version, records=records, published=published)
