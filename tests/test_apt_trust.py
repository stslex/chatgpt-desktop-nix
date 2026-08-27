"""Fixture tests for the signed-APT trust chain.

Each test builds a complete, self-consistent repository in a temporary
directory, signed with a throwaway key, then introduces exactly one defect and
asserts the chain refuses it. Building the fixtures rather than committing them
keeps the failure modes readable: every test states its own defect in one line.

The production trust anchor is not used here — these tests would otherwise
require OpenAI's private key. The committed key's identity is asserted
separately, in ``test_pinned_key.py`` and in ``checks.trust-key``.
"""

from __future__ import annotations

import gzip
import hashlib
import json
import os
import shutil
import subprocess
import tempfile
import textwrap
import unittest
from unittest import mock

import apt_trust as T


def _have_gpg() -> bool:
    return shutil.which("gpg") is not None and shutil.which("gpgv") is not None


@unittest.skipUnless(_have_gpg(), "gpg and gpgv are required")
class SigningFixture(unittest.TestCase):
    """A throwaway signing key plus helpers to build signed repositories."""

    @classmethod
    def setUpClass(cls) -> None:
        cls._home = tempfile.mkdtemp(prefix="apt-trust-gnupg-")
        os.chmod(cls._home, 0o700)
        cls.gnupg = cls._home

        # Two keys: the one the fixtures pin, and an impostor.
        cls.fingerprints = {}
        for name in ("Trusted Test Key", "Untrusted Other Key"):
            subprocess.run(
                ["gpg", "--homedir", cls.gnupg, "--batch", "--quiet",
                 "--passphrase", "", "--quick-generate-key", name,
                 "rsa2048", "sign", "never"],
                check=True, capture_output=True,
            )
        listing = subprocess.run(
            ["gpg", "--homedir", cls.gnupg, "--batch", "--with-colons",
             "--list-secret-keys", "--with-fingerprint"],
            check=True, capture_output=True, text=True,
        ).stdout
        current = None
        for line in listing.splitlines():
            parts = line.split(":")
            if parts[0] == "sec":
                current = "pending"
            elif parts[0] == "fpr" and current == "pending":
                current = parts[9]
            elif parts[0] == "uid" and current not in (None, "pending"):
                cls.fingerprints[parts[9]] = current
                current = None

        cls.trusted_fpr = cls.fingerprints["Trusted Test Key"]
        cls.untrusted_fpr = cls.fingerprints["Untrusted Other Key"]

        cls.keyrings = {}
        for uid, fpr in cls.fingerprints.items():
            path = os.path.join(cls._home, f"{fpr}.gpg")
            subprocess.run(
                ["gpg", "--homedir", cls.gnupg, "--batch", "--yes",
                 "--output", path, "--export", fpr],
                check=True, capture_output=True,
            )
            cls.keyrings[fpr] = path

    @classmethod
    def tearDownClass(cls) -> None:
        shutil.rmtree(cls._home, ignore_errors=True)

    def setUp(self) -> None:
        self.tmp = tempfile.mkdtemp(prefix="apt-trust-")
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)
        # Point the module's pinned anchor at our throwaway key.
        keyring = self.keyrings[self.trusted_fpr]
        with open(keyring, "rb") as fh:
            digest = hashlib.sha256(fh.read()).hexdigest()
        patches = [
            mock.patch.object(T, "EXPECTED_KEY_FINGERPRINT", self.trusted_fpr),
            mock.patch.object(T, "EXPECTED_KEYRING_SHA256", digest),
        ]
        for patch in patches:
            patch.start()
            self.addCleanup(patch.stop)
        self.keyring = keyring

    # -- fixture construction ------------------------------------------

    def clearsign(self, text: str, fingerprint: str | None = None) -> bytes:
        fpr = fingerprint or self.trusted_fpr
        proc = subprocess.run(
            ["gpg", "--homedir", self.gnupg, "--batch", "--yes", "--quiet",
             "--local-user", fpr, "--digest-algo", "SHA512", "--clearsign"],
            input=text.encode(), capture_output=True, check=True,
        )
        return proc.stdout

    def packages_stanza(self, *, arch: str, version: str = "26.820.71523",
                        package: str = "chatgpt",
                        filename: str | None = None,
                        size: int = 1000, sha256: str | None = None) -> str:
        if filename is None:
            filename = f"pool/main/c/chatgpt/chatgpt_{version}_{arch}.deb"
        if sha256 is None:
            sha256 = hashlib.sha256(f"{arch}{version}".encode()).hexdigest()
        return textwrap.dedent(f"""\
            Package: {package}
            Version: {version}
            Architecture: {arch}
            Maintainer: OpenAI <support@openai.com>
            Filename: {filename}
            Size: {size}
            SHA256: {sha256}
            Description: ChatGPT by OpenAI
            """)

    def build_repo(self, *, stanzas: dict[str, str] | None = None,
                   valid_until: str | None = None,
                   corrupt_index_hash: bool = False,
                   corrupt_index_size: bool = False,
                   sign_with: str | None = None,
                   tamper_signature: bool = False) -> dict[str, bytes]:
        """Return a URL -> bytes map describing a complete signed repository."""
        if stanzas is None:
            stanzas = {a: self.packages_stanza(arch=a)
                       for a in ("amd64", "arm64")}

        blobs: dict[str, bytes] = {}
        lines = ["Codename: stable", "Suite: stable"]
        if valid_until:
            lines.append(f"Valid-Until: {valid_until}")
        lines.append("SHA256:")

        for arch, text in stanzas.items():
            rel = f"main/binary-{arch}/Packages.gz"
            blob = gzip.compress(text.encode(), mtime=0)
            blobs[f"{T.APT_ORIGIN}/dists/stable/{rel}"] = blob
            digest = hashlib.sha256(blob).hexdigest()
            size = len(blob)
            if corrupt_index_hash:
                digest = "0" * 64
            if corrupt_index_size:
                size += 1
            lines.append(f" {digest} {size:>16} {rel}")

        release = "\n".join(lines) + "\n"
        signed = self.clearsign(release, sign_with)
        if tamper_signature:
            signed = signed.replace(b"Codename: stable", b"Codename: stabIe")
        blobs[f"{T.APT_ORIGIN}/dists/stable/InRelease"] = signed
        return blobs

    def fetcher(self, blobs: dict[str, bytes]):
        def fetch(url: str) -> bytes:
            if url not in blobs:
                raise AssertionError(f"unexpected fetch: {url}")
            return blobs[url]
        return fetch

    def resolve(self, blobs, **kwargs):
        return T.resolve_signed_release(
            self.fetcher(blobs), self.keyring, **kwargs
        )


class TestValidMetadata(SigningFixture):
    def test_accepts_a_well_formed_signed_repository(self):
        release = self.resolve(self.build_repo())
        self.assertEqual(release.version, "26.820.71523")
        self.assertEqual(set(release.records), {"amd64", "arm64"})
        self.assertEqual(
            release.records["amd64"].filename,
            "pool/main/c/chatgpt/chatgpt_26.820.71523_amd64.deb",
        )

    def test_accepts_metadata_that_is_still_valid(self):
        blobs = self.build_repo(valid_until="Sat, 01 Jan 2050 00:00:00 UTC")
        self.assertEqual(self.resolve(blobs).version, "26.820.71523")


class TestSignatureFailures(SigningFixture):
    def test_rejects_a_tampered_payload(self):
        with self.assertRaises(T.TrustError) as ctx:
            self.resolve(self.build_repo(tamper_signature=True))
        self.assertIn("signature verification failed", str(ctx.exception))

    def test_rejects_an_unpinned_signing_key(self):
        with self.assertRaises(T.TrustError) as ctx:
            self.resolve(self.build_repo(sign_with=self.untrusted_fpr))
        self.assertIn("verification failed", str(ctx.exception).lower())

    def test_rejects_an_unsigned_release(self):
        blobs = self.build_repo()
        blobs[f"{T.APT_ORIGIN}/dists/stable/InRelease"] = (
            b"Codename: stable\nSuite: stable\nSHA256:\n"
        )
        with self.assertRaises(T.TrustError):
            self.resolve(blobs)

    def test_rejects_a_modified_keyring(self):
        # Simulate an attempt to swap the committed key for another one.
        with mock.patch.object(T, "EXPECTED_KEYRING_SHA256", "0" * 64):
            with self.assertRaises(T.TrustError) as ctx:
                self.resolve(self.build_repo())
        self.assertIn("manual-review", str(ctx.exception))


class TestExpiry(SigningFixture):
    def test_rejects_expired_metadata(self):
        blobs = self.build_repo(valid_until="Tue, 01 Jan 2019 00:00:00 UTC")
        with self.assertRaises(T.TrustError) as ctx:
            self.resolve(blobs)
        self.assertIn("expired", str(ctx.exception))

    def test_absent_valid_until_is_accepted(self):
        # The live OpenAI origin does not publish Valid-Until today.
        self.assertNotIn(b"Valid-Until",
                         self.build_repo()[f"{T.APT_ORIGIN}/dists/stable/InRelease"])
        self.assertEqual(self.resolve(self.build_repo()).version, "26.820.71523")


class TestIndexIntegrity(SigningFixture):
    def test_rejects_a_wrong_index_hash(self):
        with self.assertRaises(T.TrustError) as ctx:
            self.resolve(self.build_repo(corrupt_index_hash=True))
        self.assertIn("SHA-256 mismatch", str(ctx.exception))

    def test_rejects_a_wrong_index_size(self):
        with self.assertRaises(T.TrustError) as ctx:
            self.resolve(self.build_repo(corrupt_index_size=True))
        self.assertIn("size mismatch", str(ctx.exception))

    def test_rejects_a_missing_index_entry(self):
        blobs = self.build_repo(
            stanzas={"amd64": self.packages_stanza(arch="amd64")}
        )
        with self.assertRaises(T.TrustError) as ctx:
            self.resolve(blobs)
        self.assertIn("does not list", str(ctx.exception))


class TestPackageStanzas(SigningFixture):
    def test_rejects_a_package_name_mismatch(self):
        blobs = self.build_repo(stanzas={
            "amd64": self.packages_stanza(arch="amd64", package="not-chatgpt"),
            "arm64": self.packages_stanza(arch="arm64"),
        })
        with self.assertRaises(T.TrustError) as ctx:
            self.resolve(blobs)
        self.assertIn("no Package: chatgpt stanza", str(ctx.exception))

    def test_rejects_an_architecture_mismatch(self):
        # The arm64 index contains only an amd64 stanza.
        blobs = self.build_repo(stanzas={
            "amd64": self.packages_stanza(arch="amd64"),
            "arm64": self.packages_stanza(arch="amd64"),
        })
        with self.assertRaises(T.TrustError) as ctx:
            self.resolve(blobs)
        self.assertIn("architecture arm64", str(ctx.exception))

    def test_rejects_architecture_version_skew(self):
        blobs = self.build_repo(stanzas={
            "amd64": self.packages_stanza(arch="amd64", version="26.820.71523"),
            "arm64": self.packages_stanza(arch="arm64", version="26.820.60940"),
        })
        with self.assertRaises(T.TrustError) as ctx:
            self.resolve(blobs)
        self.assertIn("architecture version skew", str(ctx.exception))

    def test_rejects_duplicate_stanzas_for_one_architecture(self):
        doubled = (self.packages_stanza(arch="amd64") + "\n" +
                   self.packages_stanza(arch="amd64", version="26.820.99999"))
        blobs = self.build_repo(stanzas={
            "amd64": doubled,
            "arm64": self.packages_stanza(arch="arm64"),
        })
        with self.assertRaises(T.TrustError) as ctx:
            self.resolve(blobs)
        self.assertIn("exactly one", str(ctx.exception))


class TestFilenameSanitisation(unittest.TestCase):
    """``Filename`` is attacker-influenced input; it must not escape the origin."""

    def test_accepts_a_normal_pool_path(self):
        good = "pool/main/c/chatgpt/chatgpt_26.820.71523_amd64.deb"
        self.assertEqual(T.sanitize_filename(good), good)

    def test_rejects_traversal(self):
        for bad in [
            "pool/../../../etc/passwd",
            "pool/main/../../../../tmp/evil.deb",
            "pool/./../../evil.deb",
        ]:
            with self.subTest(bad=bad), self.assertRaises(T.TrustError):
                T.sanitize_filename(bad)

    def test_rejects_absolute_paths_and_urls(self):
        for bad in [
            "/etc/passwd",
            "//evil.example.com/x.deb",
            "https://evil.example.com/x.deb",
            "http://evil.example.com/x.deb",
            "file:///etc/passwd",
        ]:
            with self.subTest(bad=bad), self.assertRaises(T.TrustError):
                T.sanitize_filename(bad)

    def test_rejects_paths_outside_the_pool(self):
        for bad in ["dists/stable/evil.deb", "evil.deb", "../pool/x.deb"]:
            with self.subTest(bad=bad), self.assertRaises(T.TrustError):
                T.sanitize_filename(bad)

    def test_rejects_encoded_traversal_and_backslashes(self):
        for bad in ["pool/%2e%2e/x.deb", "pool\\..\\x.deb"]:
            with self.subTest(bad=bad), self.assertRaises(T.TrustError):
                T.sanitize_filename(bad)

    def test_rejects_empty_and_oversized(self):
        with self.assertRaises(T.TrustError):
            T.sanitize_filename("")
        with self.assertRaises(T.TrustError):
            T.sanitize_filename("pool/" + "a" * 1000)


class TestTraversalThroughTheChain(SigningFixture):
    def test_rejects_a_traversal_filename_in_a_signed_stanza(self):
        blobs = self.build_repo(stanzas={
            "amd64": self.packages_stanza(
                arch="amd64", filename="pool/../../../../etc/shadow"),
            "arm64": self.packages_stanza(arch="arm64"),
        })
        with self.assertRaises(T.TrustError) as ctx:
            self.resolve(blobs)
        self.assertIn("unsafe path component", str(ctx.exception))

    def test_rejects_an_absolute_url_filename(self):
        blobs = self.build_repo(stanzas={
            "amd64": self.packages_stanza(
                arch="amd64", filename="https://evil.example.com/x.deb"),
            "arm64": self.packages_stanza(arch="arm64"),
        })
        with self.assertRaises(T.TrustError):
            self.resolve(blobs)


class TestDebianVersionOrdering(unittest.TestCase):
    """Debian versions must never be compared as strings."""

    def test_numeric_components_compare_numerically(self):
        # The whole point: lexically "26.820.9" > "26.820.71523".
        self.assertGreater("26.820.9", "26.820.71523")
        self.assertEqual(
            T.compare_debian_versions("26.820.9", "26.820.71523"), -1)

    def test_ordering_basics(self):
        cases = [
            ("1.0", "1.0", 0),
            ("1.1", "1.0", 1),
            ("1.0", "1.1", -1),
            ("26.820.71523", "26.820.60940", 1),
            ("1.0", "1.0~rc1", 1),      # ~ sorts before everything
            ("1.0~rc1", "1.0", -1),
            ("1.0-2", "1.0-10", -1),
            ("2:1.0", "1:9.9", 1),      # epoch dominates
            ("1.010", "1.10", 0),       # leading zeros ignored
        ]
        for a, b, want in cases:
            with self.subTest(a=a, b=b):
                self.assertEqual(T.compare_debian_versions(a, b), want)

    def test_rejects_implausible_versions(self):
        for bad in ["", "../etc", "a1.0", "1.0; rm -rf /", "x" * 200]:
            with self.subTest(bad=bad), self.assertRaises(T.TrustError):
                T.validate_version(bad)


class TestSriConversion(unittest.TestCase):
    def test_converts_a_known_digest(self):
        # The real amd64 digest for 26.820.71523.
        self.assertEqual(
            T.sha256_to_sri(
                "472d03e88a29857f1015b2b9175d80523a131cf1bc3e9017eb1a8ff234de1bda"),
            "sha256-Ry0D6IophX8QFbK5F12AUjoTHPG8PpAX6xqP8jTeG9o=",
        )

    def test_rejects_non_digests(self):
        for bad in ["", "xyz", "A" * 64, "0" * 63]:
            with self.subTest(bad=bad), self.assertRaises(T.TrustError):
                T.sha256_to_sri(bad)


class TestControlParsing(unittest.TestCase):
    def test_folds_continuation_lines(self):
        fields = T.parse_control_paragraph(
            "Package: chatgpt\nDescription: One\n Two\n Three\n")
        self.assertEqual(fields["Package"], "chatgpt")
        self.assertEqual(fields["Description"], "One\nTwo\nThree")

    def test_rejects_duplicate_fields(self):
        with self.assertRaises(T.TrustError):
            T.parse_control_paragraph("Package: a\nPackage: b\n")

    def test_rejects_malformed_lines(self):
        with self.assertRaises(T.TrustError):
            T.parse_control_paragraph("this is not a field\n")


if __name__ == "__main__":
    unittest.main()
