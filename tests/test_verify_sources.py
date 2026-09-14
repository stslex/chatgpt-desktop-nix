"""Pinned verification must survive new releases without accepting forged pins."""

from __future__ import annotations

import contextlib
import copy
import gzip
import hashlib
import io
import json
from pathlib import Path
import subprocess
import tarfile
import unittest
from unittest import mock

import apt_trust as T
import update as U
import verify_sources as V
from test_apt_trust import SigningFixture


def manifest(version="26.820.71523"):
    records = {
        arch: T.PackageRecord(
            package=T.PACKAGE_NAME, version=version, architecture=arch,
            filename=f"pool/main/c/chatgpt/chatgpt_{version}_{arch}.deb",
            size=123, sha256="a" * 64,
        )
        for arch in T.SUPPORTED_ARCHITECTURES
    }
    return U.render_sources(T.VerifiedRelease(version=version, records=records))


def archive(members):
    result = bytearray(b"!<arch>\n")
    for name, body in members:
        header = (f"{name + '/':<16}{0:<12}{0:<6}{0:<6}"
                  f"{'100644':<8}{len(body):<10}`\n").encode("ascii")
        assert len(header) == 60
        result.extend(header + body + (b"\n" if len(body) % 2 else b""))
    return bytes(result)


class TestManifestValidation(unittest.TestCase):
    def test_valid_manifest_round_trips(self):
        sources = manifest()
        self.assertEqual(U.render_sources(V.release_from_sources(sources)), sources)

    def test_top_level_identity_is_not_trusted(self):
        changes = {
            "origin": "https://example.invalid", "suite": "other",
            "component": "other", "package": "other",
            "signingKeyFingerprint": "0" * 40,
        }
        for key, value in changes.items():
            with self.subTest(key=key):
                sources = manifest()
                sources[key] = value
                with self.assertRaises(T.TrustError):
                    V.release_from_sources(sources)

    def test_malformed_entries_are_rejected(self):
        changes = [
            ("size", value) for value in (True, "123", 0, -1, T.MAX_DEB_BYTES + 1)
        ] + [
            ("sha256", "a" * 63), ("sha256", "z" * 64),
            ("hash", T.sha256_to_sri("b" * 64)),
            ("debianArchitecture", "arm64"),
            ("url", "https://example.invalid/forged.deb"),
            ("filename", "pool/../forged.deb"),
            ("filename", "pool/%2e%2e/forged.deb"),
        ]
        for key, value in changes:
            with self.subTest(key=key, value=value):
                sources = manifest()
                sources["architectures"]["amd64"][key] = value
                with self.assertRaises(T.TrustError):
                    V.release_from_sources(sources)

    def test_missing_or_extra_architectures_are_rejected(self):
        for arch in T.SUPPORTED_ARCHITECTURES:
            sources = manifest()
            del sources["architectures"][arch]
            with self.assertRaises(T.TrustError):
                V.release_from_sources(sources)
        sources = manifest()
        sources["architectures"]["extra"] = sources["architectures"]["amd64"]
        with self.assertRaises(T.TrustError):
            V.release_from_sources(sources)

    def test_wrong_json_types_are_rejected(self):
        for sources in (None, [], True, {"version": 1}, {"version": "bad/version"},
                        {"version": "1", "architectures": []}):
            with self.subTest(sources=sources), self.assertRaises(T.TrustError):
                V.release_from_sources(sources)


class TestPinnedVerification(SigningFixture):
    """Run the real verifier with signed .deb fixtures; only HTTP is replaced."""

    def setUp(self):
        super().setUp()
        self.sources_path = Path(self.tmp) / "sources.json"
        self.blobs = {}
        patches = [
            mock.patch.object(U, "SOURCES_PATH", str(self.sources_path)),
            mock.patch.object(U, "KEYRING_PATH", self.keyring),
            # A new release, missing index or metadata expiry must not affect
            # verification of a pin. Any live-index request is a test failure.
            mock.patch.object(U, "fetch", side_effect=AssertionError("live APT fetch")),
            mock.patch.object(T, "resolve_signed_release",
                              side_effect=AssertionError("live APT resolution")),
        ]
        for patch in patches:
            patch.start()
            self.addCleanup(patch.stop)
        download = mock.patch.object(U, "fetch_to_file", side_effect=self.download)
        self.fetch = download.start()
        self.addCleanup(download.stop)

    def download(self, url, path, expected_size):
        Path(path).write_bytes(self.blobs[url])

    def packages(self, *, version="26.820.71523", unsigned=False,
                 wrong_signer=False, tamper=False, control_override=None):
        sources = manifest(version)
        for arch, entry in sources["architectures"].items():
            fields = {"Package": "chatgpt", "Version": version, "Architecture": arch}
            fields.update(control_override or {})
            control = "".join(f"{key}: {value}\n" for key, value in fields.items()).encode()
            buf = io.BytesIO()
            with tarfile.open(fileobj=buf, mode="w") as tar:
                info = tarfile.TarInfo("./control")
                info.size = len(control)
                tar.addfile(info, io.BytesIO(control))
            members = [
                ("debian-binary", b"2.0\n"),
                ("control.tar.gz", gzip.compress(buf.getvalue(), mtime=0)),
                ("data.tar.gz", gzip.compress(b"signed application payload", mtime=0)),
            ]
            if not unsigned:
                proc = subprocess.run(
                    ["gpg", "--homedir", self.gnupg, "--batch", "--yes", "--quiet",
                     "--local-user", self.untrusted_fpr if wrong_signer else self.trusted_fpr,
                     "--detach-sign"],
                    input=b"".join(body for _, body in members), capture_output=True,
                    check=True,
                )
                members.append(("_gpgorigin", proc.stdout))
            if tamper:
                members[2] = ("data.tar.gz", gzip.compress(b"forged payload", mtime=0))
            blob = archive(members)
            self.blobs[entry["url"]] = blob
            entry["size"] = len(blob)
            # Even when the attacker updates the manifest to match the forged
            # package, the unchanged signature must still stop verification.
            entry["sha256"] = hashlib.sha256(blob).hexdigest()
            entry["hash"] = T.sha256_to_sri(entry["sha256"])
        self.sources_path.write_text(json.dumps(sources))
        return sources

    def verify(self, *args):
        self.stdout, self.stderr = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(self.stdout), contextlib.redirect_stderr(self.stderr):
            return V.main(list(args))

    def test_pin_verifies_without_consulting_the_latest_release(self):
        sources = self.packages()
        self.assertEqual(self.verify(), 0, self.stderr.getvalue())
        self.assertEqual({call.args[0] for call in self.fetch.call_args_list},
                         {entry["url"] for entry in sources["architectures"].values()})
        self.assertEqual(self.fetch.call_count, 2)

    def test_strict_option_keeps_working(self):
        self.packages()
        self.assertEqual(self.verify("--strict"), 0, self.stderr.getvalue())
        self.assertEqual(self.fetch.call_count, 2)

    def test_unsigned_wrongly_signed_and_tampered_packages_fail(self):
        for defect in ("unsigned", "wrong_signer", "tamper"):
            with self.subTest(defect=defect):
                self.packages(**{defect: True})
                self.assertEqual(self.verify(), 20, self.stderr.getvalue())
                self.assertIn("_gpgorigin", self.stderr.getvalue())

    def test_signed_control_fields_must_match_the_pin(self):
        for key, value in (("Package", "other"), ("Version", "99.0"),
                           ("Architecture", "other")):
            with self.subTest(field=key):
                self.packages(control_override={key: value})
                self.assertEqual(self.verify(), 20)
                self.assertIn(f"control {key}", self.stderr.getvalue())

    def test_incorrect_size_or_hash_fails(self):
        for field, value in (("size", 123), ("sha256", "b" * 64)):
            with self.subTest(field=field):
                sources = self.packages()
                entry = sources["architectures"]["amd64"]
                entry[field] = value
                entry["hash"] = T.sha256_to_sri(entry["sha256"])
                self.sources_path.write_text(json.dumps(sources))
                self.assertEqual(self.verify(), 20)

    def test_base_policy_still_rejects_downgrades_and_digest_drift(self):
        sources = self.packages()
        base_path = Path(self.tmp) / "base.json"
        newer = manifest("26.908.40834")
        drift = copy.deepcopy(sources)
        entry = drift["architectures"]["arm64"]
        entry["sha256"] = "b" * 64
        entry["hash"] = T.sha256_to_sri(entry["sha256"])
        for base in (newer, drift):
            with self.subTest(version=base["version"]):
                base_path.write_text(json.dumps(base))
                self.assertEqual(self.verify("--base-sources", str(base_path)), 20)
        self.fetch.assert_not_called()

    def test_unchanged_pin_is_accepted_against_the_base(self):
        sources = self.packages()
        base_path = Path(self.tmp) / "base.json"
        base_path.write_text(json.dumps(sources))
        self.assertEqual(self.verify("--base-sources", str(base_path)), 0)

    def test_malformed_base_cannot_disable_the_policy(self):
        self.packages()
        base_path = Path(self.tmp) / "base.json"
        for value in ("null", "{}", "[]", "not JSON"):
            with self.subTest(value=value):
                base_path.write_text(value)
                self.assertNotEqual(self.verify("--base-sources", str(base_path)), 0)
        self.fetch.assert_not_called()

    def test_failure_to_download_either_architecture_fails_verification(self):
        self.packages()
        for failed_arch in T.SUPPORTED_ARCHITECTURES:
            def download(url, path, expected_size):
                if url.endswith(f"_{failed_arch}.deb"):
                    raise U.NetworkError("fixture download failure")
                self.download(url, path, expected_size)
            with self.subTest(architecture=failed_arch):
                self.fetch.side_effect = download
                self.assertEqual(self.verify(), 30)


if __name__ == "__main__":
    unittest.main()
