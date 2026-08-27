"""The committed trust anchor must be exactly the reviewed key.

If any of these fail, the signing key in the repository has changed. That is a
manual-review event: a human establishes the new key's provenance, updates
trust/KEY-PROVENANCE.md, and commits it through review. The updater must never
accept a new key on its own.
"""

from __future__ import annotations

import hashlib
import os
import shutil
import subprocess
import tempfile
import unittest

import apt_trust as T

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
BINARY = os.path.join(ROOT, "trust", "openai-chatgpt-archive-keyring.gpg")
ARMORED = os.path.join(ROOT, "trust", "openai-chatgpt-archive-keyring.asc")


class TestPinnedKey(unittest.TestCase):
    def test_the_binary_keyring_has_the_reviewed_digest(self):
        with open(BINARY, "rb") as fh:
            digest = hashlib.sha256(fh.read()).hexdigest()
        self.assertEqual(
            digest, T.EXPECTED_KEYRING_SHA256,
            "the committed keyring bytes changed; see trust/KEY-PROVENANCE.md",
        )

    def test_the_binary_keyring_has_the_expected_size(self):
        self.assertEqual(os.path.getsize(BINARY), 1148)

    @unittest.skipUnless(shutil.which("gpg"), "gpg is required")
    def test_it_contains_exactly_the_pinned_fingerprint(self):
        self.assertEqual(
            T.keyring_fingerprints(BINARY), [T.EXPECTED_KEY_FINGERPRINT])

    @unittest.skipUnless(shutil.which("gpg"), "gpg is required")
    def test_it_carries_the_expected_user_id(self):
        with tempfile.TemporaryDirectory() as home:
            os.chmod(home, 0o700)
            listing = subprocess.run(
                ["gpg", "--homedir", home, "--batch", "--with-colons",
                 "--show-keys", BINARY],
                capture_output=True, text=True, check=True,
            ).stdout
        uids = [line.split(":")[9] for line in listing.splitlines()
                if line.startswith("uid:")]
        self.assertEqual(uids, ["Codex Linux Repository"])

    @unittest.skipUnless(shutil.which("gpg"), "gpg is required")
    def test_the_armored_copy_round_trips_to_the_same_bytes(self):
        with tempfile.TemporaryDirectory() as home:
            os.chmod(home, 0o700)
            with open(ARMORED, "rb") as fh:
                armored = fh.read()
            proc = subprocess.run(
                ["gpg", "--homedir", home, "--batch", "--dearmor"],
                input=armored, capture_output=True, check=True,
            )
        with open(BINARY, "rb") as fh:
            self.assertEqual(proc.stdout, fh.read())

    @unittest.skipUnless(shutil.which("gpg"), "gpg is required")
    def test_assert_keyring_identity_accepts_the_committed_key(self):
        T.assert_keyring_identity(BINARY)

    @unittest.skipUnless(shutil.which("gpg"), "gpg is required")
    def test_assert_keyring_identity_rejects_anything_else(self):
        with tempfile.NamedTemporaryFile(suffix=".gpg", delete=False) as tmp:
            tmp.write(b"not a keyring")
            path = tmp.name
        self.addCleanup(os.unlink, path)
        with self.assertRaises(T.TrustError):
            T.assert_keyring_identity(path)

    def test_the_fingerprint_constant_is_a_full_fingerprint(self):
        # A short key ID would be forgeable; only the full 40 hex digits bind
        # the key material.
        self.assertRegex(T.EXPECTED_KEY_FINGERPRINT, r"^[0-9A-F]{40}$")


if __name__ == "__main__":
    unittest.main()
