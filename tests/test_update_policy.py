"""Tests for the updater's refusal policy.

These cover the decisions the updater makes *after* the signed chain has
already succeeded: whether a verified candidate is actually allowed to replace
what is committed. A perfectly valid signature is not sufficient — a signed
downgrade or a signed re-issue of a known version under different bytes must
still be refused and sent to a human.
"""

from __future__ import annotations

import unittest

import apt_trust as T
import update as U


def sources(version: str, amd_sha: str = "a" * 64, arm_sha: str = "b" * 64,
            amd_size: int = 100, arm_size: int = 200) -> dict:
    return {
        "version": version,
        "architectures": {
            "amd64": {
                "filename": f"pool/main/c/chatgpt/chatgpt_{version}_amd64.deb",
                "sha256": amd_sha,
                "size": amd_size,
            },
            "arm64": {
                "filename": f"pool/main/c/chatgpt/chatgpt_{version}_arm64.deb",
                "sha256": arm_sha,
                "size": arm_size,
            },
        },
    }


class TestDowngrade(unittest.TestCase):
    def test_allows_a_newer_version(self):
        U.guard_downgrade(sources("26.820.60940"), sources("26.820.71523"))

    def test_refuses_an_older_version(self):
        with self.assertRaises(T.TrustError) as ctx:
            U.guard_downgrade(sources("26.820.71523"), sources("26.820.60940"))
        self.assertIn("refusing a downgrade", str(ctx.exception))

    def test_refuses_a_numerically_older_version_that_sorts_higher(self):
        # "26.820.9" > "26.820.71523" lexically but is an older release.
        with self.assertRaises(T.TrustError):
            U.guard_downgrade(sources("26.820.71523"), sources("26.820.9"))

    def test_first_run_has_nothing_to_compare(self):
        U.guard_downgrade({}, sources("26.820.71523"))


class TestSameVersionDrift(unittest.TestCase):
    def test_identical_metadata_is_fine(self):
        current = sources("26.820.71523")
        U.guard_same_version_drift(current, current)

    def test_refuses_a_changed_digest_for_a_known_version(self):
        old = sources("26.820.71523", amd_sha="a" * 64)
        new = sources("26.820.71523", amd_sha="c" * 64)
        with self.assertRaises(T.TrustError) as ctx:
            U.guard_same_version_drift(old, new)
        self.assertIn("same-version digest drift", str(ctx.exception))
        self.assertIn("manual engineering review", str(ctx.exception))

    def test_refuses_a_changed_size_for_a_known_version(self):
        old = sources("26.820.71523", amd_size=100)
        new = sources("26.820.71523", amd_size=101)
        with self.assertRaises(T.TrustError):
            U.guard_same_version_drift(old, new)

    def test_refuses_a_changed_filename_for_a_known_version(self):
        old = sources("26.820.71523")
        new = sources("26.820.71523")
        new["architectures"]["arm64"]["filename"] = "pool/main/c/chatgpt/other.deb"
        with self.assertRaises(T.TrustError):
            U.guard_same_version_drift(old, new)

    def test_a_new_version_may_have_any_digest(self):
        old = sources("26.820.60940", amd_sha="a" * 64)
        new = sources("26.820.71523", amd_sha="f" * 64)
        U.guard_same_version_drift(old, new)

    def test_refuses_a_new_architecture_appearing_under_a_known_version(self):
        old = sources("26.820.71523")
        del old["architectures"]["arm64"]
        new = sources("26.820.71523")
        with self.assertRaises(T.TrustError) as ctx:
            U.guard_same_version_drift(old, new)
        self.assertIn("structural change", str(ctx.exception))


class TestRenderedMetadataIsDeterministic(unittest.TestCase):
    def test_same_input_produces_identical_output(self):
        records = {
            arch: T.PackageRecord(
                package="chatgpt", version="26.820.71523", architecture=arch,
                filename=f"pool/main/c/chatgpt/chatgpt_26.820.71523_{arch}.deb",
                size=123, sha256="a" * 64,
            )
            for arch in ("amd64", "arm64")
        }
        release = T.VerifiedRelease(version="26.820.71523", records=records)
        first = U.render_sources(release)
        second = U.render_sources(release)
        self.assertEqual(first, second)
        # Architecture order must be stable regardless of dict insertion order.
        self.assertEqual(list(first["architectures"]), ["amd64", "arm64"])
        self.assertEqual(
            first["architectures"]["amd64"]["hash"], T.sha256_to_sri("a" * 64))


class TestCommittedSourcesMatchTheRealRelease(unittest.TestCase):
    """The committed sources.json must be internally consistent."""

    def setUp(self):
        import json
        import os
        root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        with open(os.path.join(root, "sources.json"), encoding="utf-8") as fh:
            self.sources = json.load(fh)

    def test_origin_and_key_are_the_pinned_ones(self):
        self.assertEqual(self.sources["origin"], T.APT_ORIGIN)
        self.assertEqual(self.sources["suite"], T.APT_SUITE)
        self.assertEqual(self.sources["component"], T.APT_COMPONENT)
        self.assertEqual(self.sources["package"], T.PACKAGE_NAME)
        self.assertEqual(self.sources["signingKeyFingerprint"],
                         T.EXPECTED_KEY_FINGERPRINT)

    def test_every_architecture_is_self_consistent(self):
        version = self.sources["version"]
        T.validate_version(version)
        self.assertEqual(set(self.sources["architectures"]),
                         set(T.SUPPORTED_ARCHITECTURES))
        for arch, entry in self.sources["architectures"].items():
            with self.subTest(arch=arch):
                T.sanitize_filename(entry["filename"])
                self.assertIn(version, entry["filename"])
                self.assertTrue(entry["url"].endswith(entry["filename"]))
                self.assertTrue(entry["url"].startswith(T.APT_ORIGIN + "/"))
                self.assertEqual(entry["hash"], T.sha256_to_sri(entry["sha256"]))
                self.assertGreater(entry["size"], 1_000_000)
                self.assertEqual(entry["debianArchitecture"], arch)


if __name__ == "__main__":
    unittest.main()
