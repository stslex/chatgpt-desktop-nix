"""Adversarial fixtures for the .deb and archive parsing.

The hardening these cover had no tests at all, which is how the traversal check
came to be defeated by `str.lstrip("./")` removing a character set rather than
a prefix: `"../control".lstrip("./")` is `"control"`, so normalising before
checking erased the very component being looked for.

Every fixture here is built rather than committed, so each test states the one
malformation it is about.
"""

from __future__ import annotations

import io
import lzma
import os
import shutil
import subprocess
import tarfile
import tempfile
import unittest

import apt_trust as T


def _have_ar() -> bool:
    return shutil.which("ar") is not None


CONTROL = b"Package: chatgpt\nVersion: 26.820.71523\nArchitecture: amd64\n"


@unittest.skipUnless(_have_ar(), "the ar tool is required")
class DebFixture(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="deb-fixture-")
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)

    def control_tar(self, members: list[tuple[str, bytes]] | None = None,
                    directory: str | None = None) -> bytes:
        buf = io.BytesIO()
        with tarfile.open(fileobj=buf, mode="w") as tar:
            if directory is not None:
                info = tarfile.TarInfo(directory)
                info.type = tarfile.DIRTYPE
                tar.addfile(info)
            for name, data in (members or [("control", CONTROL)]):
                info = tarfile.TarInfo(name)
                info.size = len(data)
                tar.addfile(info, io.BytesIO(data))
        return buf.getvalue()

    def deb(self, *, control: bytes | None = None,
            members: list[tuple[str, bytes]] | None = None) -> str:
        """Assemble a .deb from explicit ar members."""
        if members is None:
            members = [
                ("debian-binary", b"2.0\n"),
                ("control.tar.xz", lzma.compress(
                    control if control is not None else self.control_tar())),
                ("data.tar.xz", lzma.compress(b"")),
            ]
        for name, data in members:
            with open(os.path.join(self.tmp, name), "wb") as fh:
                fh.write(data)
        path = os.path.join(self.tmp, "test.deb")
        if os.path.exists(path):
            os.unlink(path)
        subprocess.run(
            ["ar", "rc", path] + [n for n, _ in members],
            cwd=self.tmp, check=True, capture_output=True,
        )
        return path


class TestControlExtraction(DebFixture):
    def test_a_well_formed_package_parses(self):
        fields = T.read_deb_control(self.deb())
        self.assertEqual(fields["Package"], "chatgpt")
        self.assertEqual(fields["Version"], "26.820.71523")

    def test_a_leading_dot_slash_is_still_accepted(self):
        # dpkg writes "./control"; that is ordinary, not a traversal.
        fields = T.read_deb_control(
            self.deb(control=self.control_tar([("./control", CONTROL)])))
        self.assertEqual(fields["Package"], "chatgpt")

    def test_a_parent_traversal_member_is_refused(self):
        """`"../control".lstrip("./")` is `"control"`.

        Normalising before checking would let this through as the control file.
        """
        for name in ("../control", "./../control", "../../control"):
            with self.subTest(name=name):
                path = self.deb(control=self.control_tar([(name, CONTROL)]))
                with self.assertRaises(T.TrustError) as ctx:
                    T.read_deb_control(path)
                self.assertIn("traversal", str(ctx.exception))

    def test_an_absolute_member_is_refused(self):
        path = self.deb(control=self.control_tar([("/control", CONTROL)]))
        with self.assertRaises(T.TrustError) as ctx:
            T.read_deb_control(path)
        self.assertIn("traversal", str(ctx.exception))

    def test_a_control_that_is_a_directory_is_refused(self):
        path = self.deb(control=self.control_tar([], directory="control"))
        with self.assertRaises(T.TrustError) as ctx:
            T.read_deb_control(path)
        self.assertIn("not a regular file", str(ctx.exception))

    def test_a_missing_control_is_refused(self):
        path = self.deb(control=self.control_tar([("other", b"x")]))
        with self.assertRaises(T.TrustError) as ctx:
            T.read_deb_control(path)
        self.assertIn("no control file", str(ctx.exception))

    def test_a_malformed_control_tar_is_a_trust_error(self):
        path = self.deb(control=b"this is not a tar archive at all")
        with self.assertRaises(T.TrustError):
            T.read_deb_control(path)


class TestArArchive(DebFixture):
    def test_duplicate_ar_members_are_refused(self):
        path = self.deb(members=[
            ("debian-binary", b"2.0\n"),
            ("control.tar.xz", lzma.compress(self.control_tar())),
            ("data.tar.xz", lzma.compress(b"")),
        ])
        # Append a second control.tar.xz by hand.
        with open(path, "rb") as fh:
            blob = fh.read()
        extra = lzma.compress(self.control_tar())
        header = b"control.tar.xz  " + b"0" * 12 + b"0     " + b"0     "
        header += b"100644  " + f"{len(extra):<10}".encode() + b"`\n"
        with open(path, "wb") as fh:
            fh.write(blob + header + extra + (b"\n" if len(extra) % 2 else b""))
        with self.assertRaises(T.TrustError) as ctx:
            T.read_deb_control(path)
        self.assertIn("duplicate ar member", str(ctx.exception))

    def test_a_non_ar_file_is_refused(self):
        path = os.path.join(self.tmp, "not-an-archive")
        with open(path, "wb") as fh:
            fh.write(b"definitely not an ar archive")
        with self.assertRaises(T.TrustError) as ctx:
            T.read_deb_control(path)
        self.assertIn("not an ar archive", str(ctx.exception))

    def test_a_package_with_no_gpgorigin_is_refused(self):
        keyring = os.path.join(
            os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
            "trust", "openai-chatgpt-archive-keyring.gpg")
        if not os.path.exists(keyring) or not shutil.which("gpgv"):
            self.skipTest("keyring or gpgv unavailable")
        with self.assertRaises(T.TrustError) as ctx:
            T.verify_deb_gpgorigin(self.deb(), keyring)
        self.assertIn("_gpgorigin", str(ctx.exception))


class TestBoundedDecompression(unittest.TestCase):
    def test_a_gzip_bomb_is_refused_rather_than_expanded(self):
        import gzip
        bomb = gzip.compress(b"\0" * (T.MAX_INDEX_BYTES + 1024))
        self.assertLess(len(bomb), 100_000, "fixture is not actually a bomb")
        with self.assertRaises(T.TrustError) as ctx:
            T._gunzip_bounded(bomb, T.MAX_INDEX_BYTES, "bomb.gz")
        self.assertIn("more than", str(ctx.exception))

    def test_an_xz_bomb_is_refused(self):
        bomb = lzma.compress(b"\0" * (T.MAX_INDEX_BYTES + 1024))
        self.assertLess(len(bomb), 100_000)
        with self.assertRaises(T.TrustError) as ctx:
            T._decompress("control.tar.xz", bomb)
        self.assertIn("more than", str(ctx.exception))

    def test_a_zstd_bomb_is_refused(self):
        try:
            import zstandard  # noqa: F401
        except ImportError:
            self.skipTest("zstandard is not available")
        import zstandard as zstd
        bomb = zstd.ZstdCompressor().compress(b"\0" * (T.MAX_INDEX_BYTES + 1024))
        self.assertLess(len(bomb), 100_000)
        with self.assertRaises(T.TrustError) as ctx:
            T._decompress("control.tar.zst", bomb)
        self.assertIn("more than", str(ctx.exception))

    def test_malformed_compressed_data_is_a_trust_error(self):
        with self.assertRaises(T.TrustError):
            T._gunzip_bounded(b"not gzip", T.MAX_INDEX_BYTES, "x.gz")
        with self.assertRaises(T.TrustError):
            T._decompress("x.xz", b"not xz")


class TestDistributionIdentity(unittest.TestCase):
    HEADER = ("Codename: stable\nSuite: stable\n"
              "Date: Thu, 27 Aug 2026 00:04:34 +0000\n")

    def test_the_real_shape_is_accepted(self):
        T.check_distribution_identity(
            self.HEADER + "MD5Sum:\n abc 1 x\n", ["amd64", "arm64"])

    def test_a_different_suite_is_refused(self):
        with self.assertRaises(T.TrustError) as ctx:
            T.check_distribution_identity(
                "Codename: stable\nSuite: beta\nMD5Sum:\n", ["amd64"])
        self.assertIn("Suite", str(ctx.exception))

    def test_a_different_codename_is_refused(self):
        with self.assertRaises(T.TrustError):
            T.check_distribution_identity(
                "Codename: experimental\nSuite: stable\nMD5Sum:\n", ["amd64"])

    def test_a_missing_component_is_refused(self):
        with self.assertRaises(T.TrustError) as ctx:
            T.check_distribution_identity(
                self.HEADER + "Components: contrib\nMD5Sum:\n", ["amd64"])
        self.assertIn("Components", str(ctx.exception))

    def test_an_omitted_architecture_is_refused(self):
        with self.assertRaises(T.TrustError) as ctx:
            T.check_distribution_identity(
                self.HEADER + "Architectures: amd64\nMD5Sum:\n",
                ["amd64", "arm64"])
        self.assertIn("arm64", str(ctx.exception))

    def test_absent_optional_fields_are_not_invented(self):
        # The live origin publishes no Components or Architectures line.
        T.check_distribution_identity(self.HEADER + "MD5Sum:\n", ["amd64"])


class TestReportableVersions(unittest.TestCase):
    def test_the_reporter_accepts_every_version_the_trust_chain_does(self):
        import report_failure
        for version in ("26.820.71523", "2:1.0~rc1", "1.0+dfsg", "1.0-2"):
            with self.subTest(version=version):
                T.validate_version(version)
                self.assertRegex(
                    version, report_failure.VERSION_RE,
                    "the reporter would refuse a version the trust chain "
                    "accepts, and would then file nothing at all",
                )


if __name__ == "__main__":
    unittest.main()
