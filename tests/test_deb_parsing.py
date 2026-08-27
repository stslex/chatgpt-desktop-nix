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


class TestZstdTruncation(unittest.TestCase):
    """A short read is not the same as a complete frame.

    zstandard's stream_reader returns partial data for a truncated frame
    without raising, so a bounded read() cannot tell "finished" from "cut off".
    Truncated control metadata must not be parsed as though it were whole.
    """

    def setUp(self):
        try:
            import zstandard  # noqa: F401
        except ImportError:
            self.skipTest("zstandard is not available")

    def test_a_complete_frame_round_trips(self):
        import zstandard as zstd
        payload = b"Package: chatgpt\n" * 64
        blob = zstd.ZstdCompressor().compress(payload)
        self.assertEqual(T._decompress("control.tar.zst", blob), payload)

    def test_a_truncated_frame_is_refused(self):
        import zstandard as zstd
        payload = b"Package: chatgpt\n" * 4096
        blob = zstd.ZstdCompressor().compress(payload)
        with self.assertRaises(T.TrustError) as ctx:
            T._decompress("control.tar.zst", blob[: len(blob) // 2])
        self.assertRegex(str(ctx.exception), "truncated|malformed")


class TestXzTruncation(unittest.TestCase):
    """.xz is the format the origin actually ships, so this path matters most."""

    def test_a_complete_stream_round_trips(self):
        payload = b"Package: chatgpt\n" * 64
        self.assertEqual(
            T._decompress("control.tar.xz", lzma.compress(payload)), payload)

    def test_a_truncated_stream_is_refused(self):
        payload = b"Package: chatgpt\n" * 8192
        blob = lzma.compress(payload)
        with self.assertRaises(T.TrustError) as ctx:
            T._decompress("control.tar.xz", blob[: len(blob) // 2])
        self.assertRegex(str(ctx.exception), "truncated|malformed")


class TestArBounds(DebFixture):
    def test_a_member_claiming_more_than_the_file_holds_is_refused(self):
        path = self.deb()
        with open(path, "rb") as fh:
            blob = bytearray(fh.read())
        # Inflate the first member's declared size well past the file.
        offset = blob.index(b"`\n") - 12
        blob[offset:offset + 10] = b"9999999999"
        with open(path, "wb") as fh:
            fh.write(blob)
        with self.assertRaises(T.TrustError) as ctx:
            T.read_deb_control(path)
        self.assertRegex(str(ctx.exception), "runs past the end|truncated")

    def test_bad_padding_is_refused(self):
        # debian-binary is 4 bytes ("2.0\n"), so no padding; make an odd member.
        members = [
            ("debian-binary", b"2.0"),          # odd length -> needs padding
            ("control.tar.xz", lzma.compress(self.control_tar())),
            ("data.tar.xz", lzma.compress(b"")),
        ]
        path = self.deb(members=members)
        with open(path, "rb") as fh:
            blob = bytearray(fh.read())
        # Corrupt the pad byte that follows the 3-byte debian-binary member.
        index = blob.index(b"2.0") + 3
        blob[index] = ord("X")
        with open(path, "wb") as fh:
            fh.write(blob)
        with self.assertRaises(T.TrustError) as ctx:
            T.read_deb_control(path)
        self.assertIn("padded with", str(ctx.exception))


class TestConcatenatedAndTrailingData(unittest.TestCase):
    """Only one member's worth of data may be present.

    GzipFile concatenates members transparently and lzma stops at the first
    stream, so appended data would be either folded in or silently dropped.
    """

    def test_gzip_rejects_trailing_bytes(self):
        import gzip
        with self.assertRaises(T.TrustError) as ctx:
            T._gunzip_bounded(gzip.compress(b"x") + b"JUNK",
                              T.MAX_INDEX_BYTES, "x.gz")
        self.assertIn("follow the gzip member", str(ctx.exception))

    def test_gzip_rejects_a_second_member(self):
        import gzip
        with self.assertRaises(T.TrustError):
            T._gunzip_bounded(gzip.compress(b"a") + gzip.compress(b"b"),
                              T.MAX_INDEX_BYTES, "x.gz")

    def test_gzip_rejects_a_truncated_member(self):
        import gzip
        blob = gzip.compress(b"payload" * 512)
        with self.assertRaises(T.TrustError) as ctx:
            T._gunzip_bounded(blob[: len(blob) // 2], T.MAX_INDEX_BYTES, "x.gz")
        self.assertRegex(str(ctx.exception), "truncated|malformed")

    def test_xz_rejects_trailing_bytes(self):
        with self.assertRaises(T.TrustError) as ctx:
            T._decompress("x.xz", lzma.compress(b"x") + b"JUNK")
        self.assertIn("follow the xz stream", str(ctx.exception))

    def test_xz_rejects_a_second_stream(self):
        with self.assertRaises(T.TrustError):
            T._decompress("x.xz", lzma.compress(b"a") + lzma.compress(b"b"))


class TestControlFieldCaseFolding(unittest.TestCase):
    def test_duplicate_fields_differing_only_in_case_are_refused(self):
        for text in ("Package: a\npackage: b\n",
                     "Package: a\nPACKAGE: b\n",
                     "Version: 1\nvErSiOn: 2\n"):
            with self.subTest(text=text), self.assertRaises(T.TrustError) as ctx:
                T.parse_control_paragraph(text)
            self.assertIn("case-insensitive", str(ctx.exception))

    def test_distinct_fields_are_still_accepted(self):
        fields = T.parse_control_paragraph("Package: a\nVersion: 1\n")
        self.assertEqual(fields, {"Package": "a", "Version": "1"})


class TestFilenameUrlParts(unittest.TestCase):
    def test_query_fragment_and_userinfo_are_refused(self):
        for bad in ("pool/main/c/chatgpt/a.deb?x=1",
                    "pool/main/c/chatgpt/a.deb#frag",
                    "pool/x@evil.example/y.deb"):
            with self.subTest(bad=bad), self.assertRaises(T.TrustError):
                T.sanitize_filename(bad)


class TestDateNormalisation(unittest.TestCase):
    HEADER = "Suite: stable\nCodename: stable\n"

    def test_every_malformed_date_becomes_a_trust_error(self):
        for bad in ("not a date",
                    "Thu, 99 Xxx 2026 00:00:00 +0000",
                    "Mon, 1 Jan 9999999 00:00:00 +0000",
                    "Thu, 27 Aug 2026 00:00:00 +9999"):
            with self.subTest(bad=bad):
                with self.assertRaises(T.TrustError):
                    T.check_freshness(
                        f"{self.HEADER}Date: {bad}\nMD5Sum:\n")

    def test_a_date_without_a_timezone_is_read_as_utc(self):
        # Otherwise the same metadata would age differently per machine.
        stamp = T.release_date(f"{self.HEADER}Date: Thu, 27 Aug 2026 "
                               f"00:04:34\nMD5Sum:\n")
        self.assertEqual(stamp, 1787789074)


class TestDistributionIdentityIsRequired(unittest.TestCase):
    def test_a_release_without_suite_is_refused(self):
        with self.assertRaises(T.TrustError) as ctx:
            T.check_distribution_identity(
                "Codename: stable\nMD5Sum:\n", ["amd64"])
        self.assertIn("no Suite field", str(ctx.exception))

    def test_a_release_without_codename_is_refused(self):
        with self.assertRaises(T.TrustError) as ctx:
            T.check_distribution_identity("Suite: stable\nMD5Sum:\n", ["amd64"])
        self.assertIn("no Codename field", str(ctx.exception))
