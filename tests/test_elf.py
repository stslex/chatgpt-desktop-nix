"""Tests for the ELF classifier and the PT_INTERP relocator.

These build synthetic ELF64 files rather than committing binary fixtures, so
each test states the exact structural property it is about.

The relocator tests encode the two failures that actually matter, both of which
were observed on the real payload:

  * patchelf pushes PT_INTERP past the 2 KiB window detect-libc reads, which
    makes glibc detection fail and leads to SIGILL;
  * a naive search for "padding-looking" bytes can land inside a live section,
    producing a file that passes every structural check and then segfaults.
"""

from __future__ import annotations

import os
import copy
import struct
import tempfile
import unittest

import elf_classify as C
import relocate_interp as R


def build_elf(*, machine: int = 0x3E, etype: int = 3,
              interp: bytes | None = b"/lib64/ld-linux-x86-64.so.2\0",
              interp_offset: int = 736,
              needed: list[bytes] | None = None,
              android_note: bool = False,
              total_size: int = 8192,
              filler: int = 0x58,
              claim_interp_section: bool = True,
              extra_section_covering: tuple[int, int] | None = None) -> bytes:
    """Construct a minimal but structurally valid ELF64 image."""
    needed = needed or []
    buf = bytearray(b"\0" * total_size)

    phdrs: list[tuple] = []
    # PT_LOAD covering the whole file, vaddr == offset.
    phdrs.append((1, 4, 0, 0, 0, total_size, total_size, 0x1000))
    if interp is not None:
        phdrs.append((3, 4, interp_offset, interp_offset, interp_offset,
                      len(interp), len(interp), 1))

    # Dynamic string table and DT_NEEDED entries.
    dynstr_off = 4096
    strtab = b"\0"
    offsets = []
    for name in needed:
        offsets.append(len(strtab))
        strtab += name + b"\0"
    buf[dynstr_off:dynstr_off + len(strtab)] = strtab

    dyn_off = 5120
    entries: list[tuple[int, int]] = []
    for off in offsets:
        entries.append((1, off))                    # DT_NEEDED
    entries.append((5, dynstr_off))                 # DT_STRTAB (vaddr==offset)
    entries.append((10, len(strtab)))               # DT_STRSZ
    entries.append((0, 0))                          # DT_NULL
    dyn = b"".join(struct.pack("<QQ", t, v) for t, v in entries)
    buf[dyn_off:dyn_off + len(dyn)] = dyn
    if needed or True:
        phdrs.append((2, 6, dyn_off, dyn_off, dyn_off, len(dyn), len(dyn), 8))

    if android_note:
        note_off = 6144
        name = b"Android\0"
        note = struct.pack("<III", len(name), 4, 1) + name + b"\0" * 4
        buf[note_off:note_off + len(note)] = note
        phdrs.append((4, 4, note_off, note_off, note_off, len(note), len(note), 4))

    e_phoff, e_phentsize = 64, 56
    e_phnum = len(phdrs)
    for i, (t, fl, off, va, pa, fsz, msz, al) in enumerate(phdrs):
        base = e_phoff + i * e_phentsize
        struct.pack_into("<II", buf, base, t, fl)
        struct.pack_into("<QQQ", buf, base + 8, off, va, pa)
        struct.pack_into("<QQQ", buf, base + 32, fsz, msz, al)

    # Fill the gap after the program headers with the requested filler byte, so
    # the relocator has somewhere plausible to look. This happens before the
    # interpreter is written, so an in-window interpreter is not overwritten.
    gap_start = e_phoff + e_phentsize * e_phnum
    for i in range(gap_start, min(dynstr_off, total_size)):
        buf[i] = filler

    if interp is not None:
        buf[interp_offset:interp_offset + len(interp)] = interp

    # Section headers: shstrtab, optionally .interp, optionally an extra
    # section that deliberately claims part of the gap.
    names = b"\0.shstrtab\0.interp\0.claimed\0"
    shstr_off = 7168
    buf[shstr_off:shstr_off + len(names)] = names

    sections = [(0, 0, 0, 0)]  # SHT_NULL
    sections.append((1, 3, shstr_off, len(names)))  # .shstrtab, SHT_STRTAB
    if interp is not None and claim_interp_section:
        sections.append((11, 1, interp_offset, len(interp)))  # .interp
    if extra_section_covering:
        start, size = extra_section_covering
        sections.append((20, 1, start, size))  # .claimed

    e_shoff = 7680
    e_shentsize = 64
    for i, (name_off, sh_type, sh_off, sh_size) in enumerate(sections):
        base = e_shoff + i * e_shentsize
        struct.pack_into("<II", buf, base, name_off, sh_type)
        struct.pack_into("<QQ", buf, base + 16, sh_off, sh_off)  # addr, offset
        struct.pack_into("<Q", buf, base + 32, sh_size)

    buf[0:4] = b"\x7fELF"
    buf[4], buf[5], buf[6] = 2, 1, 1
    struct.pack_into("<HH", buf, 16, etype, machine)
    struct.pack_into("<Q", buf, 32, e_phoff)
    struct.pack_into("<Q", buf, 40, e_shoff)
    struct.pack_into("<HH", buf, 54, e_phentsize, e_phnum)
    struct.pack_into("<HH", buf, 58, e_shentsize, len(sections))
    struct.pack_into("<H", buf, 62, 1)  # shstrndx
    return bytes(buf)


class ElfTempMixin(unittest.TestCase):
    def write(self, data: bytes, name: str = "test.elf") -> str:
        directory = tempfile.mkdtemp(prefix="elf-test-")
        self.addCleanup(
            lambda d=directory: __import__("shutil").rmtree(d, ignore_errors=True))
        path = os.path.join(directory, name)
        with open(path, "wb") as fh:
            fh.write(data)
        return path


class TestClassifier(ElfTempMixin):
    def classify(self, path: str, system: str = "x86_64-linux"):
        info = C.read_elf(path)
        self.assertIsNotNone(info)
        return C.classify(info, system)

    def test_host_program_with_interpreter_is_patched_fully(self):
        path = self.write(build_elf(needed=[b"libc.so.6"]))
        result = self.classify(path)
        self.assertEqual(result.kind, "host-glibc-program")
        self.assertEqual(result.action, C.Action.PATCH_INTERP_AND_RUNPATH)

    def test_host_library_gets_runpath_only(self):
        path = self.write(build_elf(interp=None, needed=[b"libc.so.6"]))
        result = self.classify(path)
        self.assertEqual(result.kind, "host-glibc-library")
        self.assertEqual(result.action, C.Action.PATCH_RUNPATH)

    def test_static_binary_is_left_alone(self):
        path = self.write(build_elf(interp=None, needed=[]))
        result = self.classify(path)
        self.assertEqual(result.kind, "static")
        self.assertEqual(result.action, C.Action.LEAVE_ALONE)

    def test_musl_prebuild_is_left_alone(self):
        path = self.write(build_elf(
            interp=None, needed=[b"libc.musl-x86_64.so.1", b"libstdc++.so.6"]))
        result = self.classify(path)
        self.assertEqual(result.kind, "musl-prebuild")
        self.assertEqual(result.action, C.Action.LEAVE_ALONE)

    def test_android_prebuild_is_detected_by_its_note(self):
        path = self.write(build_elf(
            interp=None, needed=[b"libm.so"], android_note=True))
        result = self.classify(path)
        self.assertEqual(result.kind, "android-prebuild")

    def test_android_prebuild_is_detected_by_bionic_sonames(self):
        # An Android aarch64 prebuild has the same e_machine as a native one on
        # an aarch64 host, so the soname test is what keeps them apart.
        path = self.write(build_elf(
            machine=0xB7, interp=None,
            needed=[b"liblog.so", b"libc++_shared.so", b"libc.so"]))
        result = self.classify(path, system="aarch64-linux")
        self.assertEqual(result.kind, "android-prebuild")
        self.assertEqual(result.action, C.Action.LEAVE_ALONE)

    def test_musl_executable_is_detected_from_its_interpreter(self):
        """A musl executable names musl in PT_INTERP, not in DT_NEEDED.

        Checking only DT_NEEDED would classify it as a host program and give it
        a glibc interpreter.
        """
        path = self.write(build_elf(
            interp=b"/lib/ld-musl-x86_64.so.1\0", needed=[b"libc.so"]))
        result = self.classify(path)
        self.assertEqual(result.kind, "musl-prebuild")
        self.assertEqual(result.action, C.Action.LEAVE_ALONE)

    def test_a_host_binary_linking_libcxx_shared_is_not_called_android(self):
        """Bionic sonames alone are not proof; glibc linkage outweighs them."""
        path = self.write(build_elf(
            interp=None,
            needed=[b"libc++_shared.so", b"libc.so.6", b"libpthread.so.0"]))
        result = self.classify(path)
        self.assertEqual(result.kind, "host-glibc-library")

    def test_a_real_android_prebuild_is_still_detected_by_sonames(self):
        path = self.write(build_elf(
            machine=0xB7, interp=None,
            needed=[b"liblog.so", b"libc++_shared.so", b"libc.so"]))
        self.assertEqual(
            self.classify(path, system="aarch64-linux").kind, "android-prebuild")

    def test_foreign_architecture_is_left_alone(self):
        path = self.write(build_elf(machine=0xB7, interp=None,
                                    needed=[b"libc.so.6"]))
        result = self.classify(path, system="x86_64-linux")
        self.assertEqual(result.kind, "foreign-architecture")

    def test_native_aarch64_on_aarch64_is_patched(self):
        path = self.write(build_elf(machine=0xB7, interp=None,
                                    needed=[b"libc.so.6"]))
        result = self.classify(path, system="aarch64-linux")
        self.assertEqual(result.kind, "host-glibc-library")

    def test_qt_shims_are_classified_and_never_linked(self):
        for name, lib in [("libqt5_shim.so", b"libQt5Core.so.5"),
                          ("libqt6_shim.so", b"libQt6Core.so.6")]:
            with self.subTest(name=name):
                path = self.write(
                    build_elf(interp=None, needed=[lib, b"libc.so.6"]), name)
                result = self.classify(path)
                self.assertEqual(result.kind, "optional-qt-shim")
                self.assertEqual(result.action, C.Action.LEAVE_ALONE)

    def test_non_elf_files_are_ignored(self):
        path = self.write(b"#!/bin/sh\necho hello\n", "script.sh")
        self.assertIsNone(C.read_elf(path))


class TestInventoryDrift(unittest.TestCase):
    def base(self):
        return {
            "system": "x86_64-linux",
            "counts": {"static": 1},
            "entries": [{
                "path": "a", "kind": "static", "action": "leave-alone",
                "machine": "x86_64", "etype": "DYN", "interp": None,
                "needed": [], "runpath": None,
            }],
        }

    def test_identical_inventories_agree(self):
        self.assertEqual(C.compare(self.base(), self.base()), [])

    def test_a_new_elf_file_is_reported(self):
        new = self.base()
        new["entries"].append(dict(new["entries"][0], path="b"))
        problems = C.compare(self.base(), new)
        self.assertTrue(any("NEW ELF file" in p for p in problems))

    def test_a_removed_file_is_reported(self):
        problems = C.compare(self.base(), {"system": "x", "counts": {},
                                           "entries": []})
        self.assertTrue(any("disappeared" in p for p in problems))

    def test_a_reclassified_file_is_reported(self):
        new = self.base()
        new["entries"][0]["kind"] = "host-glibc-library"
        new["entries"][0]["action"] = "patch-runpath"
        problems = C.compare(self.base(), new)
        self.assertTrue(any("kind changed" in p for p in problems))

    def test_changed_dependencies_are_reported(self):
        new = self.base()
        new["entries"][0]["needed"] = ["libnew.so.1"]
        problems = C.compare(self.base(), new)
        self.assertTrue(any("DT_NEEDED changed" in p for p in problems))


class TestDetectLibcSimulation(ElfTempMixin):
    def test_reports_glibc_for_an_in_window_interpreter(self):
        path = self.write(build_elf(interp_offset=736))
        self.assertEqual(R.simulate_detect_libc(path), "glibc")

    def test_reports_musl_for_a_musl_interpreter(self):
        path = self.write(build_elf(
            interp=b"/lib/ld-musl-x86_64.so.1\0", interp_offset=736))
        self.assertEqual(R.simulate_detect_libc(path), "musl")

    def test_returns_none_when_the_interpreter_is_out_of_window(self):
        # This is precisely the SIGILL condition.
        path = self.write(build_elf(interp_offset=6000, total_size=16384))
        self.assertIsNone(R.simulate_detect_libc(path))

    def test_returns_none_for_a_static_binary(self):
        path = self.write(build_elf(interp=None))
        self.assertIsNone(R.simulate_detect_libc(path))


class TestRelocation(ElfTempMixin):
    def test_moves_an_out_of_window_interpreter_back_in(self):
        long_interp = b"/nix/store/" + b"a" * 32 + b"-glibc-2.42-67/lib/ld-linux-x86-64.so.2\0"
        path = self.write(build_elf(
            interp=long_interp, interp_offset=6000, total_size=16384))
        self.assertIsNone(R.simulate_detect_libc(path))

        before = os.path.getsize(path)
        report = R.relocate(path, verbose=False)

        self.assertTrue(report["moved"])
        self.assertLessEqual(report["after_offset"] + report["after_size"], 2048)
        self.assertEqual(os.path.getsize(path), before,
                         "relocation must not change the file size")
        self.assertEqual(R.simulate_detect_libc(path), "glibc")

    def test_is_idempotent(self):
        long_interp = b"/nix/store/" + b"b" * 32 + b"-glibc/lib/ld-linux-x86-64.so.2\0"
        path = self.write(build_elf(
            interp=long_interp, interp_offset=6000, total_size=16384))
        first = R.relocate(path, verbose=False)
        second = R.relocate(path, verbose=False)
        self.assertTrue(first["moved"])
        self.assertFalse(second["moved"])
        self.assertEqual(first["after_offset"], second["after_offset"])

    def test_leaves_an_already_in_window_interpreter_untouched(self):
        path = self.write(build_elf(interp_offset=736))
        with open(path, "rb") as fh:
            before = fh.read()
        report = R.relocate(path, verbose=False)
        with open(path, "rb") as fh:
            self.assertEqual(fh.read(), before)
        self.assertFalse(report["moved"])

    def test_never_writes_into_a_section_claimed_range(self):
        """The bug that segfaulted the bundled Node.

        The gap after the program headers is full of plausible-looking filler,
        but a section header claims it. Writing there produces a file that
        passes every structural check and crashes at runtime, so the relocator
        must refuse instead.
        """
        long_interp = b"/nix/store/" + b"c" * 32 + b"-glibc/lib/ld-linux-x86-64.so.2\0"
        path = self.write(build_elf(
            interp=long_interp, interp_offset=6000, total_size=16384,
            filler=0x00,
            # A live section covering the entire window past the headers.
            extra_section_covering=(300, 1748),
        ))
        with self.assertRaises(R.RelocationError) as ctx:
            R.relocate(path, verbose=False)
        self.assertIn("unreferenced bytes", str(ctx.exception))
        self.assertIn("manual review", str(ctx.exception))

    def test_refusal_leaves_the_file_untouched(self):
        long_interp = b"/nix/store/" + b"d" * 32 + b"-glibc/lib/ld-linux-x86-64.so.2\0"
        path = self.write(build_elf(
            interp=long_interp, interp_offset=6000, total_size=16384,
            filler=0x00, extra_section_covering=(300, 1748)))
        with open(path, "rb") as fh:
            before = fh.read()
        with self.assertRaises(R.RelocationError):
            R.relocate(path, verbose=False)
        with open(path, "rb") as fh:
            self.assertEqual(fh.read(), before)

    def test_occupied_ranges_include_sections_and_tables(self):
        path = self.write(build_elf())
        elf = R.Elf64(path)
        ranges = R.occupied_ranges(elf)
        self.assertIn((0, 64), ranges)                       # ELF header
        self.assertIn((elf.e_phoff, elf.phdr_table_end), ranges)
        # The .interp section's own range must be claimed.
        self.assertTrue(any(s == 736 for s, _ in ranges))

    def test_refuses_a_binary_with_no_section_headers(self):
        """Without section headers nothing can be proven unreferenced.

        A stripped binary would otherwise look almost entirely free, which is
        the same corruption the section-header check exists to prevent.
        """
        long_interp = b"/nix/store/" + b"e" * 32 + b"-glibc/lib/ld-linux-x86-64.so.2\0"
        data = bytearray(build_elf(
            interp=long_interp, interp_offset=6000, total_size=16384))
        struct.pack_into("<Q", data, 40, 0)   # e_shoff = 0
        struct.pack_into("<HH", data, 58, 64, 0)  # e_shnum = 0
        path = self.write(bytes(data))

        with self.assertRaises(R.RelocationError) as ctx:
            R.relocate(path, verbose=False)
        self.assertIn("no section headers", str(ctx.exception))

    def test_a_failed_relocation_leaves_no_partial_file(self):
        """Validation happens on a staged copy, never on the original.

        The caller treats a relocation failure as 'not relocated' and carries
        on, so a half-written original would be shipped rather than caught.
        """
        long_interp = b"/nix/store/" + b"f" * 32 + b"-glibc/lib/ld-linux-x86-64.so.2\0"
        path = self.write(build_elf(
            interp=long_interp, interp_offset=6000, total_size=16384,
            filler=0x00, extra_section_covering=(300, 1748)))
        with open(path, "rb") as fh:
            before = fh.read()

        with self.assertRaises(R.RelocationError):
            R.relocate(path, verbose=False)

        with open(path, "rb") as fh:
            self.assertEqual(fh.read(), before)
        directory = os.path.dirname(path)
        self.assertEqual(
            [f for f in os.listdir(directory) if f.endswith(".interp-tmp")], [],
            "a staging file was left behind",
        )

    def test_assert_within_window_rejects_an_out_of_window_binary(self):
        path = self.write(build_elf(interp_offset=6000, total_size=16384))
        elf = R.Elf64(path)
        with self.assertRaises(R.RelocationError) as ctx:
            R.assert_within_window(elf, R.DETECT_LIBC_WINDOW, "test")
        self.assertIn("detect-libc", str(ctx.exception))


class TestSegmentProtection(ElfTempMixin):
    """File-backed segments the section table does not describe are still live.

    PT_LOAD is a mapping container and must not be treated as occupied — the
    gap we want is inside one. Every other file-backed segment points at one
    specific structure, and a payload can legitimately carry one with a
    zero-valued body and no section header. A GNU-property region shaped
    exactly like that was selected as free and overwritten.
    """

    def build_with_segment(self, p_type: int, size: int = 128):
        long_interp = (b"/nix/store/" + b"z" * 32 +
                       b"-glibc/lib/ld-linux-x86-64.so.2\0")
        data = bytearray(build_elf(interp=long_interp, interp_offset=6000,
                                   total_size=16384, filler=0x58))
        e_phnum = struct.unpack_from("<H", data, 56)[0]
        base = 64 + e_phnum * 56
        offset = ((64 + (e_phnum + 1) * 56) + 7) & ~7
        struct.pack_into("<II", data, base, p_type, 4)
        struct.pack_into("<QQQ", data, base + 8, offset, offset, offset)
        struct.pack_into("<QQQ", data, base + 32, size, size, 8)
        struct.pack_into("<H", data, 56, e_phnum + 1)
        data[offset:offset + size] = b"\x00" * size
        return self.write(bytes(data)), offset, size

    def test_a_zero_valued_gnu_property_region_is_not_overwritten(self):
        path, offset, size = self.build_with_segment(0x6474E553)
        R.relocate(path, verbose=False)
        with open(path, "rb") as fh:
            fh.seek(offset)
            self.assertEqual(fh.read(size), b"\x00" * size,
                             "PT_GNU_PROPERTY data was overwritten")

    def test_note_dynamic_and_tls_regions_are_protected(self):
        for p_type, label in [(4, "PT_NOTE"), (2, "PT_DYNAMIC"), (7, "PT_TLS")]:
            with self.subTest(segment=label):
                path, offset, size = self.build_with_segment(p_type)
                R.relocate(path, verbose=False)
                with open(path, "rb") as fh:
                    fh.seek(offset)
                    self.assertEqual(fh.read(size), b"\x00" * size,
                                     f"{label} data was overwritten")

    def test_pt_load_is_still_treated_as_a_container(self):
        # If PT_LOAD were counted as occupied, no relocation could ever happen.
        long_interp = (b"/nix/store/" + b"y" * 32 +
                       b"-glibc/lib/ld-linux-x86-64.so.2\0")
        path = self.write(build_elf(interp=long_interp, interp_offset=6000,
                                    total_size=16384))
        report = R.relocate(path, verbose=False)
        self.assertTrue(report["moved"])


class TestMalformedElfIsRefused(ElfTempMixin):
    def test_a_duplicate_pt_interp_is_refused(self):
        long_interp = (b"/nix/store/" + b"w" * 32 +
                       b"-glibc/lib/ld-linux-x86-64.so.2\0")
        data = bytearray(build_elf(interp=long_interp, interp_offset=6000,
                                   total_size=16384))
        e_phnum = struct.unpack_from("<H", data, 56)[0]
        base = 64 + e_phnum * 56
        struct.pack_into("<II", data, base, 3, 4)          # a second PT_INTERP
        struct.pack_into("<QQQ", data, base + 8, 6000, 6000, 6000)
        struct.pack_into("<QQQ", data, base + 32, len(long_interp),
                         len(long_interp), 1)
        struct.pack_into("<H", data, 56, e_phnum + 1)
        path = self.write(bytes(data))
        with self.assertRaises(R.RelocationError) as ctx:
            R.relocate(path, verbose=False)
        self.assertIn("PT_INTERP segments", str(ctx.exception))

    def test_a_segment_running_past_the_file_is_refused(self):
        data = bytearray(build_elf(total_size=8192))
        e_phnum = struct.unpack_from("<H", data, 56)[0]
        base = 64 + e_phnum * 56
        struct.pack_into("<II", data, base, 4, 4)
        struct.pack_into("<QQQ", data, base + 8, 8000, 8000, 8000)
        struct.pack_into("<QQQ", data, base + 32, 100000, 100000, 4)
        struct.pack_into("<H", data, 56, e_phnum + 1)
        path = self.write(bytes(data))
        with self.assertRaises(R.RelocationError) as ctx:
            R.relocate(path, verbose=False)
        self.assertIn("past the", str(ctx.exception))

    def test_a_program_header_table_past_the_file_is_refused(self):
        data = bytearray(build_elf())
        struct.pack_into("<H", data, 56, 4000)   # absurd phnum
        path = self.write(bytes(data))
        with self.assertRaises(R.RelocationError) as ctx:
            R.relocate(path, verbose=False)
        self.assertIn("past end of file", str(ctx.exception))

    def test_a_section_header_table_past_the_file_is_refused(self):
        data = bytearray(build_elf())
        struct.pack_into("<Q", data, 40, 900000)   # e_shoff beyond the file
        path = self.write(bytes(data))
        with self.assertRaises(R.RelocationError) as ctx:
            R.relocate(path, verbose=False)
        self.assertIn("past end of file", str(ctx.exception))


class TestRunpathMerging(unittest.TestCase):
    def setUp(self):
        import patch_elves
        self.merge = patch_elves.merged_runpath

    def test_origin_entries_stay_first(self):
        merged = self.merge("$ORIGIN/../lib:$ORIGIN/x", "/nix/store/a/lib")
        self.assertTrue(merged.startswith("$ORIGIN/../lib:$ORIGIN/x:"))
        self.assertIn("/nix/store/a/lib", merged)

    def test_our_paths_are_added_when_there_is_no_existing_runpath(self):
        self.assertEqual(self.merge("", "/nix/store/a/lib"), "/nix/store/a/lib")

    def test_duplicates_are_collapsed(self):
        merged = self.merge("/nix/store/a/lib", "/nix/store/a/lib:/b")
        self.assertEqual(merged, "/nix/store/a/lib:/b")

    def test_non_origin_existing_entries_are_kept_last(self):
        merged = self.merge("$ORIGIN/a:/opt/legacy", "/nix/store/x")
        self.assertEqual(merged, "$ORIGIN/a:/nix/store/x:/opt/legacy")

    def test_the_braced_origin_form_is_also_kept_first(self):
        # "${ORIGIN}/../lib" is as valid as "$ORIGIN/../lib"; demoting it would
        # let a store library shadow a bundled one.
        merged = self.merge("${ORIGIN}/../lib:/opt/legacy", "/nix/store/x")
        self.assertEqual(merged, "${ORIGIN}/../lib:/nix/store/x:/opt/legacy")


if __name__ == "__main__":
    unittest.main()


class TestRegionInvariant(ElfTempMixin):
    """The target region is proven, not inferred.

    "No section header claims these bytes" is a negative inference: section
    headers are advisory at run time and a file may be stripped or hand-made,
    so their silence proves nothing. The relocator instead requires the binary
    to match a reviewed description of where patchelf's vacated space is.
    """

    def build(self, filler=0x58):
        long_interp = (b"/nix/store/" + b"q" * 32 +
                       b"-glibc/lib/ld-linux-x86-64.so.2\0")
        return self.write(build_elf(interp=long_interp, interp_offset=6000,
                                    total_size=16384, filler=filler))

    def test_a_matching_invariant_permits_relocation(self):
        path = self.build()
        region = R.describe_target_region(R.Elf64(path))
        report = R.relocate(path, verbose=False, expect_region=region)
        self.assertTrue(report["moved"])

    def test_each_pinned_property_is_load_bearing(self):
        import copy
        base = R.describe_target_region(R.Elf64(self.build()))
        mutations = {
            "phnum": lambda r: r["elfHeader"].__setitem__("phnum", 99),
            "phoff": lambda r: r["elfHeader"].__setitem__("phoff", 128),
            "filler start": lambda r: r.__setitem__("fillerStart", 4096),
            "filler length": lambda r: r.__setitem__("fillerLength", 10 ** 9),
            "filler byte": lambda r: r.__setitem__("fillerByte", 0),
            "PT_INTERP count": lambda r: r.__setitem__("interpSegments", 7),
            "load offset": lambda r: r["containingLoad"].__setitem__(
                "p_offset", 4096),
            "load flags": lambda r: r["containingLoad"].__setitem__(
                "p_flags", 7),
            "load align": lambda r: r["containingLoad"].__setitem__(
                "p_align", 3),
        }
        for label, mutate in mutations.items():
            with self.subTest(pinned=label):
                bad = copy.deepcopy(base)
                mutate(bad)
                with self.assertRaises(R.RelocationError) as ctx:
                    R.relocate(self.build(), verbose=False, expect_region=bad)
                self.assertIn("invariant no longer holds", str(ctx.exception))

    def test_the_search_window_never_grows_past_the_reviewed_extent(self):
        # A longer filler run than recorded is legitimate -- a bigger store
        # path vacates more -- and is accepted. But the tuple this returns
        # becomes the trusted search window, and searching bytes nobody
        # reviewed defeats the point of pinning a region at all. The reviewed
        # length is what was established; clamp to it.
        path = self.build()
        elf = R.Elf64(path)
        region = R.describe_target_region(elf)
        shrunk = copy.deepcopy(region)
        shrunk["fillerLength"] = region["fillerLength"] // 2
        self.assertGreater(region["fillerLength"], shrunk["fillerLength"])

        start, length = R.assert_region_invariant(elf, shrunk)
        self.assertEqual(start, region["fillerStart"])
        self.assertEqual(
            length, shrunk["fillerLength"],
            "the search window grew past the reviewed extent")

    def test_a_shorter_run_than_reviewed_is_still_refused(self):
        # Clamping must not turn the shortness check into a no-op: a run
        # shorter than reviewed means patchelf laid the file out differently.
        path = self.build()
        elf = R.Elf64(path)
        grown = copy.deepcopy(R.describe_target_region(elf))
        grown["fillerLength"] += 10 ** 6
        with self.assertRaises(R.RelocationError) as ctx:
            R.assert_region_invariant(elf, grown)
        self.assertIn("shorter than the reviewed", str(ctx.exception))

    def test_a_reviewed_region_with_no_filler_length_is_refused(self):
        # Without this the clamp would silently produce an empty search window
        # and relocation would fail with a confusing "no free range" error
        # rather than saying the committed invariant is incomplete.
        path = self.build()
        elf = R.Elf64(path)
        region = copy.deepcopy(R.describe_target_region(elf))
        del region["fillerLength"]
        with self.assertRaises(R.RelocationError) as ctx:
            R.assert_region_invariant(elf, region)
        self.assertIn("no filler length", str(ctx.exception))

    def test_zero_padding_is_no_longer_treated_as_filler(self):
        # A zero byte is not evidence of anything; only patchelf's own 0x58 is.
        self.assertNotIn(0x00, R.FILLER_BYTES)
        self.assertEqual(R.FILLER_BYTES, frozenset({0x58}))
        path = self.build(filler=0x00)
        with self.assertRaises(R.RelocationError):
            R.relocate(path, verbose=False)


class TestStructuralValidation(ElfTempMixin):
    def test_a_section_running_past_the_file_is_refused(self):
        data = bytearray(build_elf())
        # Inflate the .shstrtab section's size well past the file.
        e_shoff = struct.unpack_from("<Q", data, 40)[0]
        struct.pack_into("<Q", data, e_shoff + 64 + 32, 10 ** 9)
        path = self.write(bytes(data))
        with self.assertRaises(R.RelocationError) as ctx:
            R.Elf64(path).validate_sections()
        self.assertRegex(str(ctx.exception), "past the|past end of file")

    def test_an_out_of_range_section_name_offset_is_refused(self):
        data = bytearray(build_elf())
        e_shoff = struct.unpack_from("<Q", data, 40)[0]
        struct.pack_into("<I", data, e_shoff + 64, 10 ** 6)   # sh_name
        path = self.write(bytes(data))
        with self.assertRaises(R.RelocationError) as ctx:
            R.Elf64(path).validate_sections()
        self.assertIn("name table", str(ctx.exception))

    def test_a_section_overlapping_the_program_header_table_is_refused(self):
        # occupied_ranges() is built from the section table and is what proves
        # a byte range is unclaimed. A table that puts a section on top of the
        # program headers is structurally impossible, and accepting it makes
        # that proof worthless.
        data = bytearray(build_elf())
        e_shoff = struct.unpack_from("<Q", data, 40)[0]
        base = e_shoff + 64
        struct.pack_into("<I", data, base + 4, 1)      # SHT_PROGBITS
        struct.pack_into("<Q", data, base + 24, 64)    # sh_offset -> the PHT
        struct.pack_into("<Q", data, base + 32, 300)   # sh_size
        path = self.write(bytes(data))
        with self.assertRaises(R.RelocationError) as ctx:
            R.Elf64(path).validate_sections()
        self.assertIn("overlap", str(ctx.exception))
        self.assertIn("program header table", str(ctx.exception))

    def test_two_overlapping_sections_are_refused(self):
        data = bytearray(build_elf())
        e_shoff = struct.unpack_from("<Q", data, 40)[0]
        for index, (off, size) in enumerate(((2048, 512), (2200, 512)), start=1):
            base = e_shoff + 64 * index
            struct.pack_into("<I", data, base + 4, 1)
            struct.pack_into("<Q", data, base + 24, off)
            struct.pack_into("<Q", data, base + 32, size)
        path = self.write(bytes(data))
        with self.assertRaises(R.RelocationError) as ctx:
            R.Elf64(path).validate_sections()
        self.assertIn("overlap", str(ctx.exception))

    def test_a_section_overlapping_the_elf_header_is_refused(self):
        data = bytearray(build_elf())
        e_shoff = struct.unpack_from("<Q", data, 40)[0]
        base = e_shoff + 64
        struct.pack_into("<I", data, base + 4, 1)
        struct.pack_into("<Q", data, base + 24, 0)
        struct.pack_into("<Q", data, base + 32, 32)
        path = self.write(bytes(data))
        with self.assertRaises(R.RelocationError) as ctx:
            R.Elf64(path).validate_sections()
        self.assertIn("ELF header", str(ctx.exception))

    def test_a_well_formed_file_is_still_accepted(self):
        # The overlap rule must not reject ordinary binaries.
        R.Elf64(self.write(build_elf())).validate_sections()

    def test_the_classifier_refuses_a_truncated_program_header_table(self):
        data = bytearray(build_elf())
        struct.pack_into("<H", data, 56, 500)      # absurd phnum
        path = self.write(bytes(data))
        with self.assertRaises(C.ElfError) as ctx:
            C.read_elf(path)
        self.assertIn("past the", str(ctx.exception))

    def test_the_classifier_refuses_a_segment_past_the_file(self):
        data = bytearray(build_elf())
        e_phnum = struct.unpack_from("<H", data, 56)[0]
        base = 64 + e_phnum * 56
        struct.pack_into("<II", data, base, 4, 4)
        struct.pack_into("<QQQ", data, base + 8, 8000, 8000, 8000)
        struct.pack_into("<QQQ", data, base + 32, 10 ** 9, 10 ** 9, 4)
        struct.pack_into("<H", data, 56, e_phnum + 1)
        path = self.write(bytes(data))
        with self.assertRaises(C.ElfError):
            C.read_elf(path)
