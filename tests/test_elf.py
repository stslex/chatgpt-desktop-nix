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

    def test_assert_within_window_rejects_an_out_of_window_binary(self):
        path = self.write(build_elf(interp_offset=6000, total_size=16384))
        elf = R.Elf64(path)
        with self.assertRaises(R.RelocationError) as ctx:
            R.assert_within_window(elf, R.DETECT_LIBC_WINDOW, "test")
        self.assertIn("detect-libc", str(ctx.exception))


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


if __name__ == "__main__":
    unittest.main()
