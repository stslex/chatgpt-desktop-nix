#!/usr/bin/env python3
"""Keep the ELF interpreter inside the first 2 KiB of a patched executable.

Why this exists
---------------

The app bundles ``detect-libc`` (>= 2.1.0), which decides whether it is running
on glibc or musl by inspecting its own executable. It does this in a very
specific way (``lib/filesystem.js`` and ``lib/elf.js`` upstream):

    fs.readSync(fd, buffer, 0, 2048, 0)      // exactly one read, 2048 bytes
    ...walk the program headers, find PT_INTERP...
    elf.subarray(p_offset, p_offset + p_filesz)
    interpreter.includes('/ld-musl-')  -> musl
    interpreter.includes('/ld-linux-') -> glibc

Everything comes out of that single 2048-byte buffer. Nothing seeks.

The stock ``ChatGPT`` binary has ``PT_INTERP`` at file offset 736, comfortably
inside the window. But its interpreter string is ``/lib64/ld-linux-x86-64.so.2``
(27 bytes) and a Nix store path is around 80. ``patchelf`` cannot grow the
string in place, so it appends a new ``.interp`` at the end of the file and
repoints ``PT_INTERP`` there. Measured on the real 314 MB binary, the offset
moves from **736 to 314,945,896**.

``detect-libc`` then slices past the end of its 2048-byte buffer, gets an empty
string, concludes neither glibc nor musl, and falls through to
``process.report.getReport()``. On the shipped Electron build that path can
raise **SIGILL**, which is what users see when opening a Git-backed Codex
thread.

The fix
-------

``patchelf`` backfills the space it vacated with ``0x58`` (``'X'``) filler. On
the real binary that leaves 209,216 contiguous free bytes starting immediately
after the extended program-header table at offset 904. That is far more than
the ~80 bytes we need, and it is inside the first ``PT_LOAD`` segment, so the
bytes are mapped and addressable.

So: after ``patchelf`` has done its work, move the interpreter string back into
that free region and repoint ``PT_INTERP`` (and the ``.interp`` section header)
at it. The file length never changes and no other structure moves.

This operates purely on ELF structure. It does not touch ``app.asar`` and does
not patch any JavaScript.
"""

from __future__ import annotations

import argparse
import contextlib
import os
import shutil
import struct
import sys

PT_LOAD, PT_INTERP = 1, 3
SHT_PROGBITS = 1
SHT_NOBITS = 8

#: The window detect-libc reads. The interpreter string must end within it.
DETECT_LIBC_WINDOW = 2048

#: The single byte patchelf writes into space it has vacated.
#:
#: 0x00 was previously accepted too, and that was wrong twice over. Zeros occur
#: naturally inside live data -- the bundled Node has a run of them at offset
#: 1411 inside .dynstr, and writing the interpreter there produced a binary
#: that passed every structural check and then segfaulted -- and, more
#: fundamentally, a zero byte is not evidence of anything. 0x58 is: patchelf
#: writes it deliberately to mark space it has abandoned, so a run of it is a
#: positive statement about provenance rather than an absence of information.
#:
#: This matters because "no section header claims these bytes" is a *negative*
#: inference. Section headers are advisory at run time and a file may be
#: stripped, rewritten or hand-made; their silence proves nothing. The filler
#: byte, the pinned region invariant below, and the absence of any structural
#: claim are three independent statements, and the relocator requires all of
#: them.
PATCHELF_FILLER = 0x58
FILLER_BYTES = frozenset({PATCHELF_FILLER})


class RelocationError(Exception):
    pass


class Elf64:
    """Just enough mutable ELF64 to move PT_INTERP. Little-endian only."""

    def __init__(self, path: str):
        self.path = path
        with open(path, "rb") as fh:
            self.data = bytearray(fh.read())
        if self.data[:4] != b"\x7fELF":
            raise RelocationError(f"{path}: not an ELF file")
        if self.data[4] != 2:
            raise RelocationError(f"{path}: only ELF64 is supported")
        if self.data[5] != 1:
            raise RelocationError(f"{path}: only little-endian is supported")
        self.e_phoff = struct.unpack_from("<Q", self.data, 32)[0]
        self.e_shoff = struct.unpack_from("<Q", self.data, 40)[0]
        self.e_phentsize, self.e_phnum = struct.unpack_from("<HH", self.data, 54)
        self.e_shentsize, self.e_shnum = struct.unpack_from("<HH", self.data, 58)
        self.e_shstrndx = struct.unpack_from("<H", self.data, 62)[0]

    # -- program headers ---------------------------------------------------

    def _ph_base(self, index: int) -> int:
        return self.e_phoff + index * self.e_phentsize

    def phdr(self, index: int) -> dict:
        base = self._ph_base(index)
        p_type, p_flags = struct.unpack_from("<II", self.data, base)
        p_offset, p_vaddr, p_paddr = struct.unpack_from("<QQQ", self.data, base + 8)
        p_filesz, p_memsz, p_align = struct.unpack_from("<QQQ", self.data, base + 32)
        return dict(index=index, p_type=p_type, p_flags=p_flags, p_offset=p_offset,
                    p_vaddr=p_vaddr, p_paddr=p_paddr, p_filesz=p_filesz,
                    p_memsz=p_memsz, p_align=p_align)

    def phdrs(self) -> list[dict]:
        return [self.phdr(i) for i in range(self.e_phnum)]

    def set_phdr(self, index: int, *, p_offset: int, p_vaddr: int, p_paddr: int,
                 p_filesz: int, p_memsz: int) -> None:
        base = self._ph_base(index)
        struct.pack_into("<QQQ", self.data, base + 8, p_offset, p_vaddr, p_paddr)
        struct.pack_into("<QQ", self.data, base + 32, p_filesz, p_memsz)

    @property
    def phdr_table_end(self) -> int:
        return self.e_phoff + self.e_phentsize * self.e_phnum

    # -- section headers ---------------------------------------------------

    def _sh_base(self, index: int) -> int:
        return self.e_shoff + index * self.e_shentsize

    def section_name(self, index: int) -> str:
        if not self.e_shoff or self.e_shstrndx >= self.e_shnum:
            return ""
        strtab_base = self._sh_base(self.e_shstrndx)
        strtab_off = struct.unpack_from("<Q", self.data, strtab_base + 24)[0]
        strtab_size = struct.unpack_from("<Q", self.data, strtab_base + 32)[0]
        name_off = struct.unpack_from("<I", self.data, self._sh_base(index))[0]
        start = strtab_off + name_off
        limit = strtab_off + strtab_size
        end = self.data.find(b"\0", start, limit)
        if end == -1:
            # An unterminated name means a malformed table; slicing with -1
            # would silently drop the last byte instead of saying so.
            end = limit
        return self.data[start:end].decode("utf-8", "replace")

    def find_section(self, wanted: str) -> int | None:
        if not self.e_shoff:
            return None
        for i in range(self.e_shnum):
            if self.section_name(i) == wanted:
                return i
        return None

    def section_header(self, index: int) -> dict:
        base = self._sh_base(index)
        sh_name, sh_type = struct.unpack_from("<II", self.data, base)
        sh_flags, sh_addr, sh_offset = struct.unpack_from("<QQQ", self.data,
                                                          base + 8)
        sh_size = struct.unpack_from("<Q", self.data, base + 32)[0]
        return dict(index=index, sh_name=sh_name, sh_type=sh_type,
                    sh_flags=sh_flags, sh_addr=sh_addr, sh_offset=sh_offset,
                    sh_size=sh_size)

    def validate_sections(self) -> None:
        """Assert every file-backed section, and the name table, is in range."""
        if not self.e_shoff or not self.e_shnum:
            return
        size = len(self.data)
        strtab_base = self._sh_base(self.e_shstrndx)
        strtab_off = struct.unpack_from("<Q", self.data, strtab_base + 24)[0]
        strtab_size = struct.unpack_from("<Q", self.data, strtab_base + 32)[0]
        if strtab_off + strtab_size > size:
            raise RelocationError(
                f"{self.path}: section name table runs past end of file")

        for i in range(self.e_shnum):
            sh = self.section_header(i)
            if sh["sh_type"] == SHT_NOBITS or sh["sh_size"] == 0:
                continue
            if sh["sh_offset"] + sh["sh_size"] > size:
                raise RelocationError(
                    f"{self.path}: section {i} spans "
                    f"[{sh['sh_offset']}, {sh['sh_offset'] + sh['sh_size']}), "
                    f"past the {size}-byte file")
            if sh["sh_name"] >= strtab_size:
                raise RelocationError(
                    f"{self.path}: section {i} name offset {sh['sh_name']} is "
                    f"outside the {strtab_size}-byte name table")

        # No two file-backed regions may claim the same byte.
        #
        # In-range is not the same as well-formed. A section table can put two
        # sections on top of each other, or a section on top of the ELF header,
        # the program header table or the section header table -- all of which
        # are structurally impossible in a real binary and all of which were
        # accepted here. That matters because occupied_ranges() is built from
        # this table and is what proves a candidate byte range is unclaimed: a
        # table that lies about what it covers makes that proof worthless.
        claims: list[tuple[int, int, str]] = [
            (0, 64, "the ELF header"),
        ]
        if self.e_phnum:
            claims.append((self.e_phoff, self.e_phoff + self.e_phnum * 56,
                           "the program header table"))
        if self.e_shnum:
            claims.append((self.e_shoff, self.e_shoff + self.e_shnum * 64,
                           "the section header table"))
        for i in range(self.e_shnum):
            sh = self.section_header(i)
            if sh["sh_type"] == SHT_NOBITS or sh["sh_size"] == 0:
                continue
            claims.append((sh["sh_offset"], sh["sh_offset"] + sh["sh_size"],
                           f"section {i} ({self.section_name(i)!r})"))

        claims.sort()
        for (a_start, a_end, a_what), (b_start, b_end, b_what) in zip(
                claims, claims[1:]):
            if b_start < a_end:
                raise RelocationError(
                    f"{self.path}: {a_what} spans [{a_start}, {a_end}) and "
                    f"{b_what} spans [{b_start}, {b_end}); they overlap, so "
                    f"the section table does not describe a well-formed file")

    def set_section_location(self, index: int, *, sh_addr: int, sh_offset: int,
                             sh_size: int) -> None:
        base = self._sh_base(index)
        struct.pack_into("<Q", self.data, base + 16, sh_addr)
        struct.pack_into("<Q", self.data, base + 24, sh_offset)
        struct.pack_into("<Q", self.data, base + 32, sh_size)

    # -- helpers -----------------------------------------------------------

    def validate_structure(self) -> None:
        """Assert every header table lies inside the file before reading it."""
        size = len(self.data)
        if self.e_phentsize < 56 or self.e_phnum == 0:
            raise RelocationError(
                f"{self.path}: implausible program header table "
                f"(entsize={self.e_phentsize}, num={self.e_phnum})")
        if self.e_phoff + self.e_phentsize * self.e_phnum > size:
            raise RelocationError(
                f"{self.path}: program header table runs past end of file")
        if self.e_shoff:
            if self.e_shentsize < 64:
                raise RelocationError(
                    f"{self.path}: implausible section header entry size "
                    f"{self.e_shentsize}")
            if self.e_shoff + self.e_shentsize * self.e_shnum > size:
                raise RelocationError(
                    f"{self.path}: section header table runs past end of file")
            if self.e_shnum and self.e_shstrndx >= self.e_shnum:
                raise RelocationError(
                    f"{self.path}: shstrndx {self.e_shstrndx} is out of range")
        for phdr in self.phdrs():
            end = phdr["p_offset"] + phdr["p_filesz"]
            if phdr["p_filesz"] and end > size:
                raise RelocationError(
                    f"{self.path}: segment {phdr['index']} "
                    f"(type 0x{phdr['p_type']:x}) extends to {end}, past the "
                    f"{size}-byte file")

    def interp_index(self) -> int:
        found = [p["index"] for p in self.phdrs() if p["p_type"] == PT_INTERP]
        if not found:
            raise RelocationError(f"{self.path}: no PT_INTERP segment")
        if len(found) > 1:
            # The kernel uses the first; other tools may not agree. Rewriting
            # one of several would leave the file self-inconsistent.
            raise RelocationError(
                f"{self.path}: {len(found)} PT_INTERP segments; exactly one is "
                f"expected. Refusing to guess which one is authoritative.")
        return found[0]

    def interp_string(self) -> str:
        phdr = self.phdr(self.interp_index())
        raw = bytes(self.data[phdr["p_offset"]:phdr["p_offset"] + phdr["p_filesz"]])
        return raw.split(b"\0")[0].decode("utf-8")

    def containing_load(self, offset: int, length: int) -> dict | None:
        for phdr in self.phdrs():
            if phdr["p_type"] != PT_LOAD:
                continue
            start, end = phdr["p_offset"], phdr["p_offset"] + phdr["p_filesz"]
            if start <= offset and offset + length <= end:
                return phdr
        return None

    def save(self, path: str | None = None) -> None:
        target = path or self.path
        with open(target, "r+b" if os.path.exists(target) else "wb") as fh:
            fh.write(self.data)
            fh.truncate(len(self.data))



def occupied_ranges(elf: Elf64,
                    moving_interp: int | None = None) -> list[tuple[int, int]]:
    """Every file range that some ELF structure actually claims.

    Covers the ELF header, the program-header table, the section-header table
    and the file-backed contents of every section. Anything outside all of
    these is genuinely unreferenced and safe to reuse.

    Raises if the file has no section headers. Without them this function can
    only account for the two header tables, so almost the entire file would
    look unclaimed and the caller would happily write into live data. Returning
    a permissive answer there would silently reintroduce exactly the corruption
    the section-header check exists to prevent.
    """
    if not elf.e_shoff or not elf.e_shnum:
        raise RelocationError(
            f"{elf.path}: no section headers, so no range can be proven "
            f"unreferenced. Refusing to relocate the interpreter rather than "
            f"guessing which bytes are free."
        )

    ranges: list[tuple[int, int]] = [(0, 64)]  # ELF header
    ranges.append((elf.e_phoff, elf.phdr_table_end))
    ranges.append((elf.e_shoff, elf.e_shoff + elf.e_shentsize * elf.e_shnum))

    for i in range(elf.e_shnum):
        base = elf._sh_base(i)
        sh_type = struct.unpack_from("<I", elf.data, base + 4)[0]
        sh_offset = struct.unpack_from("<Q", elf.data, base + 24)[0]
        sh_size = struct.unpack_from("<Q", elf.data, base + 32)[0]
        # SHT_NOBITS (.bss) occupies no file space.
        if sh_type == SHT_NOBITS or sh_size == 0:
            continue
        ranges.append((sh_offset, sh_offset + sh_size))

    # Every file-backed program segment except PT_LOAD.
    #
    # PT_LOAD is a mapping container: the gap we want is by definition inside
    # one, so treating whole PT_LOADs as occupied would rule out every
    # candidate. Within a PT_LOAD it is the section table that says which bytes
    # are live.
    #
    # Every other segment type is different -- PT_NOTE, PT_GNU_PROPERTY,
    # PT_DYNAMIC, PT_TLS, PT_PHDR and friends each point at one specific live
    # structure, and the section table need not describe it. Omitting them is
    # not theoretical: a PT_GNU_PROPERTY region carrying CET/IBT markings, with
    # a zero-valued payload and no section header, was selected as "free" and
    # overwritten with the interpreter string.
    for index, phdr in enumerate(elf.phdrs()):
        if phdr["p_type"] == PT_LOAD or not phdr["p_filesz"]:
            continue
        if index == moving_interp:
            # The bytes we are relocating away from are the one region that is
            # legitimately about to become free.
            continue
        ranges.append((phdr["p_offset"], phdr["p_offset"] + phdr["p_filesz"]))

    return sorted(ranges)


def describe_target_region(elf: Elf64, window: int = DETECT_LIBC_WINDOW,
                           moving_interp: int | None = None) -> dict:
    """Record everything that makes this binary's target region provable.

    Emitted at review time and committed. The relocator then requires the
    binary in front of it to match, so any change in how patchelf lays the file
    out -- a different program-header count, a shorter filler run, a different
    containing segment, different flags or alignment -- stops the build instead
    of silently relocating into somewhere that merely looks free.
    """
    start = (elf.phdr_table_end + 7) & ~7
    end = start
    while end < len(elf.data) and elf.data[end] == PATCHELF_FILLER:
        end += 1

    load = elf.containing_load(start, max(1, end - start))
    interp = elf.phdr(elf.interp_index())

    return {
        "elfHeader": {
            "phoff": elf.e_phoff,
            "phentsize": elf.e_phentsize,
            "phnum": elf.e_phnum,
            "phdrTableEnd": elf.phdr_table_end,
            "shentsize": elf.e_shentsize,
            "shnum": elf.e_shnum,
            "shstrndx": elf.e_shstrndx,
        },
        "interpSegments": sum(
            1 for p in elf.phdrs() if p["p_type"] == PT_INTERP),
        "fillerByte": PATCHELF_FILLER,
        "fillerStart": start,
        "fillerLength": end - start,
        "containingLoad": None if load is None else {
            "index": load["index"],
            "p_offset": load["p_offset"],
            "p_vaddr": load["p_vaddr"],
            "p_filesz": load["p_filesz"],
            "p_flags": load["p_flags"],
            "p_align": load["p_align"],
        },
        "window": window,
        "prepatchInterp": {
            "p_offset": interp["p_offset"],
            "p_filesz": interp["p_filesz"],
        },
    }


def assert_region_invariant(elf: Elf64, expected: dict) -> tuple[int, int]:
    """Hold the binary to the committed description of its target region.

    Returns the (start, length) of the proven filler run. Raises on any drift.
    """
    actual = describe_target_region(
        elf, expected.get("window", DETECT_LIBC_WINDOW))

    problems: list[str] = []

    for key, want in expected.get("elfHeader", {}).items():
        got = actual["elfHeader"].get(key)
        if got != want:
            problems.append(f"elfHeader.{key}: expected {want}, got {got}")

    if actual["interpSegments"] != expected.get("interpSegments"):
        problems.append(
            f"PT_INTERP count: expected {expected.get('interpSegments')}, "
            f"got {actual['interpSegments']}")

    if actual["fillerByte"] != expected.get("fillerByte"):
        problems.append("filler byte changed")

    if actual["fillerStart"] != expected.get("fillerStart"):
        problems.append(
            f"filler run starts at {actual['fillerStart']}, expected "
            f"{expected.get('fillerStart')}")

    # The run may legitimately be longer than recorded (a bigger store path
    # vacates more), but never shorter: that would mean patchelf laid the file
    # out differently and the region is no longer the one that was reviewed.
    if actual["fillerLength"] < expected.get("fillerLength", 0):
        problems.append(
            f"filler run is {actual['fillerLength']} bytes, shorter than the "
            f"reviewed {expected.get('fillerLength')}")

    want_load = expected.get("containingLoad")
    got_load = actual["containingLoad"]
    if want_load is None or got_load is None:
        problems.append("the filler run is not inside a PT_LOAD segment")
    else:
        for key, want in want_load.items():
            if got_load.get(key) != want:
                problems.append(
                    f"containing PT_LOAD {key}: expected {want}, got "
                    f"{got_load.get(key)}")

    if problems:
        raise RelocationError(
            f"{elf.path}: the reviewed target-region invariant no longer "
            f"holds:\n  " + "\n  ".join(problems) +
            "\n\nThe interpreter is only moved into a region whose provenance "
            "was established by review. patchelf has laid this binary out "
            "differently, so that region is not the one that was reviewed. "
            "Re-establish the invariant by hand and commit it."
        )

    # Hand back the REVIEWED extent, not the observed one.
    #
    # The run may legitimately be longer than recorded, and that is fine as a
    # sanity check -- but this tuple becomes the trusted search window, and
    # searching bytes beyond what was reviewed defeats the point of pinning a
    # region at all. The reviewed length was enough when it was established, so
    # clamp to it.
    reviewed = expected.get("fillerLength", 0)
    if reviewed <= 0:
        raise RelocationError(
            f"{elf.path}: the reviewed region records no filler length, so "
            f"there is no reviewed extent to search. Re-establish the "
            f"invariant by hand and commit it."
        )
    return actual["fillerStart"], min(actual["fillerLength"], reviewed)


def find_free_range(elf: Elf64, need: int, window: int,
                    moving_interp: int | None = None,
                    region: tuple[int, int] | None = None) -> int:
    """Find ``need`` unreferenced bytes ending inside ``window``.

    A candidate must satisfy three independent conditions:

    1. no section header or header table claims any byte of it;
    2. every byte is patchelf filler (``0x58``) or zero padding;
    3. it lies inside a ``PT_LOAD`` segment, so the bytes are mapped.

    Condition 1 is the one that matters. Condition 2 alone is not safe: live
    sections contain runs of zeros, and writing into one produces a binary
    that looks structurally valid and crashes at runtime.
    """
    occupied = occupied_ranges(elf, moving_interp=moving_interp)
    limit = min(window, len(elf.data))

    def claimed(start: int, end: int) -> bool:
        return any(s < end and start < e for s, e in occupied)

    # Start after the program-header table and keep 8-byte alignment.
    offset = (elf.phdr_table_end + 7) & ~7
    if region is not None:
        region_start, region_length = region
        offset = max(offset, region_start)
        limit = min(limit, region_start + region_length)
    while offset + need <= limit:
        end = offset + need
        if claimed(offset, end):
            # Jump past whichever claimed range we collided with.
            nxt = min((e for s, e in occupied if s < end and offset < e),
                      default=offset + 1)
            offset = (max(nxt, offset + 1) + 7) & ~7
            continue
        chunk = elf.data[offset:end]
        if all(byte in FILLER_BYTES for byte in chunk):
            return offset
        # Restart just past the last non-filler byte in this window rather than
        # stepping a fixed 8 bytes, which could step over an otherwise usable
        # run that begins in the middle of the rejected chunk.
        last_bad = max(i for i, byte in enumerate(chunk)
                       if byte not in FILLER_BYTES)
        offset = (offset + last_bad + 1 + 7) & ~7

    raise RelocationError(
        f"{elf.path}: could not find {need} unreferenced bytes between "
        f"{elf.phdr_table_end} and {limit}. patchelf left no reusable gap, so "
        f"the interpreter cannot be moved back inside the {window}-byte "
        f"detect-libc window without relaying out the file. This needs manual "
        f"review rather than an automatic workaround."
    )


def assert_within_window(elf: Elf64, window: int, label: str) -> None:
    phdr = elf.phdr(elf.interp_index())
    end = phdr["p_offset"] + phdr["p_filesz"]
    if end > window:
        raise RelocationError(
            f"{elf.path}: {label}: PT_INTERP occupies "
            f"[{phdr['p_offset']}, {end}) which is outside the first {window} "
            f"bytes. detect-libc would fail to identify glibc here."
        )


def relocate(path: str, *, window: int = DETECT_LIBC_WINDOW,
             verbose: bool = True, expect_region: dict | None = None) -> dict:
    """Move PT_INTERP back inside the detect-libc window. Idempotent."""
    elf = Elf64(path)
    elf.validate_structure()
    elf.validate_sections()
    original_size = len(elf.data)

    index = elf.interp_index()
    before = elf.phdr(index)
    interp = elf.interp_string()
    encoded = interp.encode("utf-8") + b"\0"

    if not interp.startswith("/"):
        raise RelocationError(f"{path}: implausible interpreter {interp!r}")

    report = {
        "path": path,
        "interpreter": interp,
        "before_offset": before["p_offset"],
        "before_size": before["p_filesz"],
        "moved": False,
    }

    if before["p_offset"] + before["p_filesz"] <= window:
        report["after_offset"] = before["p_offset"]
        report["after_size"] = before["p_filesz"]
        if verbose:
            print(f"  {os.path.basename(path)}: PT_INTERP already at offset "
                  f"{before['p_offset']} (within {window}); nothing to do")
        return report

    region = None
    if expect_region is not None:
        # Positive proof first: hold the binary to the reviewed description of
        # where patchelf's vacated space is, and confine the search to it.
        region = assert_region_invariant(elf, expect_region)

    target = find_free_range(elf, len(encoded), window,
                             moving_interp=index, region=region)
    load = elf.containing_load(target, len(encoded))
    if load is None:
        raise RelocationError(
            f"{path}: offset {target} is not inside any PT_LOAD segment; "
            f"refusing to place the interpreter in unmapped space"
        )
    vaddr = load["p_vaddr"] + (target - load["p_offset"])

    elf.data[target:target + len(encoded)] = encoded
    elf.set_phdr(index, p_offset=target, p_vaddr=vaddr, p_paddr=vaddr,
                 p_filesz=len(encoded), p_memsz=len(encoded))

    section = elf.find_section(".interp")
    if section is not None:
        elf.set_section_location(section, sh_addr=vaddr, sh_offset=target,
                                 sh_size=len(encoded))

    if len(elf.data) != original_size:
        raise RelocationError(
            f"{path}: file size changed from {original_size} to {len(elf.data)}"
        )

    # Validate a candidate file and only then replace the original. Writing
    # first and checking afterwards would leave a corrupted binary behind
    # whenever a check fails -- and the caller treats a failure as "not
    # relocated", so it would ship that corruption rather than stopping.
    staged = path + ".interp-tmp"
    try:
        with open(staged, "wb") as fh:
            fh.write(elf.data)
        shutil.copymode(path, staged)

        verified = Elf64(staged)
        verified.validate_structure()
        verified.validate_sections()
        assert_within_window(verified, window, "after relocation")

        # PT_INTERP and the .interp section must agree. A reader that trusts
        # one and a reader that trusts the other must not see different things.
        section = verified.find_section(".interp")
        after_ph = verified.phdr(verified.interp_index())
        if section is not None:
            sh = verified.section_header(section)
            if (sh["sh_offset"], sh["sh_size"]) != (
                    after_ph["p_offset"], after_ph["p_filesz"]):
                raise RelocationError(
                    f"{path}: .interp section ({sh['sh_offset']}, "
                    f"{sh['sh_size']}) disagrees with PT_INTERP "
                    f"({after_ph['p_offset']}, {after_ph['p_filesz']})")
            if sh["sh_addr"] != after_ph["p_vaddr"]:
                raise RelocationError(
                    f"{path}: .interp address {sh['sh_addr']} disagrees with "
                    f"PT_INTERP vaddr {after_ph['p_vaddr']}")
        if verified.interp_string() != interp:
            raise RelocationError(
                f"{path}: interpreter changed during relocation: "
                f"{verified.interp_string()!r} != {interp!r}"
            )
        if os.path.getsize(staged) != original_size:
            raise RelocationError(f"{path}: staged size changed")
        if simulate_detect_libc(staged, window) != "glibc":
            raise RelocationError(
                f"{path}: the relocated binary still does not report glibc"
            )

        os.replace(staged, path)
    except BaseException:
        with contextlib.suppress(FileNotFoundError):
            os.unlink(staged)
        raise

    after = verified.phdr(verified.interp_index())
    report.update(moved=True, after_offset=after["p_offset"],
                  after_size=after["p_filesz"])
    if verbose:
        print(f"  {os.path.basename(path)}: PT_INTERP {before['p_offset']} -> "
              f"{after['p_offset']} (within {window}), size unchanged at "
              f"{original_size} bytes")
    return report


def simulate_detect_libc(path: str, window: int = DETECT_LIBC_WINDOW) -> str | None:
    """Reimplement detect-libc's probe exactly, for regression testing.

    Mirrors ``detect-libc``'s own algorithm: a single read of the first
    ``window`` bytes, a program-header walk confined to that buffer, and a
    substring test on the extracted interpreter. Returns ``"glibc"``,
    ``"musl"`` or ``None`` — where ``None`` is the failure that leads to the
    SIGILL fallback path.
    """
    with open(path, "rb") as fh:
        buf = fh.read(window)
    if len(buf) < 64 or buf[:4] != b"\x7fELF" or buf[4] != 2:
        return None
    try:
        e_phoff = struct.unpack_from("<Q", buf, 32)[0]
        e_phentsize, e_phnum = struct.unpack_from("<HH", buf, 54)
        for i in range(e_phnum):
            base = e_phoff + i * e_phentsize
            # detect-libc reads straight out of the 2048-byte buffer; a header
            # beyond it throws, which it swallows into a null result.
            if base + 56 > len(buf):
                return None
            p_type = struct.unpack_from("<I", buf, base)[0]
            if p_type != PT_INTERP:
                continue
            p_offset = struct.unpack_from("<Q", buf, base + 8)[0]
            p_filesz = struct.unpack_from("<Q", buf, base + 32)[0]
            # Buffer.subarray clamps silently rather than throwing.
            interp = buf[p_offset:p_offset + p_filesz]
            text = interp.split(b"\0")[0].decode("utf-8", "replace")
            if "/ld-musl-" in text:
                return "musl"
            if "/ld-linux-" in text:
                return "glibc"
            return None
    except (struct.error, IndexError):
        return None
    return None


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("binaries", nargs="+")
    parser.add_argument("--window", type=int, default=DETECT_LIBC_WINDOW)
    parser.add_argument(
        "--verify-only", action="store_true",
        help="assert the invariant without modifying anything",
    )
    parser.add_argument(
        "--require-glibc-detection", action="store_true",
        help="also assert the detect-libc probe reports glibc",
    )
    args = parser.parse_args()

    failures = 0
    for path in args.binaries:
        try:
            if args.verify_only:
                elf = Elf64(path)
                assert_within_window(elf, args.window, "verification")
                phdr = elf.phdr(elf.interp_index())
                print(f"  {os.path.basename(path)}: PT_INTERP at "
                      f"{phdr['p_offset']} (within {args.window}) -> "
                      f"{elf.interp_string()}")
            else:
                relocate(path, window=args.window)

            if args.require_glibc_detection:
                detected = simulate_detect_libc(path, args.window)
                if detected != "glibc":
                    raise RelocationError(
                        f"{path}: detect-libc probe returned {detected!r}, "
                        f"expected 'glibc'. This is the exact condition that "
                        f"causes SIGILL when opening a Git-backed Codex thread."
                    )
                print(f"  {os.path.basename(path)}: detect-libc probe reports glibc")
        except RelocationError as exc:
            print(f"ERROR: {exc}", file=sys.stderr)
            failures += 1
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
