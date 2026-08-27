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
import os
import struct
import sys

PT_LOAD, PT_INTERP = 1, 3
SHT_PROGBITS = 1

#: The window detect-libc reads. The interpreter string must end within it.
DETECT_LIBC_WINDOW = 2048

#: Byte values patchelf leaves behind in space it has vacated. 0x58 ('X') is
#: its distinctive filler; 0x00 shows up as alignment padding beside it.
#:
#: Matching on bytes alone is NOT sufficient and must never be the only test.
#: A run of zeros occurs naturally *inside* live sections — the bundled Node
#: binary has one at offset 1411, and writing the interpreter there produces a
#: binary that passes every structural check and then segfaults on the first
#: run. The authoritative test is that no section header claims the range;
#: these byte values are only a corroborating signal.
FILLER_BYTES = frozenset({0x58, 0x00})


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
        end = self.data.find(b"\0", start, strtab_off + strtab_size)
        return self.data[start:end].decode("utf-8", "replace")

    def find_section(self, wanted: str) -> int | None:
        if not self.e_shoff:
            return None
        for i in range(self.e_shnum):
            if self.section_name(i) == wanted:
                return i
        return None

    def set_section_location(self, index: int, *, sh_addr: int, sh_offset: int,
                             sh_size: int) -> None:
        base = self._sh_base(index)
        struct.pack_into("<Q", self.data, base + 16, sh_addr)
        struct.pack_into("<Q", self.data, base + 24, sh_offset)
        struct.pack_into("<Q", self.data, base + 32, sh_size)

    # -- helpers -----------------------------------------------------------

    def interp_index(self) -> int:
        for phdr in self.phdrs():
            if phdr["p_type"] == PT_INTERP:
                return phdr["index"]
        raise RelocationError(f"{self.path}: no PT_INTERP segment")

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


SHT_NOBITS = 8


def occupied_ranges(elf: Elf64) -> list[tuple[int, int]]:
    """Every file range that some ELF structure actually claims.

    Covers the ELF header, the program-header table, the section-header table
    and the file-backed contents of every section. Anything outside all of
    these is genuinely unreferenced and safe to reuse.
    """
    ranges: list[tuple[int, int]] = [(0, 64)]  # ELF header
    ranges.append((elf.e_phoff, elf.phdr_table_end))
    if elf.e_shoff:
        ranges.append(
            (elf.e_shoff, elf.e_shoff + elf.e_shentsize * elf.e_shnum)
        )
        for i in range(elf.e_shnum):
            base = elf._sh_base(i)
            sh_type = struct.unpack_from("<I", elf.data, base + 4)[0]
            sh_offset = struct.unpack_from("<Q", elf.data, base + 24)[0]
            sh_size = struct.unpack_from("<Q", elf.data, base + 32)[0]
            # SHT_NOBITS (.bss) occupies no file space.
            if sh_type == SHT_NOBITS or sh_size == 0:
                continue
            ranges.append((sh_offset, sh_offset + sh_size))
    return sorted(ranges)


def find_free_range(elf: Elf64, need: int, window: int) -> int:
    """Find ``need`` unreferenced bytes ending inside ``window``.

    A candidate must satisfy three independent conditions:

    1. no section header or header table claims any byte of it;
    2. every byte is patchelf filler (``0x58``) or zero padding;
    3. it lies inside a ``PT_LOAD`` segment, so the bytes are mapped.

    Condition 1 is the one that matters. Condition 2 alone is not safe: live
    sections contain runs of zeros, and writing into one produces a binary
    that looks structurally valid and crashes at runtime.
    """
    occupied = occupied_ranges(elf)
    limit = min(window, len(elf.data))

    def claimed(start: int, end: int) -> bool:
        return any(s < end and start < e for s, e in occupied)

    # Start after the program-header table and keep 8-byte alignment.
    offset = (elf.phdr_table_end + 7) & ~7
    while offset + need <= limit:
        end = offset + need
        if claimed(offset, end):
            # Jump past whichever claimed range we collided with.
            nxt = min((e for s, e in occupied if s < end and offset < e),
                      default=offset + 1)
            offset = (max(nxt, offset + 1) + 7) & ~7
            continue
        if all(byte in FILLER_BYTES for byte in elf.data[offset:end]):
            return offset
        offset = (offset + 8) & ~7

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
             verbose: bool = True) -> dict:
    """Move PT_INTERP back inside the detect-libc window. Idempotent."""
    elf = Elf64(path)
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

    target = find_free_range(elf, len(encoded), window)
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

    elf.save()

    # Re-read from disk and assert the result, rather than trusting our own
    # in-memory view.
    verified = Elf64(path)
    assert_within_window(verified, window, "after relocation")
    if verified.interp_string() != interp:
        raise RelocationError(
            f"{path}: interpreter changed during relocation: "
            f"{verified.interp_string()!r} != {interp!r}"
        )
    if os.path.getsize(path) != original_size:
        raise RelocationError(f"{path}: on-disk size changed")

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
