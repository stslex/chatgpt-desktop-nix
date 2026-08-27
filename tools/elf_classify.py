#!/usr/bin/env python3
"""Explicit, testable ELF classifier for the ChatGPT Desktop payload.

The upstream payload mixes several unrelated kinds of ELF file in one tree:
host binaries that must be patched for NixOS, static executables that must not
be touched, musl prebuilds, Android prebuilds and prebuilds for other CPU
architectures. Running a blanket ``autoPatchelf`` over everything is wrong: it
would rewrite files that are not meant for this platform and would silently
mask upstream layout changes.

This module classifies every ELF file from its own headers, decides what the
build is allowed to do to it, and emits a stable inventory. CI compares that
inventory against a committed baseline so any new or reclassified ELF file
fails the build and goes to a human.

Classification is header-driven. Paths are used only as a corroborating signal,
never as the sole basis for a decision.
"""

from __future__ import annotations

import argparse
import dataclasses
import json
import os
import struct
import sys
from typing import Iterator

# ELF constants
ELFCLASS32, ELFCLASS64 = 1, 2
ET_EXEC, ET_DYN = 2, 3
PT_LOAD, PT_DYNAMIC, PT_INTERP, PT_NOTE = 1, 2, 3, 4
DT_NEEDED, DT_RPATH, DT_RUNPATH, DT_STRTAB, DT_STRSZ, DT_SONAME = 1, 15, 29, 5, 10, 14

EM_NAMES = {
    0x03: "i386",
    0x28: "arm",
    0x3E: "x86_64",
    0xB7: "aarch64",
    0xF3: "riscv",
}

#: Nix system name -> ELF e_machine for the host we are building for.
SYSTEM_MACHINE = {
    "x86_64-linux": "x86_64",
    "aarch64-linux": "aarch64",
}

#: The generic loader path each host architecture's binaries name.
SYSTEM_GENERIC_INTERP = {
    "x86_64-linux": "/lib64/ld-linux-x86-64.so.2",
    "aarch64-linux": "/lib/ld-linux-aarch64.so.1",
}


class Action:
    """What the build may do to a file of a given class."""

    PATCH_INTERP_AND_RUNPATH = "patch-interpreter-and-runpath"
    PATCH_RUNPATH = "patch-runpath"
    LEAVE_ALONE = "leave-alone"


@dataclasses.dataclass(frozen=True)
class ElfInfo:
    path: str
    machine: str
    elf_class: int
    etype: str
    interp: str | None
    interp_offset: int | None
    interp_size: int | None
    needed: tuple[str, ...]
    runpath: str | None
    soname: str | None
    is_android: bool
    size: int


@dataclasses.dataclass(frozen=True)
class Classified:
    info: ElfInfo
    kind: str
    action: str
    reason: str


class ElfError(Exception):
    pass


def read_elf(path: str) -> ElfInfo | None:
    """Parse the ELF headers we need. Returns None for non-ELF files."""
    with open(path, "rb") as fh:
        head = fh.read(64)
        if len(head) < 20 or head[:4] != b"\x7fELF":
            return None
        elf_class = head[4]
        endian = "<" if head[5] == 1 else ">"
        if elf_class not in (ELFCLASS32, ELFCLASS64):
            raise ElfError(f"{path}: unsupported ELF class {elf_class}")

        etype, machine_id = struct.unpack_from(endian + "HH", head, 16)
        if elf_class == ELFCLASS64:
            e_phoff = struct.unpack_from(endian + "Q", head, 32)[0]
            e_phentsize, e_phnum = struct.unpack_from(endian + "HH", head, 54)
        else:
            e_phoff = struct.unpack_from(endian + "I", head, 28)[0]
            e_phentsize, e_phnum = struct.unpack_from(endian + "HH", head, 42)

        fh.seek(e_phoff)
        phdrs = fh.read(e_phentsize * e_phnum)

        interp = interp_off = interp_sz = None
        dynamic: list[tuple[int, int]] = []
        is_android = False
        loads: list[tuple[int, int, int, int]] = []

        for i in range(e_phnum):
            base = i * e_phentsize
            if base + e_phentsize > len(phdrs):
                break
            p_type = struct.unpack_from(endian + "I", phdrs, base)[0]
            if elf_class == ELFCLASS64:
                p_offset, p_vaddr = struct.unpack_from(endian + "QQ", phdrs, base + 8)
                p_filesz = struct.unpack_from(endian + "Q", phdrs, base + 32)[0]
            else:
                p_offset, p_vaddr = struct.unpack_from(endian + "II", phdrs, base + 4)
                p_filesz = struct.unpack_from(endian + "I", phdrs, base + 16)[0]

            if p_type == PT_INTERP:
                interp_off, interp_sz = p_offset, p_filesz
                fh.seek(p_offset)
                interp = fh.read(p_filesz).split(b"\0")[0].decode("utf-8", "replace")
            elif p_type == PT_DYNAMIC:
                fh.seek(p_offset)
                dyn = fh.read(p_filesz)
                step = 16 if elf_class == ELFCLASS64 else 8
                fmt = endian + ("QQ" if elf_class == ELFCLASS64 else "II")
                for off in range(0, len(dyn) - step + 1, step):
                    tag, val = struct.unpack_from(fmt, dyn, off)
                    if tag == 0:
                        break
                    dynamic.append((tag, val))
            elif p_type == PT_LOAD:
                loads.append((p_offset, p_vaddr, p_filesz, 0))
            elif p_type == PT_NOTE:
                fh.seek(p_offset)
                note = fh.read(min(p_filesz, 4096))
                if b"Android" in note:
                    is_android = True

        needed: list[str] = []
        runpath = soname = None
        strtab_addr = next((v for t, v in dynamic if t == DT_STRTAB), None)
        strtab_size = next((v for t, v in dynamic if t == DT_STRSZ), None)
        if strtab_addr is not None and strtab_size:
            strtab_off = _vaddr_to_offset(strtab_addr, loads)
            if strtab_off is not None:
                fh.seek(strtab_off)
                strtab = fh.read(strtab_size)

                def name(idx: int) -> str:
                    end = strtab.find(b"\0", idx)
                    return strtab[idx:end if end != -1 else None].decode(
                        "utf-8", "replace"
                    )

                for tag, val in dynamic:
                    if tag == DT_NEEDED:
                        needed.append(name(val))
                    elif tag in (DT_RUNPATH, DT_RPATH):
                        runpath = name(val)
                    elif tag == DT_SONAME:
                        soname = name(val)

        return ElfInfo(
            path=path,
            machine=EM_NAMES.get(machine_id, f"unknown-0x{machine_id:x}"),
            elf_class=elf_class,
            etype={ET_EXEC: "EXEC", ET_DYN: "DYN"}.get(etype, str(etype)),
            interp=interp,
            interp_offset=interp_off,
            interp_size=interp_sz,
            needed=tuple(needed),
            runpath=runpath,
            soname=soname,
            is_android=is_android,
            size=os.path.getsize(path),
        )


def _vaddr_to_offset(vaddr: int, loads) -> int | None:
    for p_offset, p_vaddr, p_filesz, _ in loads:
        if p_vaddr <= vaddr < p_vaddr + p_filesz:
            return p_offset + (vaddr - p_vaddr)
    return None


#: Chromium dlopens exactly one of these at runtime, and only under a KDE
#: desktop, to talk to KWallet. We deliberately do not pull Qt 5 *and* Qt 6
#: into the closure to satisfy optional shims that this package's target
#: environment never loads: secrets go through the Secret Service API
#: (libsecret) instead. Leaving them unpatched makes the dlopen fail cleanly.
QT_SHIMS = frozenset({"libqt5_shim.so", "libqt6_shim.so"})

ANDROID_SONAMES = frozenset({"liblog.so", "libc++_shared.so"})


def classify(info: ElfInfo, system: str) -> Classified:
    """Decide the class and permitted action for one ELF file."""
    host_machine = SYSTEM_MACHINE[system]
    basename = os.path.basename(info.path)

    # 1. Android prebuilds. Detected from the ELF's own Android note or its
    #    bionic sonames, never from the path, because on an aarch64 host an
    #    android-arm64 prebuild has the same e_machine as a native one.
    if info.is_android or ANDROID_SONAMES.intersection(info.needed):
        return Classified(
            info, "android-prebuild", Action.LEAVE_ALONE,
            "bionic/Android prebuild; not loadable on this platform",
        )

    # 2. Prebuilds for a different CPU architecture.
    if info.machine != host_machine:
        return Classified(
            info, "foreign-architecture", Action.LEAVE_ALONE,
            f"built for {info.machine}, host is {host_machine}",
        )

    # 3. musl prebuilds shipped alongside the glibc ones.
    if any(n.startswith("libc.musl-") or n.startswith("ld-musl-")
           for n in info.needed):
        return Classified(
            info, "musl-prebuild", Action.LEAVE_ALONE,
            "links against musl libc; the glibc sibling is used instead",
        )

    # 4. Static executables. No interpreter and nothing to resolve, so there is
    #    nothing patchelf could usefully do and every edit is pure risk.
    if not info.needed and info.interp is None:
        return Classified(
            info, "static", Action.LEAVE_ALONE,
            "statically linked; no interpreter and no dynamic dependencies",
        )

    # 5. Optional Chromium keyring shims.
    if basename in QT_SHIMS:
        return Classified(
            info, "optional-qt-shim", Action.LEAVE_ALONE,
            "optional KDE/KWallet shim; deliberately not linked so the closure "
            "does not need both Qt 5 and Qt 6",
        )

    # 6. Host programs with an interpreter.
    if info.interp is not None:
        return Classified(
            info, "host-glibc-program", Action.PATCH_INTERP_AND_RUNPATH,
            "host glibc executable; needs the Nix interpreter and RUNPATH",
        )

    # 7. Host shared objects and Node native modules.
    return Classified(
        info, "host-glibc-library", Action.PATCH_RUNPATH,
        "host glibc shared object; needs RUNPATH only",
    )


def walk(root: str) -> Iterator[str]:
    for dirpath, _dirnames, filenames in os.walk(root):
        for filename in sorted(filenames):
            path = os.path.join(dirpath, filename)
            if os.path.islink(path) or not os.path.isfile(path):
                continue
            yield path


def build_inventory(root: str, system: str) -> dict:
    entries = []
    for path in sorted(walk(root)):
        try:
            info = read_elf(path)
        except (ElfError, struct.error, OSError) as exc:
            raise ElfError(f"{path}: unreadable ELF ({exc})") from exc
        if info is None:
            continue
        result = classify(info, system)
        rel = os.path.relpath(path, root)
        entries.append({
            "path": rel,
            "kind": result.kind,
            "action": result.action,
            "machine": info.machine,
            "etype": info.etype,
            "interp": info.interp,
            "needed": list(info.needed),
            "runpath": info.runpath,
        })
    entries.sort(key=lambda e: e["path"])
    counts: dict[str, int] = {}
    for entry in entries:
        counts[entry["kind"]] = counts.get(entry["kind"], 0) + 1
    return {"system": system, "counts": counts, "entries": entries}


def summarize(inventory: dict) -> str:
    lines = [f"ELF inventory for {inventory['system']}: "
             f"{len(inventory['entries'])} files"]
    for kind, count in sorted(inventory["counts"].items()):
        lines.append(f"  {kind:24} {count:3}")
    return "\n".join(lines)


def compare(baseline: dict, current: dict) -> list[str]:
    """Return human-readable differences between two inventories.

    Any difference is a hard failure upstream: a new ELF file, a removed one,
    or one that changed class means the payload's shape changed and a human has
    to look at it. The updater must never respond by widening an ignore list.
    """
    problems: list[str] = []
    old = {e["path"]: e for e in baseline["entries"]}
    new = {e["path"]: e for e in current["entries"]}

    for path in sorted(set(new) - set(old)):
        problems.append(
            f"NEW ELF file not in the reviewed baseline: {path} "
            f"(classified {new[path]['kind']} -> {new[path]['action']})"
        )
    for path in sorted(set(old) - set(new)):
        problems.append(f"ELF file disappeared from the payload: {path}")
    for path in sorted(set(old) & set(new)):
        for field in ("kind", "action", "machine", "etype"):
            if old[path][field] != new[path][field]:
                problems.append(
                    f"{path}: {field} changed {old[path][field]!r} -> "
                    f"{new[path][field]!r}"
                )
        if sorted(old[path]["needed"]) != sorted(new[path]["needed"]):
            added = sorted(set(new[path]["needed"]) - set(old[path]["needed"]))
            removed = sorted(set(old[path]["needed"]) - set(new[path]["needed"]))
            problems.append(
                f"{path}: DT_NEEDED changed (added {added}, removed {removed})"
            )
    return problems


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("root", help="extracted payload root")
    parser.add_argument("--system", required=True, choices=sorted(SYSTEM_MACHINE))
    parser.add_argument("--emit", help="write the inventory JSON here")
    parser.add_argument("--baseline", help="compare against this committed baseline")
    parser.add_argument("--list-action", help="print paths with this action")
    args = parser.parse_args()

    inventory = build_inventory(args.root, args.system)

    if args.list_action:
        for entry in inventory["entries"]:
            if entry["action"] == args.list_action:
                print(entry["path"])
        return 0

    if args.emit:
        with open(args.emit, "w", encoding="utf-8") as fh:
            json.dump(inventory, fh, indent=1, sort_keys=True)
            fh.write("\n")

    print(summarize(inventory), file=sys.stderr)

    if args.baseline:
        with open(args.baseline, encoding="utf-8") as fh:
            baseline = json.load(fh)
        problems = compare(baseline, inventory)
        if problems:
            print(
                "\nELF inventory drift against the reviewed baseline:\n",
                file=sys.stderr,
            )
            for problem in problems:
                print(f"  - {problem}", file=sys.stderr)
            print(
                "\nThis is a deliberate manual-review breakpoint. An upstream "
                "release that changes the ELF inventory must be inspected by a "
                "human, and the baseline updated in a reviewed commit. Do not "
                "widen an ignore list to make this pass.",
                file=sys.stderr,
            )
            return 1
        print("ELF inventory matches the reviewed baseline", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
