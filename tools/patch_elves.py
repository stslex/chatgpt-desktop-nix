#!/usr/bin/env python3
"""Apply the ELF classifier's decisions to an extracted payload.

Every file is patched according to the class the classifier assigned it, and
nothing else is touched. In particular this never runs a blanket
``autoPatchelf`` over the tree: static binaries, musl prebuilds, Android
prebuilds, foreign-architecture prebuilds and the optional Qt keyring shims are
all left byte-identical.

Existing ``$ORIGIN`` entries in a RUNPATH are preserved and kept first, so
native modules that locate their own bundled libraries relative to themselves
(Sharp finding libvips, for example) keep working.
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import elf_classify as C  # noqa: E402
import relocate_interp as R  # noqa: E402


def run(cmd: list[str]) -> None:
    proc = subprocess.run(cmd, capture_output=True, text=True)
    if proc.returncode != 0:
        raise SystemExit(
            f"command failed: {' '.join(cmd)}\n{proc.stdout}\n{proc.stderr}"
        )


def current_runpath(path: str, patchelf: str) -> str:
    proc = subprocess.run(
        [patchelf, "--print-rpath", path], capture_output=True, text=True
    )
    return proc.stdout.strip() if proc.returncode == 0 else ""


def merged_runpath(existing: str, additions: str) -> str:
    """Combine an existing RUNPATH with ours, keeping $ORIGIN entries first.

    Order matters: a module that ships its own copy of a library must find that
    copy before any store-wide one, otherwise we would silently swap out the
    exact build it was linked against.
    """
    seen: list[str] = []

    def add(entries: str) -> None:
        for entry in entries.split(":"):
            entry = entry.strip()
            if entry and entry not in seen:
                seen.append(entry)

    add(":".join(e for e in existing.split(":") if "$ORIGIN" in e))
    add(additions)
    add(":".join(e for e in existing.split(":") if "$ORIGIN" not in e))
    return ":".join(seen)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("root", help="payload root to patch in place")
    parser.add_argument("--system", required=True, choices=sorted(C.SYSTEM_MACHINE))
    parser.add_argument("--interpreter", required=True)
    parser.add_argument("--runpath", required=True,
                        help="colon-separated library path to add")
    parser.add_argument("--patchelf", default="patchelf")
    parser.add_argument("--report", help="write a JSON report here")
    parser.add_argument(
        "--require-in-window", action="append", default=[],
        help="payload-relative path whose interpreter MUST end up inside the "
             "detect-libc window; repeatable",
    )
    parser.add_argument(
        "--expect-in-window",
        help="JSON file recording the reviewed per-binary window outcome",
    )
    args = parser.parse_args()

    inventory = C.build_inventory(args.root, args.system)
    print(C.summarize(inventory), file=sys.stderr)

    if not os.path.exists(args.interpreter):
        raise SystemExit(f"interpreter does not exist: {args.interpreter}")

    required = set(args.require_in_window)
    in_window: dict[str, bool] = {}
    patched_programs: list[str] = []
    patched_libraries: list[str] = []
    untouched: list[str] = []

    for entry in inventory["entries"]:
        path = os.path.join(args.root, entry["path"])
        action = entry["action"]

        if action == C.Action.LEAVE_ALONE:
            untouched.append(entry["path"])
            continue

        os.chmod(path, os.stat(path).st_mode | 0o200)
        existing = current_runpath(path, args.patchelf)
        combined = merged_runpath(existing, args.runpath)

        if action == C.Action.PATCH_INTERP_AND_RUNPATH:
            run([args.patchelf, "--set-interpreter", args.interpreter, path])
            run([args.patchelf, "--set-rpath", combined, path])

            # patchelf has now almost certainly pushed PT_INTERP past the 2 KiB
            # window detect-libc reads. Try to put it back.
            #
            # This does not always succeed, and that is not a failure. Whether
            # it can succeed depends on where patchelf relaid the file: for the
            # main ChatGPT binary it vacates ~209 KiB right after the program
            # headers, but for the bundled Node it packs .dynamic and .dynstr
            # into that space and leaves no gap at all. Writing the interpreter
            # into a claimed range produces a binary that passes every
            # structural check and then segfaults, so when there is no genuinely
            # free range we leave the interpreter where patchelf put it. The
            # binary still runs correctly; only its detect-libc self-probe is
            # inconclusive.
            #
            # Which binaries end up in which state is recorded below and
            # asserted against a reviewed expectation, so a change surfaces to
            # a human instead of passing silently.
            try:
                R.relocate(path, verbose=False)
                relocated = True
                failure = None
            except R.RelocationError as exc:
                relocated = False
                failure = str(exc)

            detected = R.simulate_detect_libc(path)
            in_window[entry["path"]] = detected == "glibc"
            if not relocated:
                print(f"  note: {entry['path']} keeps its interpreter outside "
                      f"the detect-libc window ({failure.splitlines()[0]})",
                      file=sys.stderr)

            if entry["path"] in required and detected != "glibc":
                raise SystemExit(
                    f"{entry['path']} must have its interpreter inside the "
                    f"{R.DETECT_LIBC_WINDOW}-byte detect-libc window, but the "
                    f"probe reports {detected!r}.\n"
                    f"This is the exact condition that makes opening a "
                    f"Git-backed Codex thread raise SIGILL.\n"
                    + (f"\nRelocation failed: {failure}" if failure else "")
                )
            patched_programs.append(entry["path"])
        else:
            run([args.patchelf, "--set-rpath", combined, path])
            patched_libraries.append(entry["path"])

    print(
        f"patched {len(patched_programs)} programs, "
        f"{len(patched_libraries)} libraries; left {len(untouched)} files "
        f"untouched",
        file=sys.stderr,
    )

    if args.expect_in_window:
        with open(args.expect_in_window, encoding="utf-8") as fh:
            expected = json.load(fh)
        if expected != in_window:
            print(
                "\nInterpreter-window outcome differs from the reviewed "
                "expectation:", file=sys.stderr)
            for path in sorted(set(expected) | set(in_window)):
                was, now = expected.get(path), in_window.get(path)
                if was != now:
                    print(f"  - {path}: expected {was}, got {now}", file=sys.stderr)
            print(
                "\nA change here means patchelf relaid one of these binaries "
                "differently. Review it by hand and update the expectation in a "
                "reviewed commit; do not silence this.", file=sys.stderr)
            return 1
        print("interpreter-window outcome matches the reviewed expectation",
              file=sys.stderr)

    if args.report:
        with open(args.report, "w", encoding="utf-8") as fh:
            json.dump({
                "system": args.system,
                "interpreter": args.interpreter,
                "programs": sorted(patched_programs),
                "libraries": sorted(patched_libraries),
                "untouched": sorted(untouched),
                "interpreterInDetectLibcWindow": in_window,
            }, fh, indent=1, sort_keys=True)
            fh.write("\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
