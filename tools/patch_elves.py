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
    """Read an ELF's existing RUNPATH.

    A failure here must be fatal. Treating it as "no RUNPATH" would silently
    drop a $ORIGIN entry that a native module needs to find its own bundled
    libraries, producing a package that builds cleanly and misbehaves at run
    time.
    """
    proc = subprocess.run(
        [patchelf, "--print-rpath", path], capture_output=True, text=True
    )
    if proc.returncode != 0:
        raise SystemExit(
            f"patchelf --print-rpath failed for {path} "
            f"(exit {proc.returncode}): {proc.stderr.strip()}"
        )
    return proc.stdout.strip()


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

    # Both "$ORIGIN/../lib" and "${ORIGIN}/../lib" are valid and mean the same
    # thing; matching only the bare form would demote a braced entry behind our
    # store paths and let a store library shadow a bundled one.
    def is_origin(entry: str) -> bool:
        return "$ORIGIN" in entry or "${ORIGIN}" in entry

    add(":".join(e for e in existing.split(":") if is_origin(e)))
    add(additions)
    add(":".join(e for e in existing.split(":") if not is_origin(e)))
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
    parser.add_argument(
        "--relocate", action="append", default=[],
        help="payload-relative path to attempt interpreter relocation on; "
             "repeatable. Anything not listed keeps patchelf's placement.",
    )
    args = parser.parse_args()

    inventory = C.build_inventory(args.root, args.system)
    print(C.summarize(inventory), file=sys.stderr)

    if not os.path.exists(args.interpreter):
        raise SystemExit(f"interpreter does not exist: {args.interpreter}")

    required = set(args.require_in_window)
    relocatable = set(args.relocate) | required
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
            # window detect-libc reads.
            #
            # Only binaries known to perform early libc self-detection are put
            # back. Rewriting an ELF is never free, and doing it to a file that
            # has no need of it is risk without benefit; the ones left alone
            # run correctly, only their own self-probe is inconclusive.
            #
            # Relocation can also legitimately fail: for the main ChatGPT
            # binary patchelf vacates ~209 KiB right after the program headers,
            # but for the bundled Node it packs .dynamic and .dynstr into that
            # space and leaves no gap at all.
            #
            # Which binaries end up in which state is recorded below and
            # asserted against a reviewed expectation, so a change surfaces to
            # a human instead of passing silently.
            if entry["path"] not in relocatable:
                in_window[entry["path"]] = (
                    R.simulate_detect_libc(path) == "glibc")
                patched_programs.append(entry["path"])
                continue

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

    # Re-scan the finished tree. Everything above validated the payload as it
    # arrived; this validates what we are actually going to ship, which is not
    # the same thing.
    print("verifying the patched tree", file=sys.stderr)
    after = C.build_inventory(args.root, args.system)
    after_by_path = {e["path"]: e for e in after["entries"]}
    problems: list[str] = []

    if set(after_by_path) != {e["path"] for e in inventory["entries"]}:
        problems.append("the set of ELF files changed during patching")

    for entry in inventory["entries"]:
        post = after_by_path.get(entry["path"])
        if post is None:
            continue
        if post["kind"] != entry["kind"]:
            problems.append(
                f"{entry['path']}: reclassified during patching "
                f"({entry['kind']} -> {post['kind']})")
        if entry["action"] == C.Action.LEAVE_ALONE:
            for field in ("interp", "runpath", "needed", "segments"):
                if post[field] != entry[field]:
                    problems.append(
                        f"{entry['path']}: was to be left alone but its "
                        f"{field} changed")
            continue
        if post["runpath"] is None or args.runpath.split(":")[0] not in (
                post["runpath"] or ""):
            problems.append(
                f"{entry['path']}: RUNPATH does not contain the package "
                f"library path after patching (got {post['runpath']!r})")
        if entry["action"] == C.Action.PATCH_INTERP_AND_RUNPATH:
            if post["interp"] != args.interpreter:
                problems.append(
                    f"{entry['path']}: interpreter is {post['interp']!r}, "
                    f"expected {args.interpreter!r}")
        if sorted(post["segments"]) != sorted(entry["segments"]):
            # patchelf legitimately adds LOAD segments; losing a structural one
            # (a GNU property note, say) is a different matter.
            lost = set(entry["segments"]) - set(post["segments"])
            if lost:
                problems.append(
                    f"{entry['path']}: lost program segments {sorted(lost)}")

    if problems:
        print("\npost-patch verification failed:", file=sys.stderr)
        for problem in problems:
            print(f"  - {problem}", file=sys.stderr)
        return 1
    print("  patched tree matches what the classifier intended", file=sys.stderr)

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
