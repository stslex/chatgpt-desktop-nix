{ pkgs, chatgpt, system, self }:

let
  inherit (pkgs) lib runCommand runCommandCC;

  # Every check below runs against the built package, not against an
  # evaluation of it. A green `nix flake check` that never built the
  # derivation would prove nothing.
  check = name: deps: script:
    runCommand "chatgpt-check-${name}"
      { nativeBuildInputs = deps; }
      ''
        set -euo pipefail
        ${script}
        touch "$out"
      '';

  app = "${chatgpt}/lib/chatgpt";
  launcher = "${chatgpt}/bin/chatgpt";

in
{
  # --- trust anchor ------------------------------------------------------

  trust-key = check "trust-key" [ pkgs.gnupg pkgs.python3 ] ''
    keyring=${../trust/openai-chatgpt-archive-keyring.gpg}
    armored=${../trust/openai-chatgpt-archive-keyring.asc}

    echo "the committed keyring must be exactly the reviewed bytes"
    actual="$(sha256sum "$keyring" | cut -d' ' -f1)"
    expected=23e2cfbdef6afe95505f9e95a2cb63585da7ffe9b06a51ec08a32407c847d596
    if [ "$actual" != "$expected" ]; then
      echo "keyring changed: $actual != $expected" >&2
      echo "Signing-key rotation is a manual-review event." >&2
      exit 1
    fi

    echo "the armored copy must round-trip to the same bytes"
    export GNUPGHOME=$(mktemp -d)
    gpg --dearmor < "$armored" > roundtrip.gpg
    cmp "$keyring" roundtrip.gpg

    echo "the keyring must contain exactly the pinned fingerprint"
    gpg --homedir "$GNUPGHOME" --batch --with-colons --show-keys \
      --with-fingerprint "$keyring" | grep -q \
      '^fpr:::::::::3BFA0E4AE8B8CC16A2D9BA684A3B4A566C4660E4:'
  '';

  # --- source metadata ---------------------------------------------------

  sources-shape = check "sources-shape" [ pkgs.python3 ] ''
    python3 - <<'PY'
    import json
    s = json.load(open("${../sources.json}"))
    assert s["package"] == "chatgpt", s["package"]
    assert s["origin"] == "https://persistent.oaistatic.com/codex-app-prod/linux/deb"
    assert s["suite"] == "stable" and s["component"] == "main"
    assert s["signingKeyFingerprint"] == "3BFA0E4AE8B8CC16A2D9BA684A3B4A566C4660E4"
    assert set(s["architectures"]) == {"amd64", "arm64"}
    versions = {a["url"].rsplit("_", 1)[0] for a in s["architectures"].values()}
    for arch, entry in s["architectures"].items():
        assert entry["url"].startswith(s["origin"] + "/pool/"), entry["url"]
        assert entry["hash"].startswith("sha256-"), entry["hash"]
        assert len(entry["sha256"]) == 64
        assert entry["size"] > 0
        assert s["version"] in entry["filename"]
    print("sources.json shape OK at version", s["version"])
    PY
  '';

  # --- unit tests --------------------------------------------------------

  # `ar` for the .deb fixtures, and zstandard so the zstd bomb case runs
  # rather than skipping.
  unit-tests = check "unit-tests"
    [ pkgs.gnupg pkgs.binutils
      (pkgs.python3.withPackages (ps: [ ps.zstandard ])) ] ''
    cp -r ${../tools} tools
    cp -r ${../tests} tests
    cp -r ${../trust} trust
    cp ${../sources.json} sources.json
    chmod -R u+w .
    export PYTHONPATH="$PWD/tools:$PWD"
    python3 -m unittest discover -s tests -v
  '';

  # --- workflow shell behaviour -------------------------------------------

  # These drive the real scripts against real git repositories. The defect they
  # exist for could not be caught by reading: `if git ls-remote ...; then` with
  # `rc=$?` afterwards reads the status of the *if statement*, which succeeds
  # whenever neither branch runs, so a missing ref looked like exit 0.
  observe-candidate = check "observe-candidate"
    [ pkgs.git pkgs.python3 pkgs.bash ] ''
    export HOME=$PWD/home; mkdir -p "$HOME"
    git config --global user.email t@t
    git config --global user.name t
    git config --global init.defaultBranch main
    cp -r ${../tools} tools
    cp -r ${../tests} tests
    chmod -R u+w .
    bash tests/test_observe_candidate.sh
  '';

  recover-base-sources = check "recover-base-sources"
    [ pkgs.git pkgs.bash ] ''
    export HOME=$PWD/home; mkdir -p "$HOME"
    git config --global user.email t@t
    git config --global user.name t
    git config --global init.defaultBranch main
    cp -r ${../tools} tools
    cp -r ${../tests} tests
    chmod -R u+w .
    bash tests/test_recover_base_sources.sh
  '';

  push-lease = check "push-lease" [ pkgs.git pkgs.bash ] ''
    export HOME=$PWD/home; mkdir -p "$HOME"
    git config --global user.email t@t
    git config --global user.name t
    git config --global init.defaultBranch main
    cp -r ${../tests} tests
    chmod -R u+w .
    bash tests/test_push_lease.sh
  '';

  # --- the launcher's hard negatives -------------------------------------

  launcher-invariants = check "launcher-invariants" [ pkgs.bash ] ''
    echo "must never disable Chromium's sandbox"
    if grep -q -- '--no-sandbox' ${launcher}; then
      echo "launcher contains --no-sandbox" >&2; exit 1
    fi

    echo "must never export a global LD_LIBRARY_PATH"
    if grep -qE '^[^#]*\bexport +LD_LIBRARY_PATH=' ${launcher}; then
      echo "launcher exports LD_LIBRARY_PATH" >&2; exit 1
    fi

    echo "must not install a setuid sandbox"
    if [ -e ${app}/chrome-sandbox ]; then
      echo "unexpected chrome-sandbox in the payload" >&2; exit 1
    fi

    echo "must not force native Wayland unconditionally"
    if grep -qE '^[^#]*--ozone-platform=wayland' ${launcher}; then
      echo "launcher hardcodes --ozone-platform=wayland" >&2; exit 1
    fi

    echo "NIXOS_OZONE_WL must be value-tested, not emptiness-tested"
    if grep -qE '\-n "\$\{NIXOS_OZONE_WL' ${launcher}; then
      echo "launcher treats any non-empty NIXOS_OZONE_WL as true" >&2; exit 1
    fi

    echo "must preserve the user's PATH rather than replacing it"
    grep -qE 'export PATH="\$\{PATH:\+\$PATH:\}' ${launcher}

    echo "must pass user arguments through verbatim"
    grep -qE 'exec "@?[^"]*ChatGPT@?" "\$\{electron_args\[@\]\}" "\$@"' ${launcher} \
      || grep -qE 'exec ".*/ChatGPT" "\$\{electron_args\[@\]\}" "\$@"' ${launcher}

    bash -n ${launcher}

    echo "the package's own tools must actually be put on PATH"
    # @preamble@ was once substituted into a comment, so this line existed but
    # did nothing: the launcher relied entirely on the caller's PATH, and under
    # a stripped environment basename and unshare were both missing -- making
    # the namespace probe fail and the launcher report that namespaces were
    # unavailable on a host where they were fine.
    if ! grep -qE '^export PATH="/nix/store/[^"]*:\$PATH"$' ${launcher}; then
      echo "the preamble PATH export is missing or commented out" >&2
      grep -n 'PATH' ${launcher} >&2
      exit 1
    fi
    for tool in coreutils util-linux; do
      grep -qE "^export PATH=\"[^\"]*$tool" ${launcher} \
        || { echo "$tool is not on the launcher's own PATH" >&2; exit 1; }
    done

    echo "no exec may carry a redirection that outlives the command"
    # `exec 9>>"$lock" 2>/dev/null` attaches BOTH redirections to the shell
    # permanently. The 2>/dev/null then follows the process through the final
    # exec and discards everything the application ever writes to stderr --
    # every Chromium warning, every crash message. That is what the launcher
    # used to do on its normal path, right before starting the app.
    #
    # The fix is to wrap the exec in a group, so the redirection applies to the
    # group: `{ exec 9>>"$lock"; } 2>/dev/null`.
    if grep -nE '^[^#]*(^|[^{[:alnum:]_])exec [0-9{][^|]*[0-9]>' ${launcher} \
       | grep -vE '\{ *exec ' | grep -q .; then
      echo "an exec carries a redirection outside a group:" >&2
      grep -nE '^[^#]*(^|[^{[:alnum:]_])exec [0-9{][^|]*[0-9]>' ${launcher} \
        | grep -vE '\{ *exec ' >&2
      exit 1
    fi

    echo "the namespace gate must still exist and still be called"
    grep -q 'check_user_namespaces()' ${launcher}
    grep -qE '^ *check_user_namespaces$' ${launcher}

    echo "the sandbox exemption must cover --version and nothing else"
    # Electron answers --version before any renderer exists, so it does not
    # need the sandbox. Nothing else measured here has that property: `-v` is
    # not an abbreviation of --version, it initialises Ozone and starts the
    # app, so exempting it would skip the precheck for a genuine application
    # start. The exemption must stay exactly this shape.
    grep -qE '^if \(\( \$# == 1 \)\) && \[\[ "\$1" == "--version" \]\]; then$' ${launcher} \
      || { echo "the sandbox exemption is not the expected exact form:" >&2
           grep -n 'needs_sandbox' ${launcher} >&2; exit 1; }
    if [ "$(grep -c 'needs_sandbox=0' ${launcher})" != "1" ]; then
      echo "more than one path clears needs_sandbox" >&2; exit 1
    fi
    for flag in -v -h --help; do
      if grep -qE "needs_sandbox=0" ${launcher} \
         && grep -qE "\\$flag\\b[^)]*\\) *needs_sandbox=0" ${launcher}; then
        echo "$flag must not be exempt from the sandbox precheck" >&2
        exit 1
      fi
    done
  '';

  launcher-runs-with-no-environment =
    check "launcher-runs-with-no-environment" [ pkgs.coreutils ] ''
    # The launcher must carry everything it needs. Running it under `env -i`
    # proves it does not silently depend on the caller having coreutils,
    # util-linux or anything else on PATH.
    # Deliberately not named "out": that is Nix's output path, and shadowing it
    # makes the wrapper's final `touch "$out"` land somewhere else.
    reported="$(env -i ${launcher} --version 2>&1)" || {
      echo "the launcher failed with an empty environment:" >&2
      echo "$reported" >&2
      exit 1
    }
    echo "$reported"
    case "$reported" in
      *"${chatgpt.version}"*) ;;
      *) echo "unexpected --version output under env -i" >&2; exit 1 ;;
    esac
    case "$reported" in
      *"command not found"*)
        echo "a tool the launcher needs was missing from its own PATH" >&2
        exit 1 ;;
    esac
    echo "launcher runs with an empty environment"
  '';

  # The bwrap bridge works by putting our shim ahead of the real bubblewrap on
  # PATH, and that only works because Codex resolves bwrap through PATH. Its own
  # diagnostic names the alternative it checks:
  #
  #   "bubblewrap is unavailable: no system bwrap was found on PATH and no
  #    bundled codex-resources/bwrap binary was found next to the Codex
  #    executable"
  #
  # There is no such bundled binary in this payload today. If a future upstream
  # release ships one, Codex may stop consulting PATH -- and the bridge would be
  # bypassed silently, with everything still appearing to work until someone ran
  # a downloaded toolchain. Fail the build instead, so it is a packaging
  # decision rather than a surprise.
  no-bundled-bwrap = check "no-bundled-bwrap" [ pkgs.coreutils ] ''
    echo "the payload must not ship its own bwrap next to Codex"
    found=$(find ${app} -name 'bwrap' -o -name 'bwrap.*' 2>/dev/null || true)
    if [ -n "$found" ]; then
      echo "upstream now bundles a bwrap:" >&2
      echo "$found" >&2
      echo "" >&2
      echo "Codex prefers a bundled codex-resources/bwrap over PATH, so the" >&2
      echo "shim in nix/bwrap-shim.c may no longer be reached. Re-check how" >&2
      echo "Codex chooses between them before releasing this version." >&2
      exit 1
    fi
    if [ -e ${app}/resources/codex-resources ]; then
      echo "a codex-resources directory appeared; inspect it for a bwrap" >&2
      ls -la ${app}/resources/codex-resources >&2
      exit 1
    fi
    echo "no bundled bwrap; the PATH shim is still the mechanism"

    echo "and Codex must still say it looks on PATH"
    if ! grep -qa 'no system bwrap was found on PATH' ${app}/resources/codex; then
      echo "the bundled Codex no longer contains the PATH-lookup diagnostic;" >&2
      echo "its bwrap resolution may have changed." >&2
      exit 1
    fi
  '';

  # --- payload integrity --------------------------------------------------

  asar-identity = check "asar-identity" [ pkgs.python3 pkgs.dpkg pkgs.curl ] ''
    # The app.asar in the built package must be byte-identical to the one in
    # the .deb we pinned. We take the asar straight out of the fetched source
    # rather than trusting a hash recorded during the build.
    dpkg-deb --fsys-tarfile ${chatgpt.src} \
      | tar -xO ./usr/lib/chatgpt/resources/app.asar > upstream.asar
    cmp upstream.asar ${app}/resources/app.asar
    echo "app.asar is byte-identical to the upstream package"
  '';

  payload-faithful = check "payload-faithful" [ pkgs.python3 pkgs.dpkg ] ''
    # Everything we did not deliberately patch must be byte-identical to what
    # OpenAI shipped. This is the strongest statement of faithfulness we can
    # make, and it catches accidental payload rewrites (a stray patchShebangs
    # sweep, for instance) that no other check would notice.
    mkdir upstream
    dpkg-deb --extract ${chatgpt.src} upstream

    python3 - <<'PY'
    import hashlib, json, os, sys
    sys.path.insert(0, "${chatgpt.toolsDir}")

    report = json.load(open(
        "${chatgpt}/share/chatgpt-desktop/elf-patch-report.json"))
    patched = set(report["programs"]) | set(report["libraries"])

    up_root = "upstream/usr/lib/chatgpt"
    out_root = "${app}"

    def digest(path):
        h = hashlib.sha256()
        with open(path, "rb") as fh:
            for chunk in iter(lambda: fh.read(1 << 20), b""):
                h.update(chunk)
        return h.hexdigest()

    # Files we knowingly do not ship, or that we replaced.
    expected_absent = {"codex-launcher"}

    checked = differing = 0
    problems = []
    for dirpath, _dirs, files in os.walk(up_root):
        for name in files:
            up = os.path.join(dirpath, name)
            rel = os.path.relpath(up, up_root)
            if rel in expected_absent:
                continue
            key = os.path.join("usr/lib/chatgpt", rel)
            out = os.path.join(out_root, rel)
            if os.path.islink(up):
                continue
            if not os.path.exists(out):
                problems.append(f"missing from the package: {rel}")
                continue
            if key in patched:
                differing += 1      # deliberately patched, must differ
                if digest(up) == digest(out):
                    problems.append(
                        f"{rel} was selected for patching but is unchanged")
                continue
            checked += 1
            if digest(up) != digest(out):
                problems.append(f"unpatched file was modified: {rel}")

    if problems:
        for p in problems[:40]:
            print("  -", p, file=sys.stderr)
        print(f"\n{len(problems)} payload faithfulness problems", file=sys.stderr)
        sys.exit(1)
    print(f"{checked} upstream files byte-identical; "
          f"{differing} deliberately patched")
    PY
  '';

  elf-inventory = check "elf-inventory" [ pkgs.python3 ] ''
    echo "the shipped inventory must still match the reviewed baseline"
    python3 - <<'PY'
    import json, sys
    sys.path.insert(0, "${chatgpt.toolsDir}")
    import elf_classify as C
    baseline = json.load(open("${../elf-baseline}/${system}.json"))
    shipped = json.load(open("${chatgpt}/share/chatgpt-desktop/elf-inventory.json"))
    problems = C.compare(baseline, shipped)
    if problems:
        for p in problems:
            print("  -", p, file=sys.stderr)
        sys.exit(1)
    print("ELF inventory matches the reviewed baseline")
    PY
  '';

  # --- the PT_INTERP / detect-libc regression -----------------------------

  interp-window = check "interp-window" [ pkgs.python3 ] ''
    echo "PT_INTERP must remain inside the 2 KiB detect-libc window"
    python3 ${chatgpt.toolsDir}/relocate_interp.py ${app}/ChatGPT \
      --verify-only --require-glibc-detection

    echo "and each program's window status must match the reviewed expectation"
    python3 - <<'PY'
    import json, sys
    sys.path.insert(0, "${chatgpt.toolsDir}")
    import relocate_interp as R

    report = json.load(open(
        "${chatgpt}/share/chatgpt-desktop/elf-patch-report.json"))
    expected = json.load(open("${../elf-baseline}/interp-window-${system}.json"))
    actual = report["interpreterInDetectLibcWindow"]

    # Not every binary can be relocated. patchelf packs .dynamic and .dynstr
    # into the whole first 2 KiB of the bundled Node, leaving no unreferenced
    # range to move the interpreter into, so that one keeps patchelf's
    # placement. It still runs correctly; only its own detect-libc self-probe
    # is inconclusive. What must not change silently is *which* binaries are in
    # which state, so that is pinned here.
    if actual != expected:
        print("interpreter-window status changed:", file=sys.stderr)
        for path in sorted(set(expected) | set(actual)):
            if expected.get(path) != actual.get(path):
                print(f"  - {path}: expected {expected.get(path)}, "
                      f"got {actual.get(path)}", file=sys.stderr)
        sys.exit(1)

    main = "usr/lib/chatgpt/ChatGPT"
    if not actual.get(main):
        print(f"{main} must be inside the window", file=sys.stderr)
        sys.exit(1)

    for rel, ok in sorted(actual.items()):
        path = "${chatgpt}/lib/chatgpt" + rel.split("usr/lib/chatgpt", 1)[1]
        elf = R.Elf64(path)
        offset = elf.phdr(elf.interp_index())["p_offset"]
        state = "in window" if ok else "outside window (expected)"
        print(f"  {rel}: PT_INTERP at {offset} — {state}")
        if ok:
            R.assert_within_window(elf, R.DETECT_LIBC_WINDOW, "shipped package")
    PY
  '';

  # --- dynamic linking ----------------------------------------------------

  runtime-deps = check "runtime-deps" [ pkgs.python3 pkgs.glibc.bin pkgs.patchelf ] ''
    echo "every patched ELF must resolve all of its DT_NEEDED entries"
    python3 - <<'PY'
    import json, subprocess, sys, os
    report = json.load(open("${chatgpt}/share/chatgpt-desktop/elf-patch-report.json"))
    root = "${chatgpt}/lib/chatgpt"
    failures = []
    for rel in report["programs"] + report["libraries"]:
        path = root + rel.split("usr/lib/chatgpt", 1)[1]
        out = subprocess.run(["ldd", path], capture_output=True, text=True)
        # A non-zero exit means ldd did not answer the question, and an
        # unanswered question is not a pass. A file ldd rejects outright --
        # "not a dynamic executable", a truncated header, the wrong machine --
        # produces empty stdout and a diagnostic on stderr, so scanning stdout
        # alone reported it as resolving cleanly.
        if out.returncode != 0:
            detail = (out.stderr or out.stdout).strip().replace("\n", "; ")
            failures.append(f"{rel}: ldd exited {out.returncode}: {detail}")
            continue
        for line in out.stdout.splitlines():
            if "not found" in line:
                failures.append(f"{rel}: {line.strip()}")
        # ldd can also report trouble on stderr while still exiting 0, so
        # stderr is examined too -- minus the one warning that is expected
        # here. Shared objects and Node addons are installed 0444, and ldd
        # notes the missing execute bit while still resolving them correctly.
        # That is normal for a library and says nothing about its dependencies.
        noise = [
            line for line in out.stderr.splitlines()
            if line.strip()
            and "you do not have execution permission" not in line
        ]
        if noise:
            failures.append(f"{rel}: ldd wrote to stderr: "
                            + "; ".join(l.strip() for l in noise))
    if failures:
        print("unresolved dynamic dependencies:", file=sys.stderr)
        for f in failures:
            print("  -", f, file=sys.stderr)
        sys.exit(1)
    print(f"all {len(report['programs']) + len(report['libraries'])} patched "
          f"ELF files resolve cleanly")
    PY

    echo "untouched files must really be untouched"
    python3 - <<'PY'
    import json
    report = json.load(open("${chatgpt}/share/chatgpt-desktop/elf-patch-report.json"))
    assert report["untouched"], "expected some files to be left alone"
    print(f"{len(report['untouched'])} files left byte-identical")
    PY
  '';

  origin-runpath = check "origin-runpath" [ pkgs.patchelf pkgs.python3 ] ''
    echo "native modules must keep their \$ORIGIN lookups first"
    sharp=$(find ${app}/resources -name 'sharp-linux-*.node' | head -1)
    if [ -n "$sharp" ]; then
      rpath="$(patchelf --print-rpath "$sharp")"
      echo "  sharp RUNPATH: $rpath"
      case "$rpath" in
        '$ORIGIN'*) ;;
        *) echo "sharp lost its \$ORIGIN prefix" >&2; exit 1 ;;
      esac
      echo "$rpath" | grep -q 'sharp-libvips' \
        || { echo "sharp can no longer find libvips" >&2; exit 1; }
    fi
  '';

  qt-shims-unlinked = check "qt-shims-unlinked" [ pkgs.python3 ] ''
    echo "we must not have pulled in both Qt 5 and Qt 6 for optional shims"
    python3 - <<'PY'
    import json, sys
    inv = json.load(open("${chatgpt}/share/chatgpt-desktop/elf-inventory.json"))
    shims = [e for e in inv["entries"] if e["kind"] == "optional-qt-shim"]
    assert shims, "expected the Qt keyring shims to be present and classified"
    for shim in shims:
        assert shim["action"] == "leave-alone", shim
        assert not shim["runpath"], f"{shim['path']} was given a RUNPATH: {shim['runpath']}"
        print(f"  {shim['path']}: left unlinked ({', '.join(shim['needed'][:3])}...)")
    PY

    echo "and the closure must not contain Qt"
    if grep -rlE 'qtbase-[0-9]' ${app} 2>/dev/null | head -1 | grep -q .; then
      echo "Qt leaked into the package" >&2; exit 1
    fi
  '';

  # --- bundled helper smoke ----------------------------------------------

  bundled-helpers = check "bundled-helpers" [ pkgs.python3 ] ''
    echo "ripgrep"
    ${app}/resources/rg --version | head -1

    echo "bundled node"
    ${app}/resources/cua_node/bin/node --version

    echo "bundled codex"
    # Actually run it. `test -x` proves a permission bit, not that the binary
    # loads, and `|| true` would swallow the failure it exists to catch.
    codex_version="$(${app}/resources/codex --version)"
    echo "  $codex_version"
    case "$codex_version" in
      *codex*) ;;
      *) echo "codex --version produced unexpected output" >&2; exit 1 ;;
    esac

    echo "tectonic (static)"
    ${app}/resources/plugins/openai-bundled/plugins/latex/bin/tectonic --version
  '';

  node-glibc-detection = check "node-glibc-detection" [ pkgs.python3 ] ''
    # The real regression: run the bundled Node and make it perform the same
    # libc detection that detect-libc does, against the patched main binary.
    # This is the code path that SIGILLs when PT_INTERP is out of range.
    cat > probe.js <<'JS'
    const fs = require('fs');
    const buf = Buffer.alloc(2048);
    const fd = fs.openSync(process.argv[2], 'r');
    fs.readSync(fd, buf, 0, 2048, 0);
    fs.closeSync(fd);
    const phoff = Number(buf.readBigUInt64LE(32));
    const phentsize = buf.readUInt16LE(54);
    const phnum = buf.readUInt16LE(56);
    let result = null;
    for (let i = 0; i < phnum; i++) {
      const base = phoff + i * phentsize;
      if (base + 56 > buf.length) break;
      if (buf.readUInt32LE(base) !== 3) continue;
      const off = Number(buf.readBigUInt64LE(base + 8));
      const size = Number(buf.readBigUInt64LE(base + 32));
      const s = buf.subarray(off, off + size).toString('utf8').replace(/\0.*$/, "");
      if (s.includes('/ld-musl-')) result = 'musl';
      else if (s.includes('/ld-linux-')) result = 'glibc';
      break;
    }
    console.log(result);
    if (result !== 'glibc') {
      console.error('detect-libc would fail here — this is the SIGILL path');
      process.exit(1);
    }
    JS
    ${app}/resources/cua_node/bin/node probe.js ${app}/ChatGPT
  '';

  # --- bwrap / nix-ld bridge ---------------------------------------------

  bwrap-shim-parser = check "bwrap-shim-parser" [ pkgs.python3 ] ''
    # Drive the shim's bubblewrap option parser directly. The splice point has
    # to land after ALL of the caller's options: a caller's own --clearenv or
    # --setenv appearing later would override ours, and a bind placed before
    # their filesystem mounts is simply covered by them.
    trace=${chatgpt.bwrapShimTest}/bin/bwrap-trace
    test -x "$trace"

    run() {
      rm -f out.txt
      CHATGPT_BWRAP_SHIM_TRACE="$PWD/out.txt" "$trace" "$@" >/dev/null 2>&1 || true
    }

    python3 - <<'PY' > cases.json
    import json
    json.dump([
      {
        "name": "Codex-shaped argv",
        "argv": ["--unshare-user", "--unshare-net", "--ro-bind", "/", "/",
                 "--tmpfs", "/tmp", "--", "/bin/sh", "-c", "id"],
        "rewritten": True,
        "tail": ["--", "/bin/sh", "-c", "id"],
      },
      {
        "name": "'--' as the VALUE of --setenv is not the separator",
        "argv": ["--setenv", "FOO", "--", "--ro-bind", "/", "/", "--",
                 "/bin/true"],
        "rewritten": True,
        "tail": ["--", "/bin/true"],
      },
      {
        "name": "no '--' separator at all",
        "argv": ["--unshare-user", "--ro-bind", "/", "/", "/bin/echo", "hi"],
        "rewritten": True,
        "tail": ["/bin/echo", "hi"],
      },
      {
        "name": "three-arity --overlay is consumed correctly",
        "argv": ["--overlay", "/a", "/b", "/c", "--ro-bind", "/", "/", "--",
                 "/bin/true"],
        "rewritten": True,
        "tail": ["--", "/bin/true"],
      },
      {
        "name": "--args hides options, so pass through untouched",
        "argv": ["--args", "3", "--ro-bind", "/", "/", "--", "/bin/true"],
        "rewritten": False,
      },
      {
        "name": "an unknown option means pass through untouched",
        "argv": ["--some-future-option", "x", "--", "/bin/true"],
        "rewritten": False,
      },
      {
        "name": "a truncated option means pass through untouched",
        "argv": ["--unshare-user", "--setenv", "ONLYONE"],
        "rewritten": False,
      },
    ], open("cases.json", "w"))
    PY

    python3 - <<'PY'
    import json, os, subprocess, sys
    trace = "${chatgpt.bwrapShimTest}/bin/bwrap-trace"
    failures = []
    for case in json.load(open("cases.json")):
        out = os.path.abspath("out.txt")
        if os.path.exists(out):
            os.unlink(out)
        env = dict(os.environ, CHATGPT_BWRAP_SHIM_TRACE=out)
        subprocess.run([trace] + case["argv"], env=env,
                       capture_output=True)
        produced = os.path.exists(out)
        if produced != case["rewritten"]:
            failures.append(
                f"{case['name']}: expected rewritten={case['rewritten']}, "
                f"got {produced}")
            continue
        if not produced:
            print(f"  ok  {case['name']} (passed through)")
            continue
        args = [l for l in open(out).read().split("\n") if l]
        tail = args[-len(case["tail"]):]
        if tail != case["tail"]:
            failures.append(f"{case['name']}: tail is {tail}, expected "
                            f"{case['tail']}")
            continue
        head = args[:-len(case["tail"])]
        for needed in ("--ro-bind", "--setenv", "NIX_LD", "NIX_LD_LIBRARY_PATH"):
            if needed not in head:
                failures.append(f"{case['name']}: {needed} missing from {head}")
        # Everything the caller passed must still precede our injection.
        caller_head = case["argv"][:len(case["argv"]) - len(case["tail"])]
        if head[:len(caller_head)] != caller_head:
            failures.append(
                f"{case['name']}: caller options were reordered: "
                f"{head[:len(caller_head)]} != {caller_head}")
        else:
            print(f"  ok  {case['name']}")
    if failures:
        for f in failures:
            print("  FAIL", f, file=sys.stderr)
        sys.exit(1)
    print("every splice point is correct")
    PY
  '';

  bwrap-shim-production-has-no-trace-hook =
    check "bwrap-shim-production-has-no-trace-hook" [ ] ''
    # The production binary must not contain the trace hook at all. An
    # inherited environment variable that suppresses the sandbox and truncates
    # a file of the caller's choosing is not a debugging aid, it is a hole.
    if grep -q 'CHATGPT_BWRAP_SHIM_TRACE' ${chatgpt.bwrapShim}/bin/bwrap; then
      echo "the production shim contains the trace hook" >&2
      exit 1
    fi
    echo "production shim has no trace hook"
  '';

  # --- writable plugin cache ---------------------------------------------

  plugin-cache = check "plugin-cache" [ pkgs.bash pkgs.util-linux pkgs.coreutils ] ''
    # Drive the launcher's cache logic directly, including the failure modes
    # that only show up on a second or concurrent launch.
    export HOME=$PWD/home
    export XDG_CACHE_HOME=$PWD/home/.cache
    mkdir -p "$XDG_CACHE_HOME"

    # Extract the cache functions so we can call them in isolation.
    for fn in publish_plugin_cache collect_unused_caches inuse_lock degrade \
              cache_is_valid release_cache_locks; do
      sed -n "/^$fn()/,/^}/p" ${launcher} >> lib.sh
    done
    cat > drive.sh <<'SH'
    set -uo pipefail
    warn() { printf 'warn: %s\n' "$1" >&2; }
    source ./lib.sh
    publish_plugin_cache "$1" "$2" "$3"
    SH

    res=${app}/resources
    root="$XDG_CACHE_HOME/t"

    echo "--- first launch builds the cache ---"
    pub1=$(bash drive.sh "$res" "$root" key1)
    test -e "$pub1/.complete"
    test -d "$pub1/plugins"
    test -L "$pub1/app.asar"
    echo "  published at $pub1, app.asar symlinked, plugins copied"

    echo "--- the plugins copy must be writable ---"
    touch "$pub1/plugins/openai-bundled/.writetest"

    echo "--- second launch reuses it ---"
    pub2=$(bash drive.sh "$res" "$root" key1)
    test "$pub1" = "$pub2"
    test -e "$pub2/plugins/openai-bundled/.writetest"
    echo "  reused without rebuilding"

    echo "--- a partial cache is discarded, not trusted ---"
    chmod -R u+w "$pub1"; rm -f "$pub1/.complete"; rm -rf "$pub1/plugins"
    pub3=$(bash drive.sh "$res" "$root" key1)
    test -e "$pub3/.complete"
    test -d "$pub3/plugins"
    test ! -e "$pub3/plugins/openai-bundled/.writetest"
    echo "  rebuilt from scratch after an interrupted publish"

    echo "--- concurrent launches converge on one cache ---"
    rm -rf "$root"
    for i in 1 2 3 4 5 6; do bash drive.sh "$res" "$root" key2 > "out.$i" & done
    wait
    sort -u out.1 out.2 out.3 out.4 out.5 out.6 > distinct
    test "$(wc -l < distinct)" = 1
    test -e "$(cat distinct)/.complete"
    echo "  6 concurrent launches produced exactly one published cache"

    echo "--- a stamped but DAMAGED cache is rebuilt, not trusted ---"
    # The completion marker says a publish finished, not that what it published
    # is still intact. A cache can be damaged afterwards and the marker would
    # still be sitting there.
    pubD=$(bash drive.sh "$res" "$root" keyDMG)
    test -e "$pubD/.complete"
    chmod -R u+w "$pubD"
    rm -rf "$pubD/plugins/openai-bundled"
    test -e "$pubD/.complete"
    again=$(bash drive.sh "$res" "$root" keyDMG)
    test "$again" = "$pubD"
    test -d "$again/plugins/openai-bundled/plugins" \
      || { echo "a damaged cache was handed back unrepaired" >&2; exit 1; }
    echo "  damaged tree rebuilt under the lock"

    echo "--- a cache whose immutable resources vanished is rebuilt ---"
    pubS=$(bash drive.sh "$res" "$root" keySYM)
    chmod -R u+w "$pubS"; rm -f "$pubS/app.asar"
    againS=$(bash drive.sh "$res" "$root" keySYM)
    test -e "$againS/app.asar" \
      || { echo "a cache missing app.asar was handed back" >&2; exit 1; }
    echo "  missing immutable resource rebuilt"

    echo "--- another version's cache is NOT collected ---"
    # Collecting one safely needs the exclusive lock held across the deletion.
    # `flock <lock> --command true` releases it the moment `true` exits, so
    # between the check and the `rm -rf` another launch can legitimately claim
    # the cache being deleted. Not collecting is the safe choice; the cost is
    # bounded and visible.
    bash drive.sh "$res" "$root" keyA > /dev/null
    bash drive.sh "$res" "$root" keyB > /dev/null
    test -d "$root/keyA"
    test -d "$root/keyB"
    echo "  keyA survived a publish of keyB"

    echo "--- an EMPTIED bundled-plugin tree is caught ---"
    # The two directories exist and the marker is there; only their contents
    # are gone. Checking that the paths exist says nothing about that, so this
    # damage used to be handed straight back to the application.
    pubE=$(bash drive.sh "$res" "$root" keyEMPTY)
    chmod -R u+w "$pubE"
    victim=$(find "$pubE/plugins/openai-bundled/plugins" -maxdepth 1 -mindepth 1 \
             | head -1)
    test -n "$victim" || { echo "no bundled plugin to remove" >&2; exit 1; }
    rm -rf "$victim"
    test -d "$pubE/plugins/openai-bundled/plugins"   # still there, still stamped
    test -e "$pubE/.complete"
    againE=$(bash drive.sh "$res" "$root" keyEMPTY)
    test -e "$victim" \
      || { echo "an emptied bundled-plugin tree was handed back" >&2; exit 1; }
    echo "  missing bundled plugin detected and rebuilt"

    echo "--- a damaged cache IN USE is not destroyed under the running app ---"
    # The build lock serialises builders. A running instance is not a builder:
    # it holds the in-use lock, shared, for its whole lifetime. Destroying the
    # entry without asking that lock deletes the resources of a running
    # application.
    pubU=$(bash drive.sh "$res" "$root" keyUSE)
    chmod -R u+w "$pubU"
    canary="$pubU/plugins/CANARY"; : > "$canary"
    rm -f "$pubU/app.asar"                       # make it invalid
    lockfile="$(bash -c 'source ./lib.sh; inuse_lock "$1" "$2"' _ "$root" keyUSE)"
    : >> "$lockfile"
    exec {hold}>>"$lockfile"
    flock --shared --nonblock "$hold" \
      || { echo "could not take the in-use lock" >&2; exit 1; }
    outU=$(bash drive.sh "$res" "$root" keyUSE 2>err.txt)
    test -e "$canary" \
      || { echo "the cache was destroyed while another instance held it" >&2
           cat err.txt >&2; exit 1; }
    grep -q 'another instance is using it' err.txt \
      || { echo "no diagnostic explaining the refusal:" >&2; cat err.txt >&2; exit 1; }
    test "$outU" = "$res" \
      || { echo "expected a fall back to the store resources, got $outU" >&2; exit 1; }
    echo "  refused to destroy it, fell back to the read-only store copy"

    echo "--- and once nothing holds it, the same cache IS rebuilt ---"
    exec {hold}>&-
    againU=$(bash drive.sh "$res" "$root" keyUSE)
    test "$againU" = "$root/keyUSE"
    test -e "$againU/app.asar"
    test ! -e "$canary"
    echo "  rebuilt after the holder released the lock"

    echo "--- another key's staging directory is left alone ---"
    # Staging cleanup runs under this key's build lock only, so it has no
    # standing to remove a directory another key may be writing right now.
    mkdir -p "$root/.staging-keyOTHER.XXXX"
    bash drive.sh "$res" "$root" keyC > /dev/null
    test -d "$root/.staging-keyOTHER.XXXX"
    echo "  a different key's staging dir was not swept"
    rm -rf "$root/.staging-keyOTHER.XXXX"

    echo "--- this key's own abandoned staging dir IS swept ---"
    mkdir -p "$root/.staging-key4.ORPHAN"
    bash drive.sh "$res" "$root" key4 > /dev/null
    test ! -e "$root/.staging-key4.ORPHAN"
    echo "  our own orphaned staging directory removed"

    echo "--- simultaneous publishes of DIFFERENT keys all succeed ---"
    rm -rf "$root"
    for k in kA kB kC kD; do bash drive.sh "$res" "$root" "$k" > "p.$k" & done
    wait
    for k in kA kB kC kD; do
      # Deliberately not named "out": that is Nix's output path, and shadowing
      # it makes the wrapper's final `touch "$out"` land on the cache instead.
      published="$(cat "p.$k")"
      test -e "$published/.complete" || { echo "$k did not publish" >&2; exit 1; }
      test -d "$published/plugins"   || { echo "$k has no plugins" >&2; exit 1; }
    done
    echo "  four different keys published concurrently without interfering"
  '';

  # --- desktop integration ------------------------------------------------

  desktop-entry = check "desktop-entry" [ pkgs.desktop-file-utils ] ''
    desktop-file-validate ${chatgpt}/share/applications/chatgpt.desktop

    echo "Exec must point at the packaged launcher"
    grep -q "^Exec=${chatgpt}/bin/chatgpt %U$" \
      ${chatgpt}/share/applications/chatgpt.desktop

    echo "upstream branding and MIME handlers must be preserved"
    grep -q '^Name=ChatGPT$' ${chatgpt}/share/applications/chatgpt.desktop
    grep -q 'x-scheme-handler/codex' ${chatgpt}/share/applications/chatgpt.desktop

    echo "icons must be installed"
    test -f ${chatgpt}/share/pixmaps/chatgpt.png
    test -f ${chatgpt}/share/icons/hicolor/512x512/apps/chatgpt.png
  '';

  no-upstream-host-config = check "no-upstream-host-config" [ ] ''
    echo "we must not ship the upstream APT or AppArmor configuration"
    for bad in etc/apparmor.d/chatgpt etc/apt etc/default/chatgpt; do
      if [ -e "${chatgpt}/$bad" ]; then
        echo "package contains $bad" >&2; exit 1
      fi
    done
    test ! -e ${chatgpt}/lib/chatgpt/codex-launcher
    echo "no host configuration is installed"
  '';
}
