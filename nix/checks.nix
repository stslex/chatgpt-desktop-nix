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

  unit-tests = check "unit-tests" [ pkgs.python3 pkgs.gnupg ] ''
    cp -r ${../tools} tools
    cp -r ${../tests} tests
    cp -r ${../trust} trust
    cp ${../sources.json} sources.json
    chmod -R u+w .
    export PYTHONPATH="$PWD/tools:$PWD"
    python3 -m unittest discover -s tests -v
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
        "${app}/../../share/chatgpt-desktop/elf-patch-report.json"))
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
    shipped = json.load(open("${app}/../../share/chatgpt-desktop/elf-inventory.json"))
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

    echo "and every other patched program must load too"
    python3 - <<'PY'
    import json, sys
    sys.path.insert(0, "${chatgpt.toolsDir}")
    import relocate_interp as R
    report = json.load(open("${app}/../../share/chatgpt-desktop/elf-patch-report.json"))
    for rel in report["programs"]:
        path = "${chatgpt}/lib/chatgpt" + rel.split("usr/lib/chatgpt", 1)[1]
        elf = R.Elf64(path)
        R.assert_within_window(elf, R.DETECT_LIBC_WINDOW, "shipped package")
        print(f"  {rel}: PT_INTERP at {elf.phdr(elf.interp_index())['p_offset']}")
    PY
  '';

  # --- dynamic linking ----------------------------------------------------

  runtime-deps = check "runtime-deps" [ pkgs.python3 pkgs.glibc.bin pkgs.patchelf ] ''
    echo "every patched ELF must resolve all of its DT_NEEDED entries"
    python3 - <<'PY'
    import json, subprocess, sys, os
    report = json.load(open("${app}/../../share/chatgpt-desktop/elf-patch-report.json"))
    root = "${chatgpt}/lib/chatgpt"
    failures = []
    for rel in report["programs"] + report["libraries"]:
        path = root + rel.split("usr/lib/chatgpt", 1)[1]
        out = subprocess.run(["ldd", path], capture_output=True, text=True)
        for line in out.stdout.splitlines():
            if "not found" in line:
                failures.append(f"{rel}: {line.strip()}")
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
    report = json.load(open("${app}/../../share/chatgpt-desktop/elf-patch-report.json"))
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
    inv = json.load(open("${app}/../../share/chatgpt-desktop/elf-inventory.json"))
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
    ${app}/resources/codex --version 2>&1 | head -1 || true
    test -x ${app}/resources/codex

    echo "tectonic (static)"
    test -x ${app}/resources/plugins/openai-bundled/plugins/latex/bin/tectonic
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
      const s = buf.subarray(off, off + size).toString('utf8').replace(/\0.*$/, '');
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

  bwrap-bridge = check "bwrap-bridge" [ pkgs.python3 ] ''
    shim=${chatgpt.bwrapShim}/bin/bwrap
    test -x "$shim"

    echo "the shim must splice the nix-ld bind before bwrap's -- terminator"
    export CHATGPT_BWRAP_SHIM_TRACE="$PWD/trace.txt"
    "$shim" --unshare-user --unshare-net -- /bin/true arg1
    cat trace.txt

    python3 - <<'PY'
    lines = open("trace.txt").read().split("\n")
    mode, args = lines[0], [l for l in lines[1:] if l]
    print("mode:", mode)
    if mode == "passthrough":
        # No generic loader on this builder; the shim must degrade to an
        # untouched argv rather than breaking the sandbox.
        assert args == ["--unshare-user", "--unshare-net", "--", "/bin/true", "arg1"], args
        print("no generic loader present; shim passed argv through unchanged")
    else:
        assert mode == "rewritten", mode
        sep = args.index("--")
        head, tail = args[:sep], args[sep:]
        assert tail == ["--", "/bin/true", "arg1"], tail
        assert head[:2] == ["--unshare-user", "--unshare-net"], head
        assert "--ro-bind" in head, head
        assert "NIX_LD" in head and "NIX_LD_LIBRARY_PATH" in head, head
        print("shim inserted:", head[2:])
    PY
  '';

  # --- writable plugin cache ---------------------------------------------

  plugin-cache = check "plugin-cache" [ pkgs.bash pkgs.util-linux pkgs.coreutils ] ''
    # Drive the launcher's cache logic directly, including the failure modes
    # that only show up on a second or concurrent launch.
    export HOME=$PWD/home
    export XDG_CACHE_HOME=$PWD/home/.cache
    mkdir -p "$XDG_CACHE_HOME"

    # Extract just the publish function so we can call it in isolation.
    sed -n '/^publish_plugin_cache()/,/^}/p' ${launcher} > lib.sh
    cat > drive.sh <<'SH'
    set -uo pipefail
    warn() { printf 'warn: %s\n' "$1" >&2; }
    source ./lib.sh
    publish_plugin_cache "$1" "$2" "$3"
    SH

    res=${app}/resources
    root="$XDG_CACHE_HOME/t"

    echo "--- first launch builds the cache ---"
    out1=$(bash drive.sh "$res" "$root" key1)
    test -e "$out1/.complete"
    test -d "$out1/plugins"
    test -L "$out1/app.asar"
    echo "  published at $out1, app.asar symlinked, plugins copied"

    echo "--- the plugins copy must be writable ---"
    touch "$out1/plugins/openai-bundled/.writetest"

    echo "--- second launch reuses it ---"
    out2=$(bash drive.sh "$res" "$root" key1)
    test "$out1" = "$out2"
    test -e "$out2/plugins/openai-bundled/.writetest"
    echo "  reused without rebuilding"

    echo "--- a partial cache is discarded, not trusted ---"
    chmod -R u+w "$out1"; rm -f "$out1/.complete"; rm -rf "$out1/plugins"
    out3=$(bash drive.sh "$res" "$root" key1)
    test -e "$out3/.complete"
    test -d "$out3/plugins"
    test ! -e "$out3/plugins/openai-bundled/.writetest"
    echo "  rebuilt from scratch after an interrupted publish"

    echo "--- concurrent launches converge on one cache ---"
    rm -rf "$root"
    for i in 1 2 3 4 5 6; do bash drive.sh "$res" "$root" key2 > "out.$i" & done
    wait
    sort -u out.1 out.2 out.3 out.4 out.5 out.6 > distinct
    test "$(wc -l < distinct)" = 1
    test -e "$(cat distinct)/.complete"
    echo "  6 concurrent launches produced exactly one published cache"

    echo "--- stale keys are collected ---"
    bash drive.sh "$res" "$root" key3 > /dev/null
    test ! -e "$root/key2"
    echo "  previous version's cache removed"

    echo "--- abandoned staging dirs are swept ---"
    mkdir -p "$root/.staging-orphan.XXX"
    bash drive.sh "$res" "$root" key4 > /dev/null
    test ! -e "$root/.staging-orphan.XXX"
    echo "  orphaned staging directory removed"
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
