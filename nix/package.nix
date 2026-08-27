{ lib
, stdenv
, fetchurl
, runCommandCC

, dpkg
, patchelf
, python3
, desktop-file-utils
, util-linux
, bubblewrap
, nix-ld

  # Runtime libraries. Each entry below is here because something in the
  # payload names it in DT_NEEDED, or dlopens it at runtime.
, alsa-lib
, at-spi2-atk
, at-spi2-core
, atk
, cairo
, cups
, curl
, dbus
, expat
, fontconfig
, freetype
, gdk-pixbuf
, glib
, gtk3
, libGL
, libdrm
, libgbm
, libglvnd
, libnotify
, libpulseaudio
, libsecret
, libusb1
, libxkbcommon
, libxcrypt-legacy
, mesa
, nspr
, nss
, pango
, pipewire
, systemd
, vulkan-loader
, wayland
, libx11
, libxcb
, libxcomposite
, libxcursor
, libxdamage
, libxext
, libxfixes
, libxi
, libxrandr
, libxscrnsaver
, libxshmfence
, libxtst
, zlib

  # Tools the app expects to find on PATH.
, bash
, coreutils
, findutils
, gawk
, git
, gnugrep
, gnused
, gnutar
, gzip
, procps
, xz
, which
, xdg-utils

, sources ? lib.importJSON ../sources.json
}:

let
  inherit (sources) version;

  debArch = {
    x86_64-linux = "amd64";
    aarch64-linux = "arm64";
  }.${stdenv.hostPlatform.system} or (throw
    "chatgpt-desktop: unsupported system ${stdenv.hostPlatform.system}");

  source = sources.architectures.${debArch} or (throw
    "chatgpt-desktop: sources.json has no entry for ${debArch}");


  # Libraries resolved through each ELF's own RUNPATH. Never exported as
  # LD_LIBRARY_PATH: that would leak into git/node/python children the app
  # spawns and break their own dynamic linking.
  runtimeLibraries = [
    # Chromium / Electron / GTK core
    alsa-lib atk at-spi2-atk at-spi2-core cairo cups dbus expat
    gdk-pixbuf glib gtk3 pango stdenv.cc.cc.lib

    # Graphics
    libdrm libgbm libGL libglvnd mesa vulkan-loader

    # X11 and Wayland
    libxkbcommon wayland
    libx11 libxcomposite libxcursor libxdamage
    libxext libxfixes libxi libxrandr
    libxscrnsaver libxtst libxcb libxshmfence

    # Audio
    libpulseaudio pipewire

    # Crypto, secrets, devices
    nss nspr libsecret libusb1 systemd

    # Fonts and misc
    fontconfig freetype libnotify libxcrypt-legacy zlib curl
  ];

  libraryPath = lib.makeLibraryPath runtimeLibraries;

  # Tools appended to the user's PATH. This is deliberately small: the app runs
  # inside the user's own shell environment and must keep seeing their git,
  # their nix and their toolchains.
  packageBins = lib.makeBinPath [
    bash coreutils findutils gawk gnugrep gnused gnutar gzip
    git procps which xdg-utils util-linux bubblewrap

    # `xz`: the payload handles .tar.xz, and GNU tar shells out to the xz
    # binary for those. Upstream's Depends lists xz-utils for the same reason.
    xz

    # `gio`, from glib: Electron's shell.trashItem() has no in-process
    # implementation on Linux and execs a trash helper. The payload references
    # trashItem in a dozen places, and upstream's Depends lists
    # `libglib2.0-bin | kde-cli-tools | ... | trash-cli | gvfs-bin` -- that
    # alternation is exactly this dependency. glib.bin provides gio.
    glib.bin
  ];

  # A `bwrap` that bridges downloaded generic binaries into the sandbox on
  # NixOS. See nix/bwrap-shim.c for why it injects only NIX_LD variables and
  # never a bind mount.
  # The upstream loader path each architecture's binaries name.
  genericInterpreter = {
    x86_64-linux = "/lib64/ld-linux-x86-64.so.2";
    aarch64-linux = "/lib/ld-linux-aarch64.so.1";
  }.${stdenv.hostPlatform.system};

  bwrapShimFlags = lib.concatStringsSep " " [
    "-DREAL_BWRAP='\"${bubblewrap}/bin/bwrap\"'"
    "-DNIX_LD_PATH='\"${nix-ld}/libexec/nix-ld\"'"
    "-DGENERIC_INTERPRETER='\"${genericInterpreter}\"'"
    "-DNIX_LD_TARGET='\"${stdenv.cc.bintools.dynamicLinker}\"'"
    "-DNIX_LD_LIBRARY_PATH_VALUE='\"${libraryPath}\"'"
  ];

  bwrapShim = runCommandCC "chatgpt-bwrap-shim-${version}"
    {
      meta.description =
        "bwrap wrapper that injects NIX_LD into Codex's command sandbox";
    }
    ''
      mkdir -p "$out/bin"
      cc -O2 -Wall -Wextra -Werror -std=gnu11 \
        ${bwrapShimFlags} \
        -o "$out/bin/bwrap" ${./bwrap-shim.c}
    '';

  # The same source compiled with a trace hook, for tests only. The production
  # binary above has no such hook: an inherited environment variable must never
  # be able to suppress the sandbox or choose a file to truncate.
  bwrapShimTest = runCommandCC "chatgpt-bwrap-shim-test-${version}" { }
    ''
      mkdir -p "$out/bin"
      cc -O2 -Wall -Wextra -Werror -std=gnu11 \
        ${bwrapShimFlags} \
        -DSHIM_TRACE_ENV='"CHATGPT_BWRAP_SHIM_TRACE"' \
        -o "$out/bin/bwrap-trace" ${./bwrap-shim.c}
    '';

  elfBaseline = ../elf-baseline/${stdenv.hostPlatform.system}.json;

  # Ship the whole tools directory as one store path so the modules can
  # import each other at build time.
  toolsDir = lib.cleanSourceWith {
    src = ../tools;
    filter = path: _type: lib.hasSuffix ".py" path;
  };

in
stdenv.mkDerivation (finalAttrs: {
  pname = "chatgpt-desktop";
  inherit version;

  src = fetchurl {
    inherit (source) url hash;
  };

  nativeBuildInputs = [
    dpkg patchelf python3 desktop-file-utils
  ];

  # The payload is already built; we only relocate it.
  dontConfigure = true;
  dontBuild = true;
  dontStrip = true;
  dontPatchELF = true;
  dontAutoPatchelf = true;
  # The automatic sweep would rewrite shebangs throughout the vendored npm,
  # corepack and playwright trees. Those are upstream payload files and must
  # stay byte-identical; our own launcher is patched explicitly instead.
  dontPatchShebangs = true;

  unpackPhase = ''
    runHook preUnpack

    # --extract unpacks only data.tar. It never runs a maintainer script, so
    # the upstream postinst (which would install an APT source, a keyring and
    # an AppArmor profile) is not executed.
    mkdir -p payload
    dpkg-deb --extract "$src" payload

    runHook postUnpack
  '';

  installPhase = ''
    runHook preInstall

    echo "--- verifying the ELF inventory against the reviewed baseline ---"
    python3 ${toolsDir}/elf_classify.py payload \
      --system ${stdenv.hostPlatform.system} \
      --baseline ${elfBaseline} \
      --emit elf-inventory.json

    echo "--- recording app.asar identity before any patching ---"
    asarBefore="$(sha256sum payload/usr/lib/chatgpt/resources/app.asar | cut -d' ' -f1)"

    echo "--- patching only the ELF files the classifier selected ---"
    python3 ${toolsDir}/patch_elves.py payload \
      --system ${stdenv.hostPlatform.system} \
      --interpreter "${stdenv.cc.bintools.dynamicLinker}" \
      --runpath "${libraryPath}" \
      --patchelf "${patchelf}/bin/patchelf" \
      --report elf-patch-report.json \
      --require-in-window usr/lib/chatgpt/ChatGPT \
      --relocate usr/lib/chatgpt/ChatGPT \
      --expect-in-window ${../elf-baseline/interp-window-${stdenv.hostPlatform.system}.json}

    echo "--- app.asar must be byte-identical ---"
    asarAfter="$(sha256sum payload/usr/lib/chatgpt/resources/app.asar | cut -d' ' -f1)"
    if [ "$asarBefore" != "$asarAfter" ]; then
      echo "app.asar changed during the build ($asarBefore -> $asarAfter)" >&2
      exit 1
    fi
    echo "app.asar sha256 $asarAfter (unchanged)"

    mkdir -p "$out/lib" "$out/bin" "$out/share"
    cp -r payload/usr/lib/chatgpt "$out/lib/chatgpt"

    # The upstream launcher is a two-line shell script that resolves its own
    # symlink; ours supersedes it.
    rm -f "$out/lib/chatgpt/codex-launcher"

    install -Dm444 elf-inventory.json "$out/share/chatgpt-desktop/elf-inventory.json"
    install -Dm444 elf-patch-report.json "$out/share/chatgpt-desktop/elf-patch-report.json"

    echo "--- launcher ---"
    # Key the writable plugin mirror on this output's own store hash.
    #
    # An earlier version keyed it on the *pre-patch* ELF inventory, which is
    # identical for the same upstream version regardless of what it was built
    # against. Rebuilding the same version on a different nixpkgs revision
    # would then reuse a cache whose copied native modules were patched for the
    # old closure and whose symlinks point into a store path that may since
    # have been garbage collected. The output hash changes whenever anything
    # about the build does, which is exactly the property needed here.
    resourceKey="${version}-$(basename "$out" | cut -c1-32)"

    substitute ${../nix/launcher.sh} "$out/bin/chatgpt" \
      --subst-var-by out "$out" \
      --subst-var-by packageBins "${packageBins}" \
      --subst-var-by bwrapShim "${bwrapShim}/bin" \
      --subst-var-by resourceKey "$resourceKey" \
      --subst-var-by preamble "export PATH=\"${lib.makeBinPath [ coreutils util-linux ]}:\$PATH\""
    chmod +x "$out/bin/chatgpt"
    patchShebangs "$out/bin/chatgpt"

    echo "--- desktop entry, icons and MIME handlers ---"
    install -Dm444 payload/usr/share/applications/chatgpt.desktop \
      "$out/share/applications/chatgpt.desktop"
    # Point Exec at our launcher rather than the bare name the .deb assumes.
    substituteInPlace "$out/share/applications/chatgpt.desktop" \
      --replace-fail "Exec=chatgpt %U" "Exec=$out/bin/chatgpt %U"

    install -Dm444 payload/usr/share/pixmaps/chatgpt.png \
      "$out/share/pixmaps/chatgpt.png"
    install -Dm444 payload/usr/lib/chatgpt/resources/icon-chatgpt.png \
      "$out/share/icons/hicolor/512x512/apps/chatgpt.png"

    # Upstream licence text for the bundled Electron/Chromium.
    install -Dm444 payload/usr/share/doc/chatgpt/copyright \
      "$out/share/doc/chatgpt-desktop/upstream-copyright"

    runHook postInstall
  '';

  # Deliberately NOT installed from the payload:
  #   etc/apparmor.d/chatgpt  - host AppArmor policy is the user's business
  #   usr/bin/chatgpt         - symlink to the upstream launcher we replaced
  #   DEBIAN maintainer scripts - would rewrite APT config on the host

  doInstallCheck = true;
  installCheckPhase = ''
    runHook preInstallCheck

    echo "--- the interpreter must stay inside the detect-libc window ---"
    python3 ${toolsDir}/relocate_interp.py \
      "$out/lib/chatgpt/ChatGPT" --verify-only --require-glibc-detection

    echo "--- no --no-sandbox anywhere in the launcher ---"
    if grep -q -- "--no-sandbox" "$out/bin/chatgpt"; then
      echo "launcher contains --no-sandbox" >&2
      exit 1
    fi

    echo "--- no global LD_LIBRARY_PATH ---"
    if grep -qE '^[^#]*\bexport +LD_LIBRARY_PATH=' "$out/bin/chatgpt"; then
      echo "launcher exports LD_LIBRARY_PATH" >&2
      exit 1
    fi

    echo "--- desktop entry validates ---"
    desktop-file-validate "$out/share/applications/chatgpt.desktop"

    echo "--- launcher parses ---"
    ${bash}/bin/bash -n "$out/bin/chatgpt"

    runHook postInstallCheck
  '';

  passthru = {
    inherit bwrapShim bwrapShimTest sources toolsDir;
    updateScript = "${toolsDir}/update.py";
  };

  meta = {
    description = "ChatGPT Desktop by OpenAI, repackaged from the official Linux .deb";
    longDescription = ''
      The official ChatGPT Desktop application for Linux, repackaged for Nix
      from OpenAI's signed APT repository. The upstream Electron payload is
      installed unmodified apart from the ELF relocation Nix requires;
      app.asar is byte-identical to what OpenAI publishes.
    '';
    homepage = "https://developers.openai.com/codex/app";
    downloadPage = "https://learn.chatgpt.com/docs/linux/linux-app";
    changelog = "https://developers.openai.com/codex/changelog";
    license = lib.licenses.unfree;
    sourceProvenance = [ lib.sourceTypes.binaryNativeCode ];
    platforms = [ "x86_64-linux" "aarch64-linux" ];
    mainProgram = "chatgpt";
    maintainers = [ ];
  };
})
