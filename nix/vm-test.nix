{ pkgs, chatgpt }:

let
  # A genuinely generic dynamically-linked ELF: real glibc binary whose
  # PT_INTERP names the path a downloaded toolchain would name. Nothing about
  # it is Nix-aware, which is the point.
  # The loader path a downloaded toolchain names differs per architecture;
  # hardcoding the x86_64 one made this test meaningless on aarch64, where the
  # binary would simply have the wrong interpreter rather than the generic one.
  genericInterpreter = {
    x86_64-linux = "/lib64/ld-linux-x86-64.so.2";
    aarch64-linux = "/lib/ld-linux-aarch64.so.1";
  }.${pkgs.stdenv.hostPlatform.system};

  genericBinary = pkgs.runCommandCC "generic-interp-probe" { } ''
    mkdir -p "$out/bin"
    cat > probe.c <<'EOF'
    #include <stdio.h>
    int main(void) { printf("GENERIC-BINARY-RAN-OK\n"); return 0; }
    EOF
    cc -O0 -o "$out/bin/probe" probe.c
    ${pkgs.patchelf}/bin/patchelf \
      --set-interpreter ${genericInterpreter} \
      --set-rpath "" "$out/bin/probe"
    # Assert it really is generic: a probe still pointing into the store would
    # run regardless of the bridge and prove nothing.
    got="$(${pkgs.patchelf}/bin/patchelf --print-interpreter "$out/bin/probe")"
    if [ "$got" != "${genericInterpreter}" ]; then
      echo "probe interpreter is $got, expected ${genericInterpreter}" >&2
      exit 1
    fi
  '';
in

# A bounded graphical start-up smoke test in a real NixOS VM.
#
# Everything else in checks.nix inspects the package statically. This actually
# boots a machine with an X server, launches the app through its desktop entry
# the way a user would, and then looks for the specific failures that matter:
# SIGILL from the glibc-detection path, dynamic-loader errors, a sandbox that
# refused to start, and helper processes that crash immediately.
#
# It runs under plain X11 rather than a compositor. That matches the default
# path the launcher takes (Electron on XWayland) and is what CI can host; the
# native-Wayland path is opt-in and is covered by manual acceptance instead.

pkgs.testers.runNixOSTest {
  name = "chatgpt-desktop-startup";

  nodes.machine = { pkgs, ... }: {
    virtualisation = {
      memorySize = 4096;
      diskSize = 8192;
      cores = 2;
      # The package is ~1.4 GB; give the store room.
      writableStoreUseTmpfs = false;
    };

    services.xserver = {
      enable = true;
      displayManager.lightdm.enable = true;
      desktopManager.xfce.enable = true;
    };
    services.displayManager.autoLogin = {
      enable = true;
      user = "alice";
    };

    users.users.alice = {
      isNormalUser = true;
      uid = 1000;
      extraGroups = [ "video" ];
    };

    environment.systemPackages = [
      chatgpt pkgs.xdotool pkgs.procps pkgs.bubblewrap genericBinary
    ];

    # Deliberately NOT enabling programs.nix-ld. The default
    # `environment.stub-ld` puts nix-ld at the generic loader path with no
    # NIX_LD configured, which is the situation an ordinary NixOS user is in
    # and the one the bwrap shim exists to fix. Enabling programs.nix-ld would
    # make the bridge test pass for the wrong reason.
    programs.nix-ld.enable = false;

    boot.kernel.sysctl."user.max_user_namespaces" = 28633;

    # A Secret Service implementation, so the app's keyring probe has something
    # to talk to instead of erroring in a way that muddies the log.
    services.gnome.gnome-keyring.enable = true;
    security.pam.services.lightdm.enableGnomeKeyring = true;
  };

  testScript = ''
    import re

    start_all()
    machine.wait_for_x()
    machine.wait_for_unit("graphical.target")

    with subtest("the desktop entry is installed and valid"):
        machine.succeed(
            "test -f ${chatgpt}/share/applications/chatgpt.desktop")
        machine.succeed(
            "grep -q '^Exec=${chatgpt}/bin/chatgpt %U$' "
            "${chatgpt}/share/applications/chatgpt.desktop")

    with subtest("unprivileged user namespaces are available"):
        namespaces = machine.succeed(
            "cat /proc/sys/user/max_user_namespaces").strip()
        assert namespaces != "0", (
            f"user namespaces unavailable ({namespaces}); Chromium's sandbox "
            "cannot start and this package offers no way to disable it"
        )

    with subtest("the launcher runs its preflight without dying"):
        # --version exits immediately, so this exercises the launcher's
        # namespace check, plugin-cache publish and PATH handling without
        # waiting for a window.
        version = machine.succeed(
            "su - alice -c 'timeout 120 ${chatgpt}/bin/chatgpt --version'"
        ).strip()
        assert "${chatgpt.version}" in version, version
        machine.log(f"reported version: {version}")

    with subtest("the writable plugin cache is published under XDG_CACHE_HOME"):
        cache = machine.succeed(
            "su - alice -c 'ls -d ~/.cache/chatgpt-desktop-nix/resources/*/'"
        ).strip()
        machine.succeed(f"test -e {cache}/.complete")
        machine.succeed(f"test -d {cache}/plugins")
        # Large immutable resources are symlinked, not copied.
        machine.succeed(f"test -L {cache}/app.asar")
        machine.log(f"plugin cache: {cache}")

    with subtest("the app starts and maps a window"):
        machine.succeed(
            "su - alice -c 'mkdir -p ~/logs'"
        )
        machine.succeed(
            "su - alice -c 'DISPLAY=:0 nohup ${chatgpt}/bin/chatgpt "
            "> ~/logs/chatgpt.out 2> ~/logs/chatgpt.err & disown'"
        )
        # Bounded wait: the app either maps a window or we fail with its log.
        try:
            machine.wait_until_succeeds(
                "su - alice -c 'DISPLAY=:0 xdotool search --name ChatGPT'",
                timeout=180,
            )
        except Exception:
            machine.log(machine.execute("cat /home/alice/logs/chatgpt.err")[1])
            machine.log(machine.execute("cat /home/alice/logs/chatgpt.out")[1])
            raise
        machine.screenshot("chatgpt-window")

    with subtest("no loader, sandbox or SIGILL failures in the logs"):
        logs = machine.execute("cat /home/alice/logs/chatgpt.err")[1]
        logs += machine.execute("cat /home/alice/logs/chatgpt.out")[1]

        fatal = [
            (r"error while loading shared libraries", "dynamic loader failure"),
            (r"cannot open shared object file", "missing shared library"),
            (r"symbol lookup error", "unresolved symbol"),
            (r"SIGILL|Illegal instruction", "SIGILL — the detect-libc path"),
            (r"Failed to move to new namespace", "sandbox could not start"),
            (r"No usable sandbox", "sandbox unavailable"),
        ]
        for pattern, description in fatal:
            match = re.search(pattern, logs)
            assert match is None, (
                f"{description}: found {match.group(0)!r} in the app log\n"
                f"--- log ---\n{logs[-4000:]}"
            )
        machine.log("no fatal patterns in the startup log")

    with subtest("the renderer and GPU helpers are alive, not crash-looping"):
        # A crash loop keeps the *count* roughly constant while replacing the
        # processes underneath, so counting alone cannot detect it. Compare the
        # actual PID sets: a healthy Electron keeps the same helpers.
        def helper_pids():
            out = machine.succeed("pgrep -f '[C]hatGPT' || true").strip()
            return {line.strip() for line in out.splitlines() if line.strip()}

        first = helper_pids()
        assert first, "no ChatGPT processes are running at all"
        machine.sleep(20)
        second = helper_pids()
        assert second, "every ChatGPT process exited"

        survived = first & second
        replaced = first - second
        machine.log(f"helpers: {len(first)} -> {len(second)}, "
                    f"{len(survived)} survived, {len(replaced)} replaced")

        # A count is not a shape. Electron must actually have the helper roles
        # it needs; a browser process alone with no zygote and no renderer
        # would satisfy a count check and be a broken application.
        roles = machine.succeed("ps -eo args | grep '[C]hatGPT' || true")
        for flag, role in (("--type=zygote", "zygote"),
                           ("--type=renderer", "renderer")):
            assert flag in roles, (
                f"no {role} process is running; Electron did not bring up its "
                f"helper processes.\n{roles[:2000]}"
            )
        machine.log("zygote and renderer processes are present")

        # Some churn is normal (a utility process finishing its work). A
        # majority being replaced inside 20 seconds is not.
        assert len(survived) >= len(first) / 2, (
            f"{len(replaced)} of {len(first)} helper processes were replaced "
            f"within 20s, which is what a crash loop looks like.\n"
            f"before: {sorted(first)}\nafter:  {sorted(second)}"
        )

    with subtest("the generic binary fails WITHOUT the bridge"):
        # Baseline. environment.stub-ld puts nix-ld at the generic loader path
        # with no NIX_LD set, so a downloaded-toolchain-shaped binary cannot
        # start. If this ever succeeds, the test below proves nothing.
        rc, out = machine.execute(
            "su - alice -c '${pkgs.bubblewrap}/bin/bwrap --unshare-user "
            "--unshare-net --ro-bind / / --proc /proc --dev /dev "
            "-- ${genericBinary}/bin/probe' 2>&1")
        machine.log(f"without the bridge: rc={rc} {out.strip()[:200]}")
        assert "GENERIC-BINARY-RAN-OK" not in out, (
            "the generic binary ran without the bridge, so this host already "
            "provides NIX_LD and the bridge test below would be vacuous"
        )

    with subtest("the generic binary RUNS through the packaged bwrap bridge"):
        # The real thing: the package's own bwrap, real bubblewrap underneath,
        # a Codex-shaped argv with filesystem mounts, and a genuinely generic
        # dynamically-linked ELF that must actually execute.
        shim = "${chatgpt.bwrapShim}/bin/bwrap"
        rc, out = machine.execute(
            f"su - alice -c '{shim} --unshare-user --unshare-net "
            "--ro-bind / / --proc /proc --dev /dev "
            "-- ${genericBinary}/bin/probe' 2>&1")
        machine.log(f"through the bridge: rc={rc} {out.strip()[:200]}")
        assert "GENERIC-BINARY-RAN-OK" in out, (
            f"the generic binary did not run through the bridge (rc={rc}):\n{out}"
        )
        assert rc == 0, f"bridge exited {rc}"

    with subtest("the bridge works when bwrap is found on PATH by name"):
        # The real Codex path does not invoke our shim by absolute path -- it
        # runs "bwrap" and takes whatever PATH resolves. Exercising only the
        # absolute path would leave the thing that actually happens untested.
        shim_dir = "${chatgpt.bwrapShim}/bin"
        rc, out = machine.execute(
            f"su - alice -c 'PATH={shim_dir}:$PATH "
            "bwrap --unshare-user --unshare-net --ro-bind / / "
            "--proc /proc --dev /dev "
            "-- ${genericBinary}/bin/probe' 2>&1")
        machine.log(f"via PATH lookup: rc={rc} {out.strip()[:160]}")
        assert "GENERIC-BINARY-RAN-OK" in out, (
            f"the bridge did not apply when bwrap came from PATH (rc={rc}):\n{out}"
        )
        # And the resolved bwrap must be ours, not the real one.
        which = machine.succeed(
            f"su - alice -c 'PATH={shim_dir}:$PATH command -v bwrap'").strip()
        assert which.startswith("${chatgpt.bwrapShim}"), which

    with subtest("the real `codex sandbox` path is bridged end to end"):
        # Everything above drives bwrap directly with a Codex-shaped argv.
        # This drives the bundled Codex binary's own sandbox command, which is
        # what actually runs on a user's machine: Codex resolves "bwrap"
        # through PATH itself, builds its own argv, and executes the command
        # inside. Three runs, because only the contrast proves anything.
        #
        # (The subcommand is `codex sandbox <command>`. There is no
        # `codex sandbox linux` -- that parses as the command "linux".)
        codex = "${chatgpt}/lib/chatgpt/resources/codex"
        probe = "${genericBinary}/bin/probe"
        base = "${pkgs.coreutils}/bin"
        real = "${pkgs.bubblewrap}/bin"

        # 1. With no bwrap on PATH at all, Codex must fail for exactly the
        #    stated reason. This pins PATH lookup as the mechanism the whole
        #    bridge depends on: Codex also looks for a bundled
        #    codex-resources/bwrap next to itself, and if a future release
        #    shipped one, the shim could be bypassed silently.
        rc, out = machine.execute(
            f"su - alice -c 'PATH={base} {codex} sandbox {probe}' 2>&1")
        machine.log(f"codex sandbox, no bwrap: rc={rc} {out.strip()[:200]}")
        assert "bubblewrap is unavailable" in out, (
            f"Codex did not resolve bwrap through PATH, so the bridge's "
            f"mechanism is not what this package assumes (rc={rc}):\n{out}"
        )

        # 2. With the real bwrap on PATH the sandbox starts, but the generic
        #    binary still cannot: stub-ld provides no NIX_LD. If this ever
        #    succeeds, step 3 proves nothing.
        rc, out = machine.execute(
            f"su - alice -c 'PATH={real}:{base} {codex} sandbox {probe}' 2>&1")
        machine.log(f"codex sandbox, real bwrap: rc={rc} {out.strip()[:200]}")
        assert "GENERIC-BINARY-RAN-OK" not in out, (
            f"the generic binary ran under the unmodified bwrap, so this VM "
            f"already provides a working generic loader and the next "
            f"assertion would be vacuous:\n{out}"
        )

        # 3. Same Codex, same subcommand, same binary -- with the shim ahead
        #    on PATH, exactly as the launcher arranges on a NixOS host.
        shim_dir = "${chatgpt.bwrapShim}/bin"
        rc, out = machine.execute(
            f"su - alice -c 'PATH={shim_dir}:{real}:{base} "
            f"{codex} sandbox {probe}' 2>&1")
        machine.log(f"codex sandbox, shim: rc={rc} {out.strip()[:200]}")
        assert "GENERIC-BINARY-RAN-OK" in out, (
            f"the generic binary did not run through the real Codex sandbox "
            f"path with the bridge in place (rc={rc}):\n{out}"
        )

    with subtest("the launcher puts the shim ahead of the real bwrap"):
        # The launcher is what arranges this on a NixOS host, and it only does
        # so when /etc/NIXOS exists -- which it does here.
        machine.succeed("test -e /etc/NIXOS")
        launcher = machine.succeed("cat ${chatgpt}/bin/chatgpt")
        assert "${chatgpt.bwrapShim}/bin" in launcher, (
            "the launcher does not reference the shim directory"
        )
        assert 'PATH="${chatgpt.bwrapShim}/bin:$PATH"' in launcher, (
            "the shim is not prepended to PATH, so the real bwrap would win"
        )
        machine.log("launcher prepends the shim directory to PATH")

    with subtest("the shim does not disturb an ordinary sandboxed command"):
        shim = "${chatgpt.bwrapShim}/bin/bwrap"
        machine.succeed(
            f"su - alice -c '{shim} --unshare-user --ro-bind / / "
            "-- ${pkgs.coreutils}/bin/true'")

    with subtest("bundled Codex actually executes"):
        version = machine.succeed(
            "${chatgpt}/lib/chatgpt/resources/codex --version").strip()
        machine.log(f"codex: {version}")
        assert version, "codex --version produced no output"

    with subtest("bundled helpers run inside the VM"):
        machine.succeed(
            "${chatgpt}/lib/chatgpt/resources/rg --version")
        machine.succeed(
            "${chatgpt}/lib/chatgpt/resources/cua_node/bin/node "
            "-e 'process.exit(0)'")
        machine.succeed(
            "test -x ${chatgpt}/lib/chatgpt/resources/codex")

    with subtest("the app shuts down cleanly"):
        # The bracket makes the pattern match the app but not this command's
        # own argv, which otherwise contains the literal string and makes
        # pkill terminate itself.
        machine.succeed("pkill -f '[C]hatGPT' || true")
        machine.sleep(5)
        remaining = machine.succeed("pgrep -c -f '[C]hatGPT' || true").strip()
        machine.log(f"processes left after shutdown: {remaining}")
        assert remaining == "0", (
            f"{remaining} ChatGPT processes survived shutdown; the app leaves "
            f"orphans behind"
        )
  '';
}
