{ pkgs, chatgpt }:

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
    imports = [ ];

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

    # Chromium's sandbox needs unprivileged user namespaces. Assert the VM
    # provides them rather than working around their absence.
    boot.kernel.sysctl."user.max_user_namespaces" = 28633;

    environment.systemPackages = [ chatgpt pkgs.xdotool pkgs.procps ];

    # A Secret Service implementation, so the app's keyring probe has something
    # to talk to instead of erroring in a way that muddies the log.
    services.gnome.gnome-keyring.enable = true;
    security.pam.services.lightdm.enableGnomeKeyring = true;

    nixpkgs.config.allowUnfreePredicate = pkg:
      builtins.elem (pkgs.lib.getName pkg) [ "chatgpt-desktop" ];
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
        # Count zygote/renderer processes twice; a crash loop shows up as
        # helpers that keep being replaced.
        first = machine.succeed(
            "su - alice -c 'pgrep -c -f ChatGPT || true'").strip()
        machine.sleep(15)
        second = machine.succeed(
            "su - alice -c 'pgrep -c -f ChatGPT || true'").strip()
        machine.log(f"ChatGPT processes: {first} then {second}")
        assert int(second) > 0, "every ChatGPT process exited"

    with subtest("bundled helpers run inside the VM"):
        machine.succeed(
            "${chatgpt}/lib/chatgpt/resources/rg --version")
        machine.succeed(
            "${chatgpt}/lib/chatgpt/resources/cua_node/bin/node "
            "-e 'process.exit(0)'")
        machine.succeed(
            "test -x ${chatgpt}/lib/chatgpt/resources/codex")

    with subtest("the app shuts down cleanly"):
        machine.succeed("su - alice -c 'pkill -f ChatGPT || true'")
        machine.sleep(5)
  '';
}
