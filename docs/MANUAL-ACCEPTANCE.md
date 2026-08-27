# Manual acceptance

CI cannot validate authenticated UI behaviour, a real GPU, a real keyring or a
real compositor session. Those need one pass on actual hardware before the
automation is treated as production-ready.

**Status: not yet performed.**

Until this is signed off, treat routine auto-merge as unproven. Everything
here is about the *runtime*; the structural invariants (ELF classification,
interpreter window, `app.asar` identity, plugin cache, sandbox bridge) are
already enforced by CI on every build.

## Target host

| | |
| --- | --- |
| OS | NixOS unstable, flakes + Home Manager |
| Compositor | niri (Wayland) with `xwayland-satellite` |
| CPU | AMD Ryzen 9 9950X |
| GPU | AMD Radeon RX 7600 |
| Display | Kuycon G27P, 5120×2880 @ 60 Hz |
| Secrets | GNOME Keyring, unlocked by the login session |
| Proxy | wrapped outside this package |

## Before starting

```sh
nix build github:stslex/chatgpt-desktop-nix#chatgpt -L
```

Keep a terminal tailing the app's own output for the whole session — several
checks below are about what does *not* appear there.

## Checklist

Record pass/fail and paste anything unexpected.

### 1. Launch through the desktop entry, default XWayland

- [ ] The entry appears in the launcher with correct upstream branding and icon
- [ ] Launching from the entry (not the CLI) opens a window
- [ ] `xwayland-satellite` is hosting it — the window is an X11 client
- [ ] Rendering is correct at 5120×2880; no blurring, no wrong-DPI scaling

### 2. OAuth / deep-link login

- [ ] "Sign in" opens the system browser
- [ ] The `codex://` deep link hands control back to the app
- [ ] Login completes and the account is shown

### 3. Keyring persistence

- [ ] Fully quit and relaunch
- [ ] The session persists — no re-login prompt
- [ ] `secret-tool search --all service chatgpt` (or `seahorse`) shows the item
- [ ] Locking the keyring and relaunching prompts to unlock rather than failing

### 4. Chat

- [ ] Send a message and receive a streamed response
- [ ] Markdown, code blocks and syntax highlighting render
- [ ] Attach a file
- [ ] History persists across a restart

### 5. Codex, including a Git-backed thread

**This is the important one — the `PT_INTERP` regression surfaces here.**

- [ ] Open Codex
- [ ] Create a thread against a **Git repository**
- [ ] Close and reopen it
- [ ] Resume it after a full app restart
- [ ] **No SIGILL, no "Illegal instruction", no silent helper death**

If this fails, capture the crash immediately:

```sh
coredumpctl list | tail
coredumpctl info <PID>
journalctl --user -b | grep -iE 'sigill|illegal|chatgpt'
```

### 6. Sandboxed command execution

- [ ] Ask Codex to run a shell command in the workspace
- [ ] It executes inside the bubblewrap sandbox and returns output
- [ ] Writes land in the workspace, not elsewhere
- [ ] Denying a command actually blocks it

Confirm the shim is the one being used:

```sh
pgrep -af bwrap | head
ls -l "$(nix build --no-link --print-out-paths \
  github:stslex/chatgpt-desktop-nix#chatgpt)/bin/../"*bwrap-shim*/bin/bwrap 2>/dev/null
```

### 7. Downloaded generic toolchains

The point of the `nix-ld` bridge. Have Codex install and use tools it downloads
itself, rather than the ones on your `PATH`:

- [ ] **Git** — clone or inspect a repository from inside the sandbox
- [ ] **Node** — run a script with a downloaded Node, not the system one
- [ ] **Python** — run a script with a downloaded interpreter
- [ ] No `cannot execute: required file not found`
- [ ] No `No such file or directory` for `/lib64/ld-linux-x86-64.so.2`

### 8. Desktop integration

- [ ] Copy from the app and paste into another window
- [ ] Copy from another window and paste in
- [ ] Desktop notifications appear
- [ ] Focus behaves — clicking the window focuses it; Alt-Tab works
- [ ] Text is crisp at 5120×2880
- [ ] Resize, minimise, maximise
- [ ] Quit and relaunch cleanly; no orphaned processes (`pgrep -af ChatGPT`)

### 9. Proxy wrapping

- [ ] The app works under your own proxy wrapper
- [ ] `env | grep -i proxy` in the package's own environment shows **no**
      baked-in proxy values — those belong in your configuration, not here

### 10. Log review

With the session's full output captured, confirm none of these appear:

- [ ] `SIGILL` / `Illegal instruction`
- [ ] `error while loading shared libraries`
- [ ] `cannot open shared object file`
- [ ] `symbol lookup error`
- [ ] `Failed to move to new namespace` / `No usable sandbox`
- [ ] GPU reset, `amdgpu` ring timeout, or repeated GPU-process restarts
- [ ] A helper process crash loop

```sh
journalctl --user -b --since "1 hour ago" \
  | grep -iE 'chatgpt|codex|sigill|amdgpu|sandbox' | tail -50
```

### 11. Native Wayland — only after XWayland passes

Separately, and only once everything above is green:

```sh
chatgpt --ozone-platform=wayland
```

- [ ] It starts
- [ ] Note which of the documented-incomplete behaviours misbehave: floating
      windows, window positioning, focus, keyboard shortcuts

Failures here are **expected** and are an upstream limitation, not a packaging
defect. Record them; they do not block acceptance.

## Explicitly out of scope

Not acceptance criteria — they are upstream product limitations:

- **Computer Use** — macOS and Windows only
- **Linux Remote-host functionality** — not in the Linux preview

## Sign-off

| | |
| --- | --- |
| Date | |
| Package version | |
| Flake revision | |
| Result | |
| Notes | |

Once signed off, routine upstream versions may auto-merge — but only while the
structural, loader, plugin and sandbox invariants hold. Any change to those
fails CI and returns to manual review by design.
