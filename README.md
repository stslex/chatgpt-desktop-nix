# chatgpt-desktop-nix

ChatGPT Desktop by OpenAI, packaged for NixOS from OpenAI's **official signed
Linux `.deb`**.

The upstream Electron payload is installed as OpenAI ships it. `app.asar` is
byte-identical, no JavaScript is patched, and CI proves both on every build.
The only files this package modifies are the host ELF binaries that Nix
requires be relocated, and even those are chosen by an explicit, testable
classifier rather than a blanket sweep.

```sh
nix run github:stslex/chatgpt-desktop-nix
```

## Contents

- [Install](#install)
- [Wayland](#wayland)
- [Requirements](#requirements)
- [How updates work](#how-updates-work)
- [Rolling back](#rolling-back)
- [What this package does to the upstream payload](#what-this-package-does-to-the-upstream-payload)
- [The automatic updater](#the-automatic-updater)
- [One-time repository setup](#one-time-repository-setup)
- [Running the checks locally](#running-the-checks-locally)
- [Known limitations](#known-limitations)

## Install

### Try it without installing

```sh
nix run github:stslex/chatgpt-desktop-nix
```

### NixOS, via the overlay

```nix
{
  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    chatgpt-desktop.url = "github:stslex/chatgpt-desktop-nix";
    chatgpt-desktop.inputs.nixpkgs.follows = "nixpkgs";
  };

  outputs = { nixpkgs, chatgpt-desktop, ... }: {
    nixosConfigurations.myhost = nixpkgs.lib.nixosSystem {
      system = "x86_64-linux";
      modules = [
        ({ pkgs, ... }: {
          nixpkgs.overlays = [ chatgpt-desktop.overlays.default ];

          # ChatGPT Desktop is proprietary.
          nixpkgs.config.allowUnfreePredicate = pkg:
            builtins.elem (nixpkgs.lib.getName pkg) [ "chatgpt-desktop" ];

          environment.systemPackages = [ pkgs.chatgpt-desktop ];

          # The Secret Service provider the app stores its session in.
          services.gnome.gnome-keyring.enable = true;
        })
      ];
    };
  };
}
```

### Home Manager

```nix
{
  inputs.chatgpt-desktop.url = "github:stslex/chatgpt-desktop-nix";

  # in your home-manager configuration:
  home.packages = [ inputs.chatgpt-desktop.packages.${pkgs.system}.chatgpt ];
}
```

### Without the overlay

```nix
environment.systemPackages = [
  inputs.chatgpt-desktop.packages.${pkgs.system}.default
];
```

## Wayland

The launcher uses Electron's default XWayland path, which is what OpenAI
supports. Native Wayland is experimental upstream — floating windows, window
positioning, focus and keyboard shortcuts are all documented as incomplete — so
it is opt-in and never enabled for you.

Two ways to opt in:

```sh
# Per-launch, passed straight through to Electron.
chatgpt --ozone-platform=wayland

# Or via the usual NixOS convention, which also requires WAYLAND_DISPLAY.
NIXOS_OZONE_WL=1 chatgpt
```

`NIXOS_OZONE_WL` is tested for an affirmative value (`1`, `true`, `yes`, `on`),
not merely for being non-empty. Setting `NIXOS_OZONE_WL=0` means *no*, and this
package treats it that way.

Everything you pass on the command line reaches Electron unchanged, after the
package's own flags, so your arguments win.

You can also keep persistent flags in `~/.config/chatgpt-flags.conf`, one per
line, `#` for comments.

## Requirements

**Unprivileged user namespaces must be available.** Chromium's sandbox depends
on them, the upstream package ships no setuid `chrome-sandbox` helper, and this
package deliberately provides no way to turn the sandbox off. If they are
disabled the launcher stops with an actionable message rather than starting
insecurely.

The launcher does not read sysctls to decide this. It tries to create a
namespace, because reading `/proc/sys/...` covers two of the ways they can be
denied and none of the others: Ubuntu restricts them through AppArmor, a
container may drop the capability, seccomp may block the syscall. In each of
those the sysctls look fine and Chromium's zygote still dies with `SIGTRAP` and
no output.

`--version` is exempt, and only `--version`, and only as the sole argument.
Electron answers it in the browser process before any renderer exists, so it
does not depend on the sandbox; refusing it would protect nothing while
breaking packaging checks, container builds and CI.

Nothing else is exempt, which is a behavioural fact rather than caution.
Measured against this build, `-v` is **not** an abbreviation of `--version`: it
initialises Ozone and starts the application. Exempting it would skip the
precheck for a real start. `--help` and `-h` exec `man ChatGPT`, which has no
manual entry. Every invocation other than a lone `--version` goes through the
check.

On NixOS namespaces are enabled by default. If you have changed that:

```nix
boot.kernel.sysctl."user.max_user_namespaces" = 28633;
```

On a Debian or Ubuntu host, AppArmor is the usual cause:

```sh
sudo sysctl -w kernel.apparmor_restrict_unprivileged_userns=0
```

For login to persist across restarts you need a Secret Service provider — GNOME
Keyring, KWallet with the Secret Service interface, or `keepassxc` — unlocked by
your login session.

## How updates work

This is a Nix flake, so **updating this repository does not update you.** Your
system tracks whatever revision your own `flake.lock` pins. When the updater
lands a new ChatGPT version here, nothing on your machine changes until you
choose to pull it:

```sh
# In your own nix-config:
nix flake update chatgpt-desktop
sudo nixos-rebuild switch --flake .
```

To follow a specific version instead of the moving default branch, pin a
release tag:

```nix
inputs.chatgpt-desktop.url =
  "github:stslex/chatgpt-desktop-nix/chatgpt-26.820.71523-nix1";
```

## Rolling back

Every release is a tag, `chatgpt-<encoded-version>-nix<N>`, and old tags are
kept precisely so they remain usable as rollback pins.

**Where that immutability actually comes from.** The release workflow refuses to
move or delete a tag: it fails if one already exists at a different commit, and
it never force-pushes. That is a property of the workflow, not of the
repository. Nothing at the GitHub level currently prevents someone with push
access from deleting or re-pointing a `chatgpt-*` tag by hand.

If you want it enforced by the platform rather than by convention, add a tag
ruleset — Settings → Rules → Rulesets → New tag ruleset, target
`chatgpt-*`, enable *Restrict updates* and *Restrict deletions*, with an empty
bypass list. Until that exists, treat tag immutability as "the automation will
not do it", not "it cannot happen".

The version is percent-encoded into the tag rather than having its `:`, `~` and
`+` mapped to `.`, so two upstream versions can never claim the same release.

```nix
# Pin the previous known-good revision.
inputs.chatgpt-desktop.url =
  "github:stslex/chatgpt-desktop-nix/chatgpt-26.820.60940-nix1";
```

The `nixN` suffix increments when the packaging changes for an unchanged
upstream version.

## What this package does to the upstream payload

Deliberately **not** done:

- No Debian maintainer script runs. Upstream's `postinst` would add an APT
  source, install a keyring into `/usr/share/keyrings` and load an AppArmor
  profile; none of that happens, and none of it is installed.
- No `buildFHSEnv`. This is a normal derivation.
- No `--no-sandbox`, ever. CI fails the build if that string appears in the
  launcher.
- No global `LD_LIBRARY_PATH`. Each ELF carries its own RUNPATH, because a
  library path exported into the environment would follow the `git`, `node` and
  `python` processes the app spawns and break their linking.
- No telemetry added.
- Your `PATH` is never replaced, only appended to, so the app keeps seeing your
  shell, your Git, your Nix and your toolchains.
- No `app.asar` modification and no JavaScript patching.

Done:

- Host glibc ELF files get a Nix interpreter and RUNPATH.
- The desktop entry's `Exec=` is rewritten to the packaged launcher and
  validated with `desktop-file-validate`; upstream branding, icons and MIME
  handlers are preserved.
- A writable bundled-plugin resource cache is published under
  `$XDG_CACHE_HOME` (see below).

### The ELF classifier

The payload mixes several unrelated kinds of ELF file in one tree. Running
`autoPatchelf` over all of it would rewrite files not meant for this platform
and would hide upstream changes. Instead every ELF file is classified from its
own headers:

| Class | Action | Count (x86_64) |
| --- | --- | --- |
| `host-glibc-program` | patch interpreter + RUNPATH | 7 |
| `host-glibc-library` | patch RUNPATH | 19 |
| `static` | leave byte-identical | 5 |
| `musl-prebuild` | leave byte-identical | 5 |
| `android-prebuild` | leave byte-identical | 6 |
| `foreign-architecture` | leave byte-identical | 13 |
| `optional-qt-shim` | leave byte-identical | 2 |

The Qt shims are Chromium's optional KWallet integration. Linking them would
drag **both** Qt 5 and Qt 6 into the closure to satisfy code that only loads
under KDE; secrets go through the Secret Service API instead, so they are left
unlinked and the `dlopen` fails cleanly.

Android prebuilds are detected from their `.note.android.ident` note and bionic
sonames rather than their path, because on an aarch64 host an `android-arm64`
prebuild has the same `e_machine` as a native one.

The full inventory is committed under `elf-baseline/`. **Any** new, removed or
reclassified ELF file fails the build and goes to a human. The updater is never
allowed to widen it.

### The `PT_INTERP` invariant

The app bundles `detect-libc`, which decides glibc-versus-musl by reading the
first 2048 bytes of its own executable, walking the program headers, and
extracting `PT_INTERP` **out of that same buffer**. Nothing seeks.

The stock binary has `PT_INTERP` at offset 736. Its interpreter string is 27
bytes; a Nix store path is about 80, so `patchelf` cannot grow it in place and
instead appends a new `.interp` at the end of the file. Measured on the real
314 MB binary, the offset moves **from 736 to 314,945,896**. `detect-libc` then
slices past its buffer, gets nothing, and falls through to
`process.report.getReport()` — the path that raises **SIGILL** when opening a
Git-backed Codex thread ([openai/codex#38123]).

`tools/relocate_interp.py` moves the interpreter back into space `patchelf`
vacated, then re-reads the file from disk and asserts the result. Two things
make it safe:

- The target range must be claimed by **no section header** and no header
  table. Matching on padding-looking bytes alone is not enough — the bundled
  Node has a run of zeros at offset 1411 that sits inside a live section, and
  writing there produces a binary that passes every structural check and then
  segfaults. That failure was found by this repository's own smoke test.
- The file length never changes and nothing else moves.

Not every binary can be relocated. `patchelf` packs `.dynamic` and `.dynstr`
into the whole first 2 KiB of the bundled Node, leaving no unreferenced range,
so that one keeps `patchelf`'s placement — it runs correctly, only its own
self-probe is inconclusive. Which binaries end up in which state is pinned in
`elf-baseline/interp-window-*.json`; the main `ChatGPT` binary is **required**
to be in-window, and a change anywhere fails the build.

[openai/codex#38123]: https://github.com/openai/codex/issues/38123

### Writable plugin resources

Electron reconciles bundled-plugin metadata on startup by writing under its
resources path, which is read-only in the Nix store. The launcher publishes a
writable mirror and points the app at it with
`CODEX_ELECTRON_BUNDLED_PLUGINS_RESOURCES_PATH` — the exact variable the
shipped `app.asar` reads for this.

The mirror lives under `$XDG_CACHE_HOME/chatgpt-desktop-nix/resources/`, keyed
by package version **and this build's own store-path hash** — not by the
upstream version alone, so rebuilding the same ChatGPT release against a
different nixpkgs revision cannot reuse a cache whose copied native modules were
patched for the old closure. It symlinks the large immutable resources
(`app.asar` alone is ~270 MB, `codex` ~265 MB) and copies only the `plugins`
subtree that actually gets rewritten. Publication is atomic: staged in a
temporary directory, flushed with `sync`, marked complete, then `mv -T`'d into
place. A directory without its completion marker is treated as an interrupted
build and discarded rather than trusted. Concurrent launches serialise on an
`flock`, and each launch holds a shared lock on its own entry for as long as it
runs.

**Caches for older versions are deliberately not deleted.** Doing it safely
needs the exclusive lock held across the deletion, and the obvious test does not
provide that: `flock --nonblock <lock> --command true` releases the lock the
moment `true` exits, leaving a window in which another launch can legitimately
claim the cache about to be removed. The cost of keeping them is bounded and
visible — roughly 50 MB per upstream version under
`$XDG_CACHE_HOME/chatgpt-desktop-nix/resources`, which is always safe to delete
by hand when the app is not running. The cost of collecting wrongly is pulling
resources out from under a running application.

### The Codex command sandbox

Codex sandboxes the commands it runs with Bubblewrap, and inside that sandbox it
runs toolchains it downloaded itself — generic Linux builds of git, node, python
or pnpm with `/lib64/ld-linux-x86-64.so.2` baked into their ELF headers, which
is not a real loader on NixOS.

NixOS's default `environment.stub-ld` puts a stub at that path whose entire
behaviour is to print `Could not start dynamically linked executable` and exit
127. It is not `nix-ld` and it ignores `NIX_LD`, so the loader has to be
replaced, not merely configured.

Rather than requiring you to enable `programs.nix-ld` system-wide, the package
ships its own `bwrap` (`nix/bwrap-shim.c`), placed ahead of the real one on
`PATH` and only when `/etc/NIXOS` exists. It injects a read-only bind of
`nix-ld` plus `NIX_LD` and `NIX_LD_LIBRARY_PATH`, then execs the real `bwrap`.
The bind exists only inside the sandbox namespace.

Two details make it actually work, and both were established by measurement
against bubblewrap 0.11.2 rather than assumed:

- **The bind target is the *resolved* path**, not `/lib64/ld-linux-x86-64.so.2`
  itself. bwrap refuses to bind over a symlink, and on NixOS that path is one;
  binding over what it resolves to — an ordinary file in the store — works, and
  the symlink then leads to our `nix-ld`.
- **The arguments go after all of the caller's options**, immediately before the
  command. Placed first, a later `--ro-bind / /` (the shape Codex uses) simply
  covers the bind and it has no effect at all.

Finding that insertion point means parsing bwrap's option grammar properly.
Scanning for the first bare `--` is wrong: several options take arbitrary
values, so `bwrap --setenv FOO -- -- cmd` has `--` as the *value* of `--setenv`.
The shim carries bubblewrap's complete option table with each option's argument
count. If it meets anything it cannot account for — an unrecognised option, a
truncated one, or `--args FD` whose options come from a file descriptor it
cannot read — it execs the real `bwrap` with the argument vector untouched.
Losing the bridge degrades a feature; guessing wrong would corrupt the sandbox.

The VM test proves this end to end on a host with only the default stub, and it
does so through the bundled Codex binary's own `codex sandbox <command>`, not
just by calling `bwrap` with a Codex-shaped argument vector. Three runs, because
only the contrast means anything:

| `PATH` contains | result |
| --- | --- |
| no `bwrap` at all | Codex fails with *bubblewrap is unavailable: no system bwrap was found on PATH…* |
| the real `bwrap` | the sandbox starts; the generic binary still cannot run |
| the shim, then the real `bwrap` | the generic binary runs and prints its output |

The first row is load-bearing. It is what pins `PATH` lookup as the mechanism
this bridge depends on: Codex's own diagnostic says it also looks for a bundled
`codex-resources/bwrap` next to the Codex executable. No such binary exists in
this payload, and the `no-bundled-bwrap` check fails the build if one ever
appears — because Codex might then stop consulting `PATH`, which would bypass
the shim silently, with everything looking fine until someone actually ran a
downloaded toolchain.

## The automatic updater

A scheduled workflow runs daily at 04:17 UTC and can be dispatched manually. For
each run it performs the whole trust chain from scratch:

1. Fetch `InRelease` from the exact official origin.
2. Verify it with `gpgv` against an isolated keyring holding **only** the
   committed key, and assert the reported signer fingerprint.
3. Enforce freshness. `Valid-Until` is honoured when present, but this origin
   does not publish it, so the signed `Date` is used instead and metadata older
   than 30 days is refused. A signature proves *who* published, never *when*:
   without an age bound, someone controlling the CDN but not the key could
   replay a genuine old snapshot indefinitely, and every hash would still match
   while the client sat on a superseded release. The date is checked but not
   recorded in `sources.json` — upstream re-signs daily, so storing it would
   open a pull request every day that changed nothing.
4. Read the signed SHA-256 and size for `Packages.gz`.
5. Download that exact `Packages.gz` and verify both.
6. Parse exactly one `Package: chatgpt` stanza per architecture.
7. Require `amd64` and `arm64` to be at the same version.
8. Sanitise `Filename` — rejecting absolute paths, URLs, traversal, encoded
   traversal and anything escaping the pool.
9. Verify each `.deb`'s size and SHA-256.
10. Verify each `.deb`'s debsigs `_gpgorigin` signature with the same key.
11. Verify the control `Package`, `Version` and `Architecture`.
12. Only then write `sources.json`.

The trust anchor is committed at `trust/openai-chatgpt-archive-keyring.gpg` and
pinned by full fingerprint `3BFA0E4AE8B8CC16A2D9BA684A3B4A566C4660E4` and
SHA-256. It is **never** fetched, refreshed or replaced at runtime. OpenAI
publishes no key URL; see [trust/KEY-PROVENANCE.md](trust/KEY-PROVENANCE.md)
for how it was obtained and what corroborates it.

The updater fails closed and sends these to manual review rather than handling
them:

- signing-key rotation
- a known version republished with different bytes
- a downgrade or repository rollback
- architecture version skew
- structural changes to the repository layout
- any new or reclassified ELF file

It never trusts `/latest`, never trusts HTTPS alone, never does
trust-on-first-use, and never compares Debian versions lexically — `26.820.9`
sorts *above* `26.820.71523` as a string and *below* it as a version.

An update touches **only `sources.json`**. CI enforces that, and re-derives the
metadata from the origin independently rather than trusting the committed file.

### Why a GitHub App

The updater opens its pull request with a short-lived GitHub App installation
token, not `GITHUB_TOKEN`. Events created by `GITHUB_TOKEN` do not start further
workflow runs, so a pull request opened with it would sit with no CI at all and
auto-merge would never have a required check to wait on.

The App needs only **Metadata: read**, **Contents: read/write** and **Pull
requests: read/write**. It is deliberately given no Actions, Administration or
ruleset-bypass permission, so it cannot merge past a failing check.

Before auto-merge is enabled, **thirteen** properties are read back from the API
and compared against expectations:

1. the author is the updater App
2. the base is the protected branch
3. the head is in this repository, never a fork
4. the branch matches the exact `automation/chatgpt-<version>` pattern
5. the automated-update label is present
6. `sources.json` is the only file changed
7. nothing under `.github/` is touched
8. no packaging code, `flake.lock` or test is touched
9. the pull request is open
10. it is not a draft
11. the head SHA still matches the verified candidate
12. the diff actually contains the verified version
13. the candidate version is newer than the base branch, by Debian ordering

Any failure leaves the pull request open for a human. The list is kept honest by
a check that reads the names out of `tools/check_automerge_eligible.py` and
fails the build if this section drifts from them.

Ordinary feature, dependency and documentation pull requests are never
auto-merged by this mechanism.

### When something fails

The protected branch and the current release are left untouched, the automation
pull request stays open, logs are retained (never the OpenAI payload), and one
deduplicated issue per upstream version is opened or updated, classified as
upstream availability, trust verification, packaging drift or runtime
regression. A later scheduled run retries the same candidate without creating
new issues.

## One-time repository setup

These steps need repository-admin rights and are not automated.

### 1. Create the GitHub App

At <https://github.com/settings/apps/new>:

- **Name:** `chatgpt-desktop-nix-updater`
- **Homepage:** the repository URL
- **Webhook:** disabled
- **Repository permissions**, and nothing else:
  - Metadata: **Read-only**
  - Contents: **Read and write**
  - Pull requests: **Read and write**
- **Where can this App be installed:** Only on this account

Do **not** grant Actions, Administration, Checks or any bypass permission.

### 2. Install it on this repository only

App settings → *Install App* → select **only** `stslex/chatgpt-desktop-nix`.

### 3. Create the `updater` environment *first*

Order matters here. The private key must never exist as a repository-wide
secret, because a repository secret is readable by any workflow job, including
one started from a branch someone dispatched by hand. Scoping it to an
environment whose deployment policy admits only `main` is what makes
"this key is only used by trusted default-branch code" true rather than
merely intended.

Settings → Environments → New environment → `updater`, then under
**Deployment branches and tags** choose *Selected branches and tags* and add a
rule for exactly `main`. Nothing else.

Only once that policy exists, add the key **to that environment**:

Settings → Environments → `updater` → Environment secrets → Add secret

- **Secret** `UPDATER_APP_PRIVATE_KEY` = the whole `.pem`, including the
  `-----BEGIN...` and `-----END...` lines

Adding it before the branch policy exists leaves a window in which a dispatch
against any ref could read it.

### 4. Record the App's public identifiers

These are not secret and belong at repository scope:

Settings → Secrets and variables → Actions → Variables

- `UPDATER_APP_ID` = the App's numeric ID
- `UPDATER_APP_SLUG` = the App's slug, e.g. `chatgpt-desktop-nix-updater`

### What the App's key protects, and what it does not

Be clear about this before installing anything.

**The App's private key is a trust root for the contents of `main`.** It grants
Contents read/write on this repository. Anyone holding it can push a branch and
open a pull request; combined with the auto-merge path, that is a route into
the protected branch.

The `ci-ok` check does **not** independently contain a compromised key. It runs
from the pull request's own head, so a `.github/` change in that head changes
the very workflow that is supposed to be judging it. What actually constrains
the automated path is the base-owned ruleset -- required check, zero bypass
actors -- plus the changed-file policy and the eligibility checks, and those
last two are themselves head-controlled code. Treat the key as
confidentiality-critical, not as something the checks would catch.

The App is deliberately limited to Metadata read, Contents read/write and Pull
requests read/write. It has no Actions permission, no Administration, and no
ruleset bypass, so it cannot alter workflows, disable checks, or merge past a
failing one.

### 5. Repository settings

Settings → General → Pull Requests:

- Allow squash merging — **on** (and make it the only merge method: turn off
  merge commits and rebase merging)
- Allow auto-merge — **on**
- Automatically delete head branches — **on**

### 6. Protect the default branch

Do this **after** the first CI run has completed, so the required check name
already exists and you cannot lock the repository against a check that has
never reported.

Settings → Rules → Rulesets → New branch ruleset:

- Target: `main` (Default branch)
- Enforcement: Active
- **Require a pull request before merging** — on
  - Required approvals: **0**. The updater's pull requests are constrained by
    the changed-file allowlist and thirteen eligibility checks instead;
    requiring
    an approval would mean no update could ever land unattended.
- **Require status checks to pass** — on
  - Required check: **`ci-ok`** (this exact name; it is intentionally constant
    so the rule does not track matrix job names)
  - Require branches to be up to date before merging — on
- **Block force pushes** — on
- Bypass list: **empty**. The updater App must not be able to bypass anything.

### 7. Verify

```sh
gh workflow run "Upstream update" --repo stslex/chatgpt-desktop-nix
gh run watch --repo stslex/chatgpt-desktop-nix
```

With `sources.json` already current, the run should verify the signed chain and
exit cleanly with no commit and no pull request.

## Running the checks locally

```sh
# Everything, including the graphical VM smoke test. Needs KVM.
nix flake check -L

# Just the package.
nix build .#chatgpt -L

# The updater and ELF unit tests, without Nix.
PYTHONPATH="$PWD/tools:$PWD" python3 -m unittest discover -s tests -v

# Re-derive the signed metadata and compare it to what is committed.
python3 tools/verify_sources.py            # metadata only
python3 tools/verify_sources.py --strict   # also both .deb bodies (~790 MB)

# Would an update be available?
python3 tools/update.py --check

# A dev shell with every tool.
nix develop
```

Individual checks:

```sh
nix build .#checks.x86_64-linux.trust-key -L
nix build .#checks.x86_64-linux.interp-window -L
nix build .#checks.x86_64-linux.payload-faithful -L
nix build .#checks.x86_64-linux.plugin-cache -L
nix build .#checks.x86_64-linux.vm-smoke -L
```

## Known limitations

**Upstream, not packaging:**

- **Computer Use is unavailable on Linux.** macOS and Windows only, per
  OpenAI's documentation.
- **Native Wayland is experimental.** Floating windows, window positioning,
  focus and keyboard shortcuts are all documented as incomplete. XWayland is
  the supported path and the default here.
- **Linux Remote-host functionality** is not part of the Linux preview.

**Packaging:**

- The bundled `cua_node/bin/node` keeps its interpreter outside the 2 KiB
  `detect-libc` window because `patchelf` leaves no reusable gap in it. It runs
  correctly; only its own libc self-probe is inconclusive. The main `ChatGPT`
  binary — where the SIGILL was actually reported — is relocated and verified.
- The Qt keyring shims are intentionally unlinked, so KWallet integration via
  those shims does not work. Secret Service does.
- Graphics drivers come from the host through `/run/opengl-driver`, which is a
  NixOS convention. On non-NixOS the app runs, but hardware acceleration
  depends on your own driver setup.
- The `bwrap` shim activates only when `/etc/NIXOS` exists. Elsewhere the real
  `bubblewrap` is used unchanged and downloaded generic toolchains rely on your
  system having a working `/lib64/ld-linux-x86-64.so.2`.

## Licence

Packaging code: MIT, see [LICENSE](LICENSE).

ChatGPT Desktop itself is proprietary OpenAI software. It is **not**
redistributed here: no OpenAI binary is committed, attached to a release, or
pushed to a binary cache. Building this flake downloads it from OpenAI's
official signed repository, and your use of it is governed by OpenAI's terms.

See [NOTICE](NOTICE) for attribution.
