# Investigation notes

What was measured against the real upstream package, what was inferred, and
what remains unverified. Recorded on **2026-08-27** against ChatGPT Desktop
**26.820.71523**.

Everything under "Verified" was observed directly by fetching, extracting and
inspecting the official packages. Everything under "Assumed" is a judgement
call that a future maintainer should feel free to overturn with evidence.

---

## Verified

### Repository and trust chain

| Fact | Value |
| --- | --- |
| APT origin | `https://persistent.oaistatic.com/codex-app-prod/linux/deb` |
| Suite / component | `stable` / `main` |
| Architectures published | `amd64`, `arm64` |
| Version at audit | `26.820.71523` (**not** the `26.820.60940` in the brief) |
| `InRelease` signer | `3BFA0E4AE8B8CC16A2D9BA684A3B4A566C4660E4` |
| Key type | RSA 4096, created 2026-08-05, UID `Codex Linux Repository` |
| `Valid-Until` | **absent** — the origin does not publish it |
| `Date` | present and signed (`Thu, 27 Aug 2026 00:04:34 +0000`) |
| `Release.gpg` | present (detached signature alongside `InRelease`) |
| `_gpgorigin` | present on both `.deb` files, signed by the same key |

`gpgv` with an isolated keyring containing only the committed key reports
`Good signature from "Codex Linux Repository"` for `InRelease` and for both
`_gpgorigin` members.

Package bodies, both matching the signed index exactly:

| Arch | Size | SHA-256 |
| --- | --- | --- |
| amd64 | 404,672,994 | `472d03e8…de1bda` |
| arm64 | 381,539,074 | `e0ecaaae…266013` |

### The signing key is not published at a URL

Every plausible key path under the origin returns HTTP 404 — `openai.gpg`,
`public.gpg`, `Release.key`, `chatgpt-archive-keyring.gpg` and a dozen others
were probed. The official documentation contains no `gpg`, `curl`, `keyring`,
`signed-by` or `sources.list` instruction at all.

The key is distributed **inside the package**: `postinst` carries it as
`SIGNING_KEY_BASE64` and decodes it to
`/usr/share/keyrings/chatgpt-archive-keyring.gpg`. The decoded keyring is
byte-identical across both architectures (SHA-256
`23e2cfbd…47d596`, 1148 bytes).

`keys.openpgp.org` serves a key under the same fingerprint, but with the UID and
its self-signature stripped pending address verification — so `gpgv` rejects it
with "No public key". It corroborates the fingerprint; it cannot be used as the
keyring.

### Payload

- Electron **42.3.0**; internal runtime name `owl`; user data directory `Codex`.
- 6173 files, ~1.4 GB extracted, 57 ELF files.
- `/usr/bin/chatgpt` is a symlink to `codex-launcher`, a 63-byte shell script
  that resolves its own path and execs `ChatGPT`.
- Both architectures ship the same file count with arch-specific native module
  directories.

ELF classification (x86_64 / aarch64):

| Class | x86_64 | aarch64 |
| --- | --- | --- |
| `host-glibc-program` | 7 | 8 |
| `host-glibc-library` | 19 | 19 |
| `static` | 5 | 4 |
| `musl-prebuild` | 5 | 0 |
| `android-prebuild` | 6 | 6 |
| `foreign-architecture` | 13 | 18 |
| `optional-qt-shim` | 2 | 2 |

`rg` is static on x86_64 and dynamic on aarch64 — which is why the classifier
reads headers rather than trusting paths or per-file allowlists.

Static (no `DT_NEEDED`, no `PT_INTERP`): `codex` (265 MB), `codex-code-mode-host`,
`node_repl`, `tectonic`, and `rg` on x86_64.

Android prebuilds carry `.note.android.ident` and need
`liblog.so` / `libc++_shared.so` / `libc.so` — distinguishable from native
aarch64 by soname, which matters because on an aarch64 host they share
`e_machine`.

`sharp-linux-x64-*.node` carries a five-entry `$ORIGIN` RUNPATH chain locating
its sibling `libvips-cpp.so.8.18.3`; `libvips-cpp` itself carries `$ORIGIN/`.
Both must be preserved and kept first.

`libgbm.so.1` was the only unresolved dependency after patching; it comes from
`libgbm` in current nixpkgs, which no longer bundles it in `mesa`.

### The `PT_INTERP` failure, reproduced

Measured on the real 314 MB `ChatGPT` binary:

| State | `PT_INTERP` offset | `detect-libc` result |
| --- | --- | --- |
| As shipped | 736 | `glibc` |
| After `patchelf --set-interpreter` | 314,945,896 | `None` ← the SIGILL path |
| After relocation | 960 | `glibc` |

`patchelf` grows the program-header table from 12 to 15 entries (ending at 904)
and backfills the space it vacates with `0x58` (`'X'`) — **209,216 contiguous
free bytes** starting at offset 904 in this binary.

`detect-libc` ≥ 2.1.0 reads `/proc/self/exe` with a single
`readSync(fd, buf, 0, 2048, 0)`, walks the program headers inside that buffer,
and extracts `PT_INTERP` with `subarray(p_offset, p_offset + p_filesz)`. Past
2048 the subarray clamps to empty and the result is `null`.

**Filler bytes alone are not a safe signal.** The bundled `node` has a run of
zeros at offset 1411 that lies inside `.dynstr`; writing the interpreter there
produced a binary that passed every structural check and then segfaulted
(exit 139). The relocator therefore consults section headers and refuses unless
the range is claimed by nothing.

`node` cannot be relocated at all: `patchelf` places `.dynamic` at 904–1512 and
`.dynstr` from 1512, leaving no unreferenced range in its first 2 KiB. It runs
correctly regardless (`v24.19.0`, executes JS).

### Plugin resources

Extracted verbatim from the shipped `app.asar`:

```js
var hre = `CODEX_ELECTRON_BUNDLED_PLUGINS_RESOURCES_PATH`,
    gre = `CODEX_ELECTRON_BUNDLED_PLUGINS_FORCE_RELOAD`;

function Wl(e){ return (e?.env ?? process.env)[hre]?.trim()
                    || e?.resourcesPath || process.resourcesPath }
function Gl(e){ return join(e.codexHome, `.tmp`, `bundled-marketplaces`,
                            e.marketplaceName ?? `openai-bundled`) }
```

and separately:

```js
function e({env:e, resourcesPath:t}){
  return e.CODEX_ELECTRON_RESOURCES_PATH?.trim() || t }
```

So **both** variables exist in this payload with distinct roles. The
bundled-plugins one overrides the resource root for plugin resolution
specifically; that is the one this package sets.

Path construction, also verbatim:

```js
join(d, ['' | 'app.asar.unpacked'], `plugins`, `openai-bundled`, `plugins`, e, o)
```

So the override root must contain `plugins/openai-bundled/plugins/<name>/…`.

The app's own writable plugin cache is `$CODEX_HOME/plugins/cache/<marketplace>`
and its marketplace staging area is `$CODEX_HOME/.tmp/bundled-marketplaces/…` —
both already in the user's home, so neither needs the store to be writable.

### Sandbox

The upstream AppArmor profile is exactly:

```
profile chatgpt "/usr/lib/chatgpt/ChatGPT" flags=(unconfined) {
  userns,
  include if exists <local/chatgpt>
}
```

Its only rule is `userns`, confirming unprivileged user namespaces are the
load-bearing mechanism. There is no setuid `chrome-sandbox` in the payload.

The bundled `codex` binary references `bwrap`, `CODEX_BWRAP_SHA256`,
`CODEX_SANDBOX`, `CODEX_SANDBOX_NETWORK_DISABLED` and the literal
`bwrap--unshare-user--unshare-net--ro-bind`, confirming it invokes bubblewrap
itself. This is the empirical justification for packaging bubblewrap and for
the loader bridge.

### Network

The origin's CDN intermittently aborts TLS handshakes mid-negotiation
(`SSL: UNEXPECTED_EOF_WHILE_READING`). This happened repeatedly across the
session, on both metadata and package downloads. Bounded retries with backoff
are a real requirement, not a theoretical one.

---

## Assumed

These are judgement calls, not measurements.

- **`node`'s inconclusive libc probe is acceptable.** The reported SIGILL is in
  the main Electron process, which is relocated and verified. Whether anything
  running under `cua_node` also calls `detect-libc` was not established;
  `cua_node` is the Computer Use runtime and Computer Use is unavailable on
  Linux. If a failure ever traces back to this, the honest fix is to relay out
  that binary, not to widen the padding search.
- **Leaving the Qt shims unlinked is correct.** They are only `dlopen`ed under
  KDE with a KWallet password store, and pulling both Qt 5 and Qt 6 into the
  closure for that is a poor trade. Not tested under KDE.
- **`CODEX_ELECTRON_BUNDLED_PLUGINS_RESOURCES_PATH` is the right variable.**
  Both it and `CODEX_ELECTRON_RESOURCES_PATH` exist; the bundled-plugins one is
  read by the bundled-plugin subsystem specifically. Whether the app strictly
  *needs* a writable resources path was not proven — the mirror is cheap and
  harmless either way, and is required by the packaging brief.
- **The runtime library list is complete.** Derived from `DT_NEEDED` across the
  payload plus the usual Electron `dlopen` set. `ldd` reports everything
  resolving and the app reports its version, but `dlopen`-only libraries can
  only really be confirmed by exercising the features that load them.
- **GitHub's `ubuntu-24.04-arm` runner is available here.** This repository is
  public, and public repositories get free ARM64 runners. **Not yet confirmed by
  an actual run** — see below.

---

### The interpreter target region

Measured on the real binary after `patchelf --set-interpreter` and
`--set-rpath`, and now pinned in `elf-baseline/interp-region-<system>.json`:

| | x86_64 | aarch64 |
| --- | --- | --- |
| program headers | 16 × 56 at offset 64, ending 960 | same |
| filler run | 960 … +209,160 | 960 … +208,896 |
| filler byte | `0x58` throughout | `0x58` throughout |
| containing `PT_LOAD` | index 1, off 0, vaddr 0, filesz 65,163,452, flags 4, align 4096 | index 1, off 0, vaddr 0, filesz 60,824,764, flags 4, align 65536 |
| `PT_INTERP` segments | 1 | 1 |
| sections/segments overlapping the run | none | none |

The filler run contains **only** `0x58` — verified by enumerating the distinct
byte values across it. That matters: `0x58` is what patchelf writes into space
it has abandoned, so a run of it is positive evidence about provenance. A zero
byte is not evidence of anything, and zeros occur inside live data.

`0x00` was previously accepted as filler too. It is not any more.

---

## Unverified — needs a real run

- **The ARM64 CI job.** Until a run on `ubuntu-24.04-arm` goes green, aarch64
  support is a claim, not a fact. The build job asserts
  `builtins.currentSystem` matches its target, so it cannot silently pass by
  emulating; if the runner is unavailable the job fails loudly. If it turns out
  to be unavailable, remove `aarch64-linux` from `systems` in `flake.nix`
  rather than weakening the gate.
- **The aarch64 interpreter-window expectation.** `elf-baseline/interp-window-aarch64-linux.json`
  was generated by running the same tooling against the arm64 payload with a
  synthetic store path of representative length, on an x86_64 host. Layout
  decisions are file-driven and should match, but the native ARM build is what
  confirms it. A mismatch fails the build, which is the intended behaviour.
- **The whole GitHub App path.** No App exists yet, so the update → PR →
  auto-merge → release flow has never executed.
- **Authenticated runtime behaviour.** Login, keyring persistence, Codex
  threads, sandboxed command execution, GPU, clipboard, notifications and
  scaling cannot be validated in CI. See
  [MANUAL-ACCEPTANCE.md](MANUAL-ACCEPTANCE.md).
