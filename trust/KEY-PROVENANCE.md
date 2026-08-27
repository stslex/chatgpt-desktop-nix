# OpenAI ChatGPT Desktop APT signing key — provenance

This directory holds the **fixed trust anchor** for every updater run in this
repository. It is committed deliberately and is never fetched, refreshed or
rotated automatically.

## Identity

| Property | Value |
| --- | --- |
| Fingerprint | `3BFA0E4AE8B8CC16A2D9BA684A3B4A566C4660E4` |
| Long key ID | `4A3B4A566C4660E4` |
| Algorithm | RSA 4096 |
| Created | 2026-08-05 |
| User ID | `Codex Linux Repository` |
| Capabilities | `[SC]` (sign, certify) |
| Binary keyring SHA-256 | `23e2cfbdef6afe95505f9e95a2cb63585da7ffe9b06a51ec08a32407c847d596` |
| Armored copy SHA-256 | `66170119ca41a07fbce504e06ecbfc4ae001b59495caba4bdbd83684a6c0eaa4` |
| Binary keyring size | 1148 bytes |

`openai-chatgpt-archive-keyring.gpg` is the byte-for-byte binary keyring.
`openai-chatgpt-archive-keyring.asc` is a reviewable armored rendering of the
exact same bytes; `gpg --dearmor` on the `.asc` reproduces the `.gpg` file
byte-for-byte, and that equivalence is asserted by `checks.trust-key`.

## How this key was obtained (bootstrap, 2026-08-27)

OpenAI does **not** publish this key at any URL. Every plausible key path under
the APT origin returns HTTP 404, and the official Linux documentation
(<https://learn.chatgpt.com/docs/linux/linux-app>) contains no `gpg`, `curl`,
`keyring`, `signed-by` or `sources.list` instruction at all. It states only that
"the package configures the signed OpenAI package repository during
installation".

That statement is accurate and is the actual distribution channel: the key is
embedded in the package's own `postinst` maintainer script as a base64 blob
named `SIGNING_KEY_BASE64`, which the script decodes to
`/usr/share/keyrings/chatgpt-archive-keyring.gpg`.

The committed key was extracted as follows, from a package that had **already**
been fully verified:

1. Fetched `dists/stable/InRelease` from
   `https://persistent.oaistatic.com/codex-app-prod/linux/deb`.
2. Fetched `Packages.gz` for `amd64` and `arm64` and confirmed both matched the
   SHA-256 and size recorded in that `InRelease`.
3. Downloaded `chatgpt_26.820.71523_amd64.deb` and
   `chatgpt_26.820.71523_arm64.deb` and confirmed both matched the SHA-256 and
   size recorded in the verified `Packages.gz`.
4. Extracted `control.tar.xz` from each package **without executing any
   maintainer script**, and decoded `SIGNING_KEY_BASE64` out of `postinst`.
5. Confirmed the decoded keyring is **byte-for-byte identical across both
   architectures**.
6. Confirmed the decoded key's fingerprint is
   `3BFA0E4AE8B8CC16A2D9BA684A3B4A566C4660E4`.
7. Confirmed `gpgv`, using an isolated keyring containing only this key,
   reports `Good signature from "Codex Linux Repository"` for that same
   `InRelease`.
8. Confirmed the same key verifies the debsigs `_gpgorigin` member of both
   `.deb` files.

### On the circularity of step 7

Steps 1–3 authenticate the package against a signature made by this very key,
so on its own that chain is self-referential: it proves internal consistency,
not authenticity. The bootstrap is therefore corroborated by two independent
observations:

- **Independent keyserver copy.** `keys.openpgp.org` returns a key under
  fingerprint `3BFA0E4AE8B8CC16A2D9BA684A3B4A566C4660E4` whose primary key
  packet is the same key. (That copy is *not* usable as a keyring on its own:
  keys.openpgp.org strips the User ID and its self-signature pending address
  verification, so `gpgv` rejects it with "No public key". It corroborates the
  fingerprint; it cannot replace the packaged key.)
- **Independent prior audit.** The same fingerprint was recorded by an earlier
  manual audit of this repository origin, before this bootstrap was performed.

Both agree with the fingerprint of the key extracted from the package. This is
the strongest anchor available given that OpenAI publishes no first-party key
URL, and it is recorded here honestly rather than being presented as
first-party confirmation.

## Rules for this key

The updater treats this file as **immutable input**:

- It is loaded from the repository working tree only.
- It is never fetched over the network.
- It is never replaced or amended from a newly downloaded package, a keyserver,
  or any other dynamic source.
- There is no trust-on-first-use path and no "accept new key" flag.
- The updater asserts the full 40-hex fingerprint before use and refuses to run
  if the committed bytes do not produce exactly that fingerprint.

If upstream rotates the signing key, every updater run fails closed with
`TrustError`. That is intentional. Recovering from a rotation is a **manual
engineering review**: a human must obtain the new key, establish its provenance,
review the diff, update this document, and commit the change through the normal
reviewed pull-request path. The automation must never do this by itself.

## Re-verifying this key locally

```sh
nix run .#verify-sources          # full signed chain against the pinned key
nix build .#checks.x86_64-linux.trust-key
```
