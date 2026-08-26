# Provenance

## Project

Opportunistic In-Band DNS Freshness

Author: Marc Nicolai Fronemann

This public-release staging tree was assembled from the retained DNS Freshness Lab after completion of the documented experimental gates.

The release separates:

- implementation reconstruction material,
- historical frozen evidence,
- reproduction material,
- protocol test vectors.

Historical evidence files under `evidence/` are preserved rather than rewritten for later convenience.

## Chromium base revision

The Chromium implementation is based on:

`782af9cb30a53f54487e5d2e44738645a8ec457c`

Tested Chromium version:

`Chromium 151.0.7922.34`

Recorded GN build arguments:

```gn
is_debug = false
symbol_level = 0
```

## Historical Chromium patch

The hard zero-DNS cutover evidence freeze contains:

`evidence/hard-cutover/chromium.patch`

SHA-256:

`496c4e5f2d80ea8e01c0931115c5907cc3a142b23ab46898e5fb578e73f14261`

That historical patch was created with ordinary Git diff behavior and therefore contains the tracked Chromium modifications only.

At freeze time, `chromium-status.txt` recorded the modified tracked files and also recorded `services/network/freshness/` as untracked.

The seven Freshness source files were therefore present in the retained working tree but were not represented in the historical `chromium.patch`.

The retained tracked working-tree diff was subsequently verified byte-for-byte against the historical hard-cutover patch.

## Complete public Chromium reconstruction patch

The public reconstruction patch is:

`implementation/chromium-freshness-v0.1.patch`

SHA-256:

`c4927dc7acf1c5a893055456ea1528a616849b97d20b125fc4a07150db7d0a77`

It contains 34 changed files in total, including these seven files as new files:

- `services/network/freshness/freshness_cursor.cc`
- `services/network/freshness/freshness_cursor.h`
- `services/network/freshness/freshness_processor.cc`
- `services/network/freshness/freshness_processor.h`
- `services/network/freshness/freshness_state_store.cc`
- `services/network/freshness/freshness_state_store.h`
- `services/network/freshness/freshness_wire_profile.h`

This complete patch was constructed later from the retained Chromium working tree using a temporary Git index without modifying the real repository index.

It applies cleanly against the recorded Chromium base revision.

Important limitation:

No freeze-time cryptographic hashes were recorded for the seven files that were untracked at the time of the historical cutover freeze. Their presence at freeze time is supported by the frozen Git status and by the Chromium build definition referencing them, but this release does not claim independently proven byte-for-byte historical identity for those seven files.

## Tested Chromium binary

The retained tested Chromium binary had SHA-256:

`4ba84b23a5551f245cca8e2a06401f89b7aa865709d6ec619f004eca4d6ec76a`

The binary itself is not included in this source release.

## Keys and certificates

Historical private lab keys are intentionally excluded from this release.

In particular, the release does not include the retained private Authority signing key, H3 server private key, DoH private key, lab CA private key, or other private keys from the original lab.

`evidence/hard-cutover/fullstack-trust-anchor.key` is not a private key. It is the public DNSSEC trust-anchor DNSKEY used by the frozen experiment.

Public certificates and already-signed frozen test objects may be included as historical evidence.

Clean reproduction should generate fresh test-only private keys rather than depend on retained historical private key material.

## Frozen evidence

Historical evidence includes the successful Chromium hard cutover, the 100-repetition browser Freshness measurement, the H3 wire comparison, and the deterministic CBOR/COSE Gate 13 vectors.

Original per-run `SHA256SUMS` files are retained inside their respective evidence directories.

`RELEASE_SHA256SUMS` is a separate release-level manifest generated only after assembly of the public staging tree.

## Third-party material

Chromium and other third-party software remain subject to their respective upstream licenses and copyrights.

The Chromium patch represents modifications against upstream Chromium and does not relicense upstream Chromium source code as original project material.

The untracked Chromium-tree directory `third_party/llvm-libclang/` was explicitly excluded from the public implementation patch.
