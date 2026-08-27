# Post-v0.1 Alt-Svc / Freshness Reordering Falsification

**Date:** 2026-08-27  
**Status:** local controlled Chromium/HTTP/3 follow-up evidence  
**Release relationship:** post-v0.1.0; the v0.1.0 tag, Zenodo deposit, and frozen v0.1 evidence remain unchanged.

## Question

Does a concrete stale-state protection difference appear between Chromium Alt-Svc handling and the versioned Freshness state model under deliberately adversarial response ordering / stale replay?

## C1 — Chromium Alt-Svc response reordering

The C1 server used three HTTP/3 ports on the same test service:

- origin: `4433`
- test-designated older alternative: `4444`
- test-designated newer alternative: `4555`

The server sent the newer Alt-Svc advertisement first and deliberately delayed the older advertisement. After both responses completed, the origin QUIC connection was closed so that the next request had to make a fresh routing decision from cached Alternative Service state.

Observed proof excerpt, repeated twice:

```text
C1_NEW_SEND t_ms=356502.4 stream=12 alt_port=4555
C1_OLD_SEND t_ms=357403.6 stream=4 alt_port=4444
C1_ALT_HIT t_ms=358120.5 role=ALT_B port=4444 stream=0 path=/probe

C1_NEW_SEND t_ms=454639.5 stream=12 alt_port=4555
C1_OLD_SEND t_ms=455539.5 stream=4 alt_port=4444
C1_ALT_HIT t_ms=456258.2 role=ALT_B port=4444 stream=0 path=/probe
```

Observed property:

> In this controlled Chromium/H3 test, the later-arriving test-designated older Alt-Svc advertisement replaced the previously learned newer alternative for the subsequent routing decision.

## C2 — native Chromium Freshness stale replay

The companion Freshness test reused the already validated native Chromium vertical slice and existing Gen100 -> Gen101 signed Delta.

Sequence:

1. admit Snapshot Gen100 / endpoint `172.18.0.61`;
2. verify and commit Delta Gen100 -> Gen101 / endpoint `172.18.0.12`;
3. deliver the same Gen100 -> Gen101 Delta again while local state is already Gen101.

Observed proof excerpt:

```text
DNS_FRESHNESS_NATIVE SNAPSHOT_ADMITTED=PASS GEN=100 ENDPOINT=172.18.0.61 ROOT_EPOCH=1
DNS_FRESHNESS_NATIVE FROM_GENERATION_DIGEST=PASS GEN=100
DNS_FRESHNESS_NATIVE COMMIT=PASS GEN=101 ENDPOINT=172.18.0.12 ROOT_EPOCH=1
DNS_FRESHNESS_NATIVE STALE_DELTA=IGNORE LOCAL_GEN=101 FROM_GEN=100
C2_BROWSER_DONE=PASS
```

The third application request also carried a Freshness cursor at Gen101 before the stale Delta was attached, confirming that the client had already advanced its local Freshness state.

Observed property:

> The stale transition did not regress the committed Freshness generation.

## Comparative result

Supported claim:

> **In these controlled Chromium/HTTP/3 tests, Alt-Svc was observed to regress to a later-arriving stale alternative, while Opportunistic Freshness rejected stale generation ancestry and preserved the newer committed state.**

The relevant design distinction is **state reconciliation, not endpoint advertisement**. The Freshness path explicitly carries generation/digest ancestry and rejects stale transitions; Alt-Svc does not define the same versioned service-state reconciliation model.

## Claim boundary

This result does **not** establish:

- universal superiority over Alt-Svc;
- how often the observed Alt-Svc regression pattern occurs in production;
- Internet-scale deployment viability;
- lower end-to-end recovery latency in every topology;
- production readiness.

It establishes a concrete stale-state protection difference in the tested Chromium/H3 scenarios.

## Local freeze

Canonical local freeze:

```text
/mnt/user/appdata/dns-service-sync-lab/benchmark/results/altsvc-vs-freshness-reorder/20260827T055217Z
```

Freeze root SHA-256:

```text
caccf4d38bb4f2dac7d5e62db60c299314b6a08f902e18a262ac45044753f9dc
```

The local freeze contains C1/C2 proof extracts, browser/server logs, test harnesses, vectors, Chromium identity, `SHA256SUMS`, and `FREEZE_ROOT.sha256`.

External teams are encouraged to reproduce the comparison independently and to test whether the observed Alt-Svc behavior remains operationally relevant across production CDNs, intermediaries, browser versions, and deployment patterns.
