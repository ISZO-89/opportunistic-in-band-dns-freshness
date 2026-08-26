# Opportunistic In-Band DNS Freshness
## Evidence Freeze v0.1 — Gates 1–18

**Status:** Frozen local-PoC evidence ledger  
**Date:** 2026-08-23  
**Purpose:** Preserve exactly what was tested, what passed, what each result supports, and what it does **not** support before Internet-Draft v00.  
**Rule:** If a later narrative document makes a broader experimental claim than this ledger, this ledger wins until new evidence exists.

---

# 1. Evidence policy

This project intentionally distinguishes four evidence classes:

- **PoC-validated:** directly exercised in the DNS Freshness Lab.
- **Standards-derived:** protocol behavior taken from or aligned with an existing RFC; the lab does not need to re-prove the RFC itself.
- **Design decision:** a v0.1 rule selected to make the protocol complete; it is not called PoC-validated unless a Gate exercised it.
- **External validation required:** properties that need other implementations, production intermediaries, Internet-scale deployment, browsers/OS resolvers, formal verification, or long-duration operation.

A `PASS` never means "the new DNS standard is proven". It means the concrete falsifiable claim of that Gate survived the tested conditions.

# 2. Evidence sources available at freeze

The freeze is based on:

1. the preserved Gate-1/2 and Gate-3B working snapshot supplied from the lab;
2. preserved benchmark/log excerpts supplied during the project;
3. the explicit terminal outputs for Gates 11–18 supplied in the working session;
4. the Protocol Specification v0.1 evidence-updated draft;
5. the Gate-13 published vector hashes and byte sizes supplied by the lab.

The model does **not** have a mounted copy of the user's live DNS-Lab filesystem at freeze time. Paths below identify the lab artifacts as reported by the test runs; this document does not pretend to have re-hashed every remote file. This distinction is deliberate.

# 3. Frozen lab context

- Risky network experiments were run in the isolated Ubuntu `DNS-Lab` VM, not by altering the productive Unraid host network stack.
- PoC base path: `/mnt/user/appdata/dns-service-sync-lab/`.
- Stable lab network: `dns-service-sync-net`, `172.18.0.0/16`.
- Core frozen benchmark images were not silently rebuilt for the reference Gate-3 measurements.
- Gate-3 v3 and Gate-3B measurements are controlled lab results, not Internet-wide performance claims.

# 4. Gate ledger

## Gates 1–2 — Functional/security foundation — PASS

**Evidence status:** PoC-validated, preserved historically as a combined Gate-1/2 foundation. The surviving project snapshot says both passed and should not be rerun while semantics remain unchanged; it does not preserve a trustworthy one-to-one mapping of every subcase to Gate 1 versus Gate 2. This freeze therefore refuses to invent that split.

**Validated foundation:** DNS bootstrap A/B/C; B supplies update for A; later A use without another DNS lookup; total-path failure -> DNS recovery; monotone epoch/generation behavior; legitimate content rollback under a newer epoch; active/cold lifecycle; wrong view rejection; view migration via DNS rebootstrap; Ed25519 signature checking; tampered payload rejection; fake Authority key rejection; wrong `service_id`, namespace escape, and wrong-old-state rejection; transactional multi-RR update; replay rejection; HTTPS/TLS 8443 hostname/CA validation; atomic commit/crash safety/locking.

**Supported claim:** the original PoC state machine and security boundary could perform signed in-band reconciliation and fail safely back to DNS under the exercised cases.

**Not supported:** final v0.1 wire encoding, final trust hierarchy, split-brain digest semantics, negative-state model, production integration.

## Piggyback proof — HTTP/1.1 precursor — PASS

**Tested:** existing HTTP/1.1 keep-alive TLS session; signed update on the same TCP/TLS session; no additional DNS query; no additional transport channel.

**Supported claim:** Opportunistic Freshness can ride application traffic on an existing H1/TLS connection.

**Claim boundary:** this proof predates Gate-13 deterministic CBOR/COSE. It does not by itself prove the final COSE/SF profile over H1.

## Gate 3 / Gate 3B — Performance and external-validity lab — PASS / GO

### Gate 3 v3 frozen reference

Five replicates, 200 measured samples/replicate, 20 warmups. Delay was **application response delay**, not real RTT.

| Injected delay | In-band marginal median | Classic DNS median | separate Push median |
|---:|---:|---:|---:|
| 0 ms | ~0.090 ms | ~0.149 ms | ~0.270 ms |
| 5 ms | ~0.287 ms | ~5.812 ms | ~6.735 ms |
| 20 ms | ~0.303 ms | ~21.387 ms | ~21.900 ms |
| 50 ms | ~0.338 ms | ~51.534 ms | ~51.963 ms |

### Gate 3B real symmetric netem RTT

| Configured RTT | In-band normal median | In-band update median | marginal median | DNS median | Push median |
|---:|---:|---:|---:|---:|---:|
| 0 ms | 205.76 us | 305.17 us | 93.63 us | 241.59 us | 285.66 us |
| 5 ms | 5600.33 us | 5834.60 us | 232.26 us | 5560.09 us | 6096.60 us |
| 20 ms | 21895.71 us | 22263.13 us | 324.14 us | 22064.12 us | 22203.83 us |
| 50 ms | 52083.48 us | 52451.97 us | 336.05 us | 52145.39 us | 52155.48 us |
| 100 ms | 102040.92 us | 102385.16 us | 311.53 us | 102203.49 us | 102264.74 us |

**Jitter case:** 20 ms base RTT + 5 ms jitter/direction; in-band marginal mean ~321.22 us, median 581.53 us; paired p95 was dominated by independent jitter and is not used as a clean processing-overhead claim.

**Loss cases:** moderate 1–2% loss did not reveal a structural in-band update disadvantage. At 2% loss, classic DNS recorded 49 timeouts/retries across 1100 logical requests while all logical DNS requests succeeded; in-band normal/update medians remained close (~21.93/22.28 ms).

**Idle:** update ready, 5 s no app activity, `IDLE_PACKETS=0`; next natural request on the same TLS connection carried the update.

**Wire capture:** normal in-band ~670 captured Ethernet B/transaction; update ~1052 B; marginal +382 B and +0 packets. Separate push ~1055 B. Simple unsigned A DNS refresh ~178 B/2 packets and is not comparable to signed DNSSEC wire cost.

**Supported claim:** on the tested active application path, the in-band mechanism avoided an additional freshness RTT and added only small local processing/bytes; it generated zero freshness traffic during the tested idle interval.

**Not supported:** universal Internet latency superiority, all loss regimes, all congestion-control behavior, all CDN paths, production scale.

## Gate 4 — Signal tax and bounded history/state — PASS

**Gate 4A:** 200 natural HTTPS requests on one TLS session with/without the experimental `DNS-Freshness: v=1;e=100` signal: plain ~670 L2 B/tx vs Freshness ~696 B/tx; +26 B/request, +0 packets.

**Gate 4B:** bounded history window 8, head 120, 100,000 random cursors. History remained 8 entries and persisted state size/hash did not grow with client count. Outcomes included current, delta, resync, and invalid-future cases; max returned update count stayed bounded by the history window.

**Supported claim:** no per-client subscription state is required for the tested reconciliation model; history can be bounded by configured window rather than client population.

**Claim boundary:** +26 B was an early textual cursor, not the final standardized cursor cost.

## Interrupted-delivery test — PASS

Signed transition 100->101 was intentionally cut at ~25%, 75%, and 99% of object delivery using connection reset; none committed. Only complete delivery followed by verification advanced to 101.

**Supported claim:** partial transfer does not partially mutate client state when commit is staged after complete verification.

## Gate 5 — Signed Checkpoint / no-change assertion — PASS

Tested valid matching checkpoint, newer head without retained bridge, expiry, tampered head/signature, and lease boundary behavior.

**Supported claim:** an Authority can issue a signed, time-bounded assertion binding a scope head to a generation/digest, and replay staleness is bounded by absolute expiry.

**Critical wording correction:** a Checkpoint does **not** prove that no newer state exists after `issued_at`; it provides bounded authorization/staleness until `valid_until`.

## Gate 6 — Scoped versioning — PASS

Freshness scope modeled as service + view/cohort + coherence group + generation. Atomic A+AAAA update changed one EU scope while unrelated HTTPS metadata and another view remained unchanged. Correctly signed wrong-scope update was rejected. With 10,002 Authority scopes and 100,000 irrelevant changes, a client with two active scopes required zero updates and its cursor/state remained unchanged.

**Supported claim:** invalidation/cursor work can scale with active scopes rather than total zone changes; related RRsets can change atomically without invalidating unrelated groups.

**Later refinement:** final standard uses opaque Authority-issued `scope_id`, not human-readable client-selected geography.

## Gate 7 — Freshness key rotation — PASS

Fake transition rejected; legitimate K1->K2 accepted; transition replay rejected; K2 accepted at activation; K1 accepted only during bounded overlap; K1 rejected after retirement; K2 continued.

**Supported claim:** lower-layer Freshness key rotation can occur without out-of-band client update while preserving bounded overlap and retirement.

## Gate 8 — DNSSEC end-to-end Freshness trust bootstrap — PASS

Isolated signed hierarchy `test.` -> `service.test.`. Client began without preinstalled Freshness key, validated parent DNSKEY from local trust anchor, child DS, DS-matching child KSK, child DNSKEY RRset, and signed HTTPS/SVCB private-use parameter containing the Freshness Ed25519 key. A Freshness Checkpoint then verified under the DNSSEC-bootstrapped key. Tampering with the published Freshness key without resigning DNSSEC produced DNSSEC bogus and did not install the fake key.

**Supported claim:** DNSSEC can bootstrap the Freshness signing trust in the tested hierarchy; the application relay need not distribute an unauthenticated public key.

**Not supported:** global Internet DNSSEC deployment path or arbitrary validating-resolver trust models.

## Gate 9 — Fork / split-brain detection — PASS

State identity upgraded to `scope_id + generation + state_digest`. A second genuinely Authority-signed state at the same generation but different digest produced `FORK_DETECTED` and did not overwrite local state. Wrong `from_digest` and wrong `to_digest` updates were rejected; a proper digest-chained transition advanced.

**Supported claim:** generation alone is insufficient; digest binding detects same-generation signed divergence and prevents silent overwrite.

## Gate 10 — DELETE / NODATA / NXDOMAIN — PASS

Sequence exercised RRset removal -> NODATA, re-add, whole-name removal -> NXDOMAIN, stale positive update rejection after NXDOMAIN, authorized later recreation, and failed invalid negative operation without partial commit.

**Supported claim:** the Freshness state model can represent positive, NODATA, NXDOMAIN, deletion, and recreation atomically.

## Gate 11 — Compromised-key DNSSEC emergency reset — PASS, then hardened

A real K2 compromise was simulated: K2 legitimately signed rogue K3, and the lower Freshness layer correctly accepted it because the signature was cryptographically valid. DNSSEC then published a newer recovery trust state and replaced the compromised chain; K5 was accepted, K3 lost authority, K3 could not re-enter, and a DNSSEC-valid lower trust generation was rejected.

**Supported claim:** the Freshness layer cannot detect theft of its own valid private key; a higher DNSSEC trust layer can provide emergency reset and anti-rollback.

**Discovered limitation:** the original scalar `trust_generation` could theoretically be jumped to a huge value by a compromised key. That led directly to Gate 12.

## Gate 12 — Separate DNSSEC `root_epoch` — PASS

The compromised lower chain intentionally advanced both `key_sequence` and scope generation to `9223372036854775807`. DNSSEC-authenticated `root_epoch=5` still superseded root 4, reset lower counters, removed old keys, cleared old scope state, required new admission, admitted a new root-5 Snapshot, rejected old-root objects, and rejected a stale DNSSEC-valid root-4 rollback.

**Supported claim:** lower-layer attacker-controlled counters cannot lock out a higher DNSSEC root reset when trust namespaces are separated.

## Gate 13 — Deterministic DNS state + CBOR + COSE_Sign1 — PASS

Semantically identical DNS states differing in owner-name case, RRset/RDATA ordering, and embedded DNS-name case produced byte-identical 174-byte deterministic CBOR and SHA-256:

`f3002e692ba244c7c5e74526ecbcd2b9e15d06346730d8d23ee6436ec7027728`

An actual state change changed the digest. Freshness objects used deterministic CBOR and tagged COSE_Sign1 (Tag 18), fully specified Ed25519 `alg=-19`. Modified payloads, correctly signed non-deterministic payload/protected headers, and deprecated `alg=-8` were rejected.

Measured objects:

| Object | payload CBOR | COSE total | RFC9651 SF value |
|---|---:|---:|---:|
| Checkpoint | 111 B | 204 B | 274 B |
| Delta | 173 B | 266 B | 358 B |

Compared with the selected minified JSON + raw-signature representation, COSE saved 48.6% (Checkpoint) and 54.1% (Delta).

Frozen vector hashes:

- `checkpoint.cose`: `6d7fd17b85c798242044cce0aa0938163954adbd7a0ff396dd7905f7003ef45d`
- `delta.cose`: `94f0882665abfa18913323a6776629f5087fee73710846273cee72e50b1cb92c`

**Supported claim:** a concrete deterministic signed binary profile exists, with reproducible test vectors and measured size.

**Claim boundary:** integer field labels remain experimental until draft wire assignments are frozen.

## Gate 14 — DNSSEC-bound `admission_context` — PASS

Two legitimate DNSSEC-authenticated views shared the same service, root epoch, and Freshness key but had different opaque admission contexts/scopes. A validly Authority-signed snapshot from the wrong context had a valid signature but was rejected specifically for `REJECT_ADMISSION_CONTEXT`. Rewriting the context broke the signature. Genuine DNSSEC context change cleared the old scope and required new admission; old context could not re-enter; unchanged context preserved state.

**Supported claim:** a relay cannot steer initial admission into a different valid Authority-signed view merely by replaying another cohort's Snapshot.

## Gate 15 — Resource bounds / oversize / DoS profile — PASS

Experimental profile: 4096 B COSE, 64 operations, 32 cursor scopes, CBOR depth 32, 5466-byte textual SF value ceiling for a 4096-byte decoded object.

Tested: exact-boundary acceptance; producer converts too-many-operations/oversize Delta to small signed `ResyncRequired`; 1 MiB malicious input rejected before CBOR parse and before signature work; oversized HTTP field rejected before Base64 decode; client independently rejects validly signed over-limit semantics; excessive nesting, duplicate map keys, and indefinite-length CBOR rejected; 33 cursor scopes rejected with zero per-scope lookups.

**Supported claim:** the protocol can be implemented with finite pre-parse/pre-crypto and semantic resource bounds.

**Claim boundary:** the exact numeric limits are experimental engineering values, not final standards constants.

## Gate 16 — Independent Go COSE verification — PASS

Independent Go implementation: `fxamacker/cbor` + Go `crypto/ed25519`, no reuse of the Gate-13 Python encoder/decoder.

It matched the frozen Checkpoint/Delta hashes, parsed COSE Tag 18, independently interpreted `alg=-19`, verified the 64-byte Ed25519 signatures for both Python-generated objects, and rejected a tampered object with `Ed25519 verification failed`.

**Supported claim:** Gate-13 COSE framing/signature vectors interoperate across Python and Go libraries/crypto stacks.

**Important claim boundary:** the Go program did **not** independently construct canonical DNS scope state, recompute the DNS `state_digest`, or implement the complete Snapshot/Checkpoint/Delta state machine. This is partial wire/security interoperability, not yet a second complete protocol implementation.

## Gate 17 — Real HTTP/2 carrier — PASS

TLS certificate and hostname validation passed; ALPN negotiated `h2`. One client TCP connection (`local port 53530`) carried streams `1/3/5`. Stream 1 had no Freshness object; after update readiness, stream 3 carried the exact 266-byte Gate-13 Delta with frozen SHA-256; stream 5 carried no duplicate. Server accepted one TCP connection and reported Freshness on stream 3.

**Supported claim:** the Gate-13 COSE response object can ride the next natural HTTP/2 application response on the same TLS/TCP connection without a dedicated Freshness connection.

**Claim boundary:** lab `h2` implementation; sequential streams; experimental text request cursor `v=1;e=101`; no real intermediary/CDN/browser.

## Gate 18 — Real HTTP/3 / QUIC carrier — PASS

TLS/QUIC negotiated ALPN `h3`. Client made one connect call and one handshake. H3 requests used streams `0/4/8`; UDP source port remained `47685`. Server created one QUIC protocol instance and one handshake. Stream 4 carried the same exact Gate-13 Delta; no duplicate on stream 8.

**Supported claim:** the Gate-13 COSE response object can ride the next natural HTTP/3 request/response stream on one existing QUIC connection without a dedicated Freshness connection or second handshake.

**Claim boundary:** lab `aioquic` implementation; no QUIC migration/0-RTT; sequential requests; experimental text request cursor; no production intermediary/browser/CDN.

# 5. Cross-gate architecture conclusions that are supported

The complete local evidence supports the following **qualified** conclusions:

1. DNS can remain bootstrap/recovery/root trust while active-service DNS state is reconciled over application traffic.
2. Freshness update delivery need not create a separate application-independent network transaction when natural application traffic already occurs.
3. Opportunistic mode can produce zero Freshness traffic during application silence.
4. Authority-signed state can survive an untrusted application relay, including tamper/replay/wrong-scope/wrong-service defenses tested across the gates.
5. Scope state can be digest-bound, fork-detectable, atomic, negative-state capable, and bounded-history.
6. DNSSEC can bootstrap and emergency-reset Freshness trust; separate `root_epoch` prevents compromised lower counters from blocking reset.
7. Initial/view admission can be bound to a DNSSEC-authenticated opaque context.
8. A deterministic CBOR + COSE_Sign1 + Ed25519 `-19` profile is concrete, measurable, and independently verifiable at the COSE/signature layer.
9. Producer and consumer resource costs can be bounded and oversize can fail to small resync/recovery behavior.
10. The signed response carrier has been demonstrated on existing H1 semantics and with the Gate-13 COSE object over real lab H2 and H3 connections.
11. DNS Push retains a real capability advantage when an update must be delivered during complete application silence; the strongest positioning is complementary/hybrid rather than universal replacement.

# 6. Claims that remain unsafe

Do **not** claim any of the following from the current evidence:

- "new DNS standard proven";
- universal superiority to classic DNS or DNS Push;
- zero staleness / instantaneous currentness;
- Internet-scale or production deployment validation;
- production browser/OS/CDN/WAF interoperability;
- final IANA assignments or final numeric limits;
- final standardized cursor cost of 26 bytes;
- complete cross-implementation protocol interoperability (Gate 16 is COSE/signature-layer interoperability only);
- final deterministic-CBOR request cursor tested end-to-end over all H1/H2/H3;
- final Gate-13 COSE carrier specifically retested over H1;
- formal proof of state-machine correctness;
- correctness under every possible concurrency/reordering/QUIC migration condition.

# 7. Standards cross-check at freeze date

The v0.1 design was checked against the following current RFC facts before freeze:

- RFC 4034 defines canonical DNS name/RR forms and RRset ordering used as the basis for deterministic DNS state identity.
- RFC 8949 explicitly permits protocols to require and validate deterministic CBOR encodings.
- RFC 9052 defines tagged COSE_Sign1 as CBOR Tag 18 and a four-element CBOR array.
- RFC 9864 defines fully specified COSE Ed25519 as algorithm `-19` and marks it Recommended; the older polymorphic EdDSA identifier is not the v0.1 target.
- RFC 9651 defines Structured Field Byte Sequences as colon-delimited Base64 and requires parsers to support at least 16,384 decoded octets; v0.1 intentionally imposes a much smaller experimental profile.
- RFC 9113 defines HTTP/2 multiplexed exchanges on one connection.
- RFC 9114 maps HTTP semantics to QUIC; request streams are client-initiated bidirectional streams, with the first request on stream 0 and subsequent request streams 4, 8, ... .
- RFC 9460 reserves SvcParamKey values 65280–65534 for Private Use, appropriate for the lab but not a final allocation.
- RFC 8765 DNS Push uses DSO SUBSCRIBE state and permits asynchronous notifications, preserving its distinct idle-delivery role.

# 8. Lab artifact/path index reported by the tests

Representative paths reported during the work:

- Gate-3B runner: `/mnt/user/appdata/dns-service-sync-lab/benchmark/run_gate3b_rtt.sh`
- Gate-4 bounded history: `/mnt/user/appdata/dns-service-sync-lab/benchmark/gate4-bounded/`
- Gate-5 checkpoint: `/mnt/user/appdata/dns-service-sync-lab/benchmark/gate5-checkpoint/`
- Gate-6 scope: `/mnt/user/appdata/dns-service-sync-lab/benchmark/gate6-scope/`
- Gate-7 rotation: `/mnt/user/appdata/dns-service-sync-lab/benchmark/gate7-key-rotation/`
- Gate-8 DNSSEC bootstrap: `/mnt/user/appdata/dns-service-sync-lab/benchmark/gate8-dnssec-bootstrap/`
- Gate-9 fork: `/mnt/user/appdata/dns-service-sync-lab/benchmark/gate9-fork-detection/`
- Gate-10 negative state: `/mnt/user/appdata/dns-service-sync-lab/benchmark/gate10-negative-state/`
- Gate-11 trust reset: `/mnt/user/appdata/dns-service-sync-lab/benchmark/gate11-trust-reset/`
- Gate-12 root epoch: `/mnt/user/appdata/dns-service-sync-lab/benchmark/gate12-root-epoch/`
- Gate-13 CBOR/COSE: `/mnt/user/appdata/dns-service-sync-lab/benchmark/gate13-cbor-cose/`
- Gate-14 admission context: `/mnt/user/appdata/dns-service-sync-lab/benchmark/gate14-admission-context/`
- Gate-15 resource bounds: `/mnt/user/appdata/dns-service-sync-lab/benchmark/gate15-resource-bounds/`
- Gate-16 Go interop: `/mnt/user/appdata/dns-service-sync-lab/benchmark/gate16-independent-interop/`
- Gate-17 HTTP/2: `/mnt/user/appdata/dns-service-sync-lab/benchmark/gate17-http2/`
- Gate-18 HTTP/3: `/mnt/user/appdata/dns-service-sync-lab/benchmark/gate18-http3/`

A public reproducibility repository should later preserve scripts, frozen dependencies/images, result logs, and vector files together rather than relying only on this path ledger.

# 9. Freeze decision

**Local PoC decision: GO to Internet-Draft/specification work.**

No fundamental architecture blocker was found in the selected Gates 1–18. This is sufficient to justify writing and circulating an Internet-Draft candidate; it is **not** sufficient to claim production readiness or standards consensus.

New local tests should be added only when they close a concrete claim boundary discovered during drafting/review. The two clearest narrow candidates, if desired, are:

1. final deterministic-CBOR request cursor over H1/H2/H3;
2. second full semantic implementation that independently computes DNS canonical state/digests and applies the state machine.

Everything else of highest value now requires external stacks, integration, deployment, or review rather than more self-contained happy-path lab work.
