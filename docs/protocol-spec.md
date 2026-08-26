# Opportunistic In-Band DNS Freshness
## Protocol Specification v0.1 — Annotated Architecture Freeze

**Status:** Research protocol specification, pre-Internet-Draft  
**Language:** German explanation with normative protocol terms in English  
**Date:** 2026-08-23  
**Intended next step:** derive an English Internet-Draft v00 and a separate technical whitepaper  
**Maturity:** architecture and core security/resource invariants validated by PoC work through Gate 18; deterministic CBOR/COSE wire objects and binary test vectors exist; a second-language Go implementation independently parsed and verified the Gate-13 COSE objects; real lab HTTP/2 and HTTP/3 carriers transported the Gate-13 Delta on one existing connection. Production middlebox/CDN/browser integration and a fully independent semantic implementation remain outstanding.

---

# 0. How to read this document

This document deliberately separates three kinds of statements:

- **[PoC-validated]** — experimentally exercised in the DNS Freshness Lab.
- **[Standards-derived]** — behavior or terminology aligned with an existing RFC.
- **[v0.1 design]** — a protocol decision made during specification work. It is not presented as already proven by the PoC unless explicitly marked.

The capitalized words **MUST**, **MUST NOT**, **SHOULD**, **SHOULD NOT**, and **MAY** are intended in the BCP 14 sense when this document is later converted into an Internet-Draft. In this annotated v0.1 they already indicate intended normative strength.

## 0.1 Important correction discovered during specification

The PoC used one scalar `trust_generation` during the emergency trust-reset experiment. That is insufficient as a final protocol rule: a compromised Freshness signing key could sign a successor with an artificially enormous generation value and attempt to make a later lower-numbered DNSSEC reset look like a rollback.

**v0.1 therefore separates trust namespaces.**

The authoritative trust coordinate is:

```
root_epoch      controlled only by DNSSEC
key_sequence    controlled inside one root_epoch
```

A Freshness key can advance `key_sequence`; it can **never** advance `root_epoch`.

A DNSSEC-authenticated higher `root_epoch` supersedes **all** state, keys, generations, and digests from lower root epochs, regardless of how large any attacker-chosen lower-level counter became.

Additionally, an emergency root reset MUST invalidate Freshness-managed DNS state authenticated under the old root epoch. The client MUST obtain a new DNS bootstrap and/or a new signed Snapshot before treating the scope as current again.

This rule was discovered during specification work after Gate 11 and was subsequently implemented and exercised in **Gate 12**. The PoC demonstrated that an attacker-controlled maximum lower-level key sequence and scope generation could not block a higher DNSSEC-authenticated `root_epoch`; the reset invalidated old keys and scope state and required fresh admission.

## 0.2 Important correction to checkpoint language

The PoC printed `CURRENT_PROVEN` when a signed checkpoint matched local state. The final protocol must use more precise language.

A signed Checkpoint proves:

1. the Authority asserted that `generation + state_digest` was the head when the Checkpoint was issued; and
2. the Authority authorizes the client to rely on that state no later than `valid_until`.

It **cannot cryptographically prove that no change happened after `issued_at`**, because a relay can replay an older still-valid Checkpoint until its absolute expiry.

Therefore the security property is **bounded staleness**, not omniscient instantaneous freshness.

This is analogous to the core trade-off of DNS caching: a validity interval bounds how long an older state can remain usable. The advantage of this protocol is that active application traffic can carry newer signed assertions without a separate DNS transaction.

## 0.3 Evidence update after Gates 12–18

The architecture hardenings discovered during specification were not left as paper-only assumptions. They were subsequently implemented and tested:

- **Gate 12:** separate DNSSEC `root_epoch` defeats attacker-chosen maximum lower-level counters, invalidates old state, and forces fresh admission;
- **Gate 13:** deterministic DNS canonicalization + CBOR + COSE_Sign1/Ed25519 `-19`, tamper/non-determinism rejection, measured wire sizes, binary vectors;
- **Gate 14:** DNSSEC-bound `admission_context` prevents valid-signature wrong-view steering and forces re-admission on genuine context change;
- **Gate 15:** hard resource bounds, pre-parse/pre-crypto oversize rejection, bounded cursor/operation/depth behavior, and small signed resync fallback;
- **Gate 16:** an independent Go implementation using `fxamacker/cbor` and Go `crypto/ed25519` parsed the Python-generated COSE_Sign1 vectors, interpreted `alg=-19`, verified both signatures, matched vector hashes, and rejected a tampered object;
- **Gate 17:** a real TLS/HTTP/2 connection negotiated `h2`, carried three application streams (`1/3/5`) on one TCP/TLS connection, and transported the Gate-13 266-byte Delta byte-identically on stream 3 without a second Freshness connection;
- **Gate 18:** a real TLS 1.3/QUIC HTTP/3 connection negotiated `h3`, carried three request streams (`0/4/8`) on one QUIC connection, and transported the same Gate-13 Delta byte-identically on stream 4 without a second QUIC handshake.

These properties are therefore marked **[PoC-validated]** in the relevant sections, with explicit claim boundaries. Numeric profile values remain experimental unless the draft later freezes them. Gate 16 proves independent COSE framing/signature interoperability, not yet a second full implementation of DNS-state canonicalization and all Freshness semantics. Gates 17/18 used the final Gate-13 COSE response object but an experimental textual request cursor (`v=1;e=101`), not yet the final CBOR cursor bundle.

---

# 1. Executive summary — plain language

Traditional DNS caching is efficient because a client can reuse an answer until its TTL expires. The cost is that a DNS change can remain unseen until the next DNS refresh.

DNS Push solves a different problem: a client subscribes to a DNS name/type and a DNS server actively sends changes over a persistent DSO session. This can provide asynchronous updates even when the application itself is idle, but it requires subscription state and a maintained stateful DNS session.

This protocol introduces a third operating mode:

> If an application is already communicating with a service, use that already-existing authenticated application traffic to carry cryptographically authenticated DNS freshness information.

The protocol does not replace DNS.

DNS remains responsible for:

- initial resolution;
- cold admission;
- recovery when no usable application path exists;
- recovery when retained history cannot bridge a version gap;
- DNSSEC-based trust bootstrap;
- emergency trust reset.

The Freshness protocol is responsible for:

- telling an active client which authoritative DNS state is current enough to use;
- carrying changed DNS state opportunistically;
- avoiding a separate DNS round trip when natural application traffic already exists;
- keeping protocol state bounded;
- detecting gaps and forks;
- preventing partial commits;
- supporting positive state, NODATA, NXDOMAIN, deletion, and recreation;
- keeping the application relay unable to forge DNS state.

The base mode creates **no application-independent freshness traffic**. If there is no natural application traffic, it sends nothing.

A deployment that requires immediate asynchronous updates while the application is silent may continue to use DNS Push. A future deployment policy can prefer Opportunistic Freshness while natural traffic exists and activate Push only when asynchronous idle delivery is actually required.

---

# 2. Problem statement

## 2.1 Existing DNS caching

A DNS resolver normally obtains an RRset and caches it for a TTL. The TTL limits how long the cached information can be used before the source needs to be consulted again.

This is highly scalable, but it creates a freshness/traffic trade-off:

```
long TTL  -> fewer DNS queries, potentially longer stale window
short TTL -> shorter stale window, more DNS query traffic
```

Serve-Stale improves resilience when authoritative refresh fails, but intentionally permits older data under defined failure conditions. It is not a mechanism for learning changes faster.

## 2.2 DNS Push

DNS Push uses DNS Stateful Operations and subscriptions. While a subscription is active, the client expects the server to report changes. This permits a client to avoid polling and can deliver a change while the application is otherwise silent.

The cost is architectural state:

- a DSO session;
- subscription state;
- connection/session lifetime management;
- keepalive behavior while the active subscription is maintained.

DNS Push is appropriate where **asynchronous notification during application silence** is genuinely required.

## 2.3 Opportunity

Many DNS lookups exist only to enable a service connection that then carries far more traffic than DNS itself.

Once the client is already exchanging authenticated HTTPS traffic with the service, a separate DNS transaction solely to learn that a cached RRset is unchanged can be redundant.

The protocol therefore asks:

> Can the service transport an Authority-signed DNS state assertion on application traffic that would have happened anyway?

If yes, the client can obtain fresher DNS state without an additional DNS request/response exchange.

---

# 3. Design goals

The base protocol has the following goals.

## 3.1 Zero freshness-only traffic while idle

**[PoC-validated]**

In Opportunistic Mode, an implementation:

- MUST NOT create a network connection solely for Freshness maintenance.
- MUST NOT create a synthetic HTTP request solely to refresh Freshness.
- MUST NOT send periodic Freshness keepalives.
- MUST NOT maintain a server-side per-client subscription merely to preserve Freshness.

If the application would otherwise send no traffic, the Freshness layer sends no traffic.

## 3.2 No extra application round trip for normal active refresh

**[PoC-validated property]**

When a natural application transaction already occurs, the client cursor travels with that transaction and a Checkpoint or Delta may return on the associated response.

Freshness therefore SHOULD NOT require an additional request/response round trip in the common active-path case.

## 3.3 DNS remains fallback and source of recovery

**[PoC-validated]**

The protocol MUST fail back to normal DNS resolution whenever:

- no eligible application path is usable;
- no trusted Freshness object is available before required validity expires;
- an update chain has a gap outside retained history;
- a scope cannot be identified safely;
- a fork is detected;
- trust is unavailable or invalid;
- a carrier strips or rejects the Freshness extension;
- the client deliberately evicts the scope.

## 3.4 Bounded server state

**[PoC-validated]**

The protocol MUST NOT require per-client subscription state.

Authority-side retained update history MUST be bounded by policy and MUST NOT grow as a function of client count.

## 3.5 Cryptographic authority separation

**[PoC-validated concept]**

The application server or relay MAY transport Freshness objects but MUST NOT be trusted merely because it terminates the application connection.

DNS state is accepted only when authorized by the Freshness trust model.

Compromise or misbehavior of a relay may delay or suppress updates, but MUST NOT allow it to forge a new valid DNS state without an authorized signing key.

## 3.6 Backward compatibility

A client, resolver, proxy, service, or DNS zone that does not implement the protocol MUST continue to operate using conventional DNS and conventional application protocol behavior.

Unknown Freshness discovery parameters MUST NOT be declared mandatory in SVCB/HTTPS during the experimental compatibility profile.

## 3.7 Bounded staleness

The protocol does not promise perfect instantaneous coherence.

It MUST provide explicit upper bounds on how long a previously signed state may continue to be relied upon through:

- Freshness assertion expiry;
- signing-key authorization expiry;
- DNSSEC root authorization policy;
- ordinary DNS recovery behavior.

---

# 4. Non-goals

The v0.1 protocol does **not** attempt to:

- replace recursive DNS;
- replace authoritative DNS;
- replace DNSSEC;
- replace DNS Push for workloads requiring asynchronous updates while the application is silent;
- make the DNS globally strongly consistent;
- reconstruct unlimited historical versions;
- provide an audit log;
- update arbitrary delegation topology in-band;
- provide a new general-purpose application transport;
- make an unsigned DNS zone cryptographically trustworthy;
- guarantee that a malicious relay cannot withhold a valid newer state during the permitted Freshness lease;
- infer geographic or ECS views on the client.

---

# 5. Actors

## 5.1 DNS Authority

The administrative authority for the DNS data represented by a Freshness Scope.

It controls:

- DNS records;
- DNSSEC-authenticated Freshness discovery;
- Freshness root trust;
- generation of signed state assertions or delegation to an authorized signing service.

## 5.2 Freshness Signer

The component holding an authorized private signing key used to sign Freshness objects.

It MAY be separated from the application server.

## 5.3 Application Relay

An HTTPS/application endpoint that carries signed Freshness objects.

The Relay:

- need not possess the Freshness private key;
- MUST NOT be assumed to be authoritative for DNS state solely because TLS authenticated the application service;
- may cache and distribute already-signed Freshness artifacts;
- may be geographically distributed.

## 5.4 Client Freshness Agent

The client component that:

- performs or consumes DNS resolution;
- validates Freshness trust;
- stores active Freshness Scopes;
- sends cursors;
- verifies signed objects;
- atomically commits updates;
- triggers DNS recovery.

## 5.5 Recursive Resolver

A conventional recursive DNS resolver.

It remains unchanged by the base protocol.

A client may validate DNSSEC itself or rely on a trusted validating resolver according to existing DNSSEC security rules.

---

# 6. Core identifiers

## 6.1 `service_id`

**[v0.1 design]**

`service_id` is a 128-bit opaque value authenticated during DNSSEC Freshness discovery.

Properties:

- MUST be stable for the service for the life of a `root_epoch`;
- MUST be included in every signed Freshness object;
- MUST be checked before an object can affect cache state;
- MUST NOT contain a client identifier;
- MUST NOT be interpreted by the client.

Purpose:

- prevents cross-service replay;
- avoids complex origin/name canonicalization inside every signed object;
- allows the DNSSEC discovery record to bind a human DNS service name to a compact protocol identifier.

## 6.2 `admission_context`

**[PoC-validated security design — Gate 14]**

`admission_context` is a 128-bit opaque value authenticated by DNSSEC discovery and associated with the DNS selection context from which the application connection was bootstrapped.

It exists to prevent an application relay from steering a new client into a different but otherwise valid Authority-signed scope.

Properties:

- MUST be authenticated by DNSSEC as part of Freshness discovery;
- MUST be included in a first-admission Snapshot;
- MUST exactly match the client's currently accepted DNSSEC discovery context;
- MUST NOT encode a stable per-client identity;
- SHOULD be shared by all clients in the same Authority-defined DNS selection cohort;
- MAY change when the Authority changes the relevant view/selection context.

The client does not interpret the value. In particular, it does not infer geography, ECS prefixes, or CDN topology from it.

A Snapshot with a valid Authority signature but a non-matching `admission_context` MUST be rejected for new admission.

If DNSSEC discovery changes `admission_context` while `root_epoch` and the Freshness root key remain unchanged, all old scoped state for the previous context MUST be invalidated and fresh admission MUST be required. Revalidation of an unchanged context MUST NOT invalidate working state.

Gate 14 exercised all of these properties using two separately DNSSEC-authenticated views sharing the same `root_epoch` and the same valid Freshness signing key. A validly signed Snapshot from the wrong context was rejected; rewriting the context broke the signature; a genuine DNSSEC context transition invalidated the old scope and required a new Snapshot.

This closes a subtle steering attack in which an untrusted relay could otherwise choose among multiple valid signed scopes.

## 6.3 `scope_id`

**[PoC concept, hardened in v0.1]**

A `scope_id` is a 128-bit opaque Authority-issued identifier for one coherence domain.

A scope represents a set of DNS query keys that are intended to change atomically and share one generation.

A scope may represent, for example:

- endpoint A + AAAA RRsets;
- HTTPS/SVCB configuration;
- another tightly coupled group.

A scope MUST NOT be interpreted as a human geography label such as `EU`, `US`, or an ECS prefix.

A scope SHOULD be shared by all clients receiving the same authoritative coherence state. It MUST NOT intentionally encode a stable per-client identity.

## 6.4 Scope membership

**[v0.1 design]**

For one `scope_id`, the member set is immutable.

A member is:

```
(owner_name, rrtype, rrclass)
```

For v0.1:

- `rrclass` MUST be `IN`.
- An implementation MUST NOT infer that an RRtype absent from the scope is DNS NODATA.
- Only explicit scope members are managed by the Freshness layer.

If the Authority needs to change scope membership, it MUST issue a new scope identifier and require a new Snapshot/admission.

This avoids ambiguous state hashing and accidental claims about DNS data outside the scope.

## 6.5 `generation`

A scope-local unsigned 64-bit monotonically increasing integer.

Rules:

- MUST increase for every semantic state change within the scope;
- MUST NOT decrease;
- MUST NOT wrap;
- MUST NOT be used alone as proof of state identity.

## 6.6 `state_digest`

**[PoC-validated concept]**

A 256-bit SHA-256 digest over the deterministic canonical representation of the complete scope state.

State identity is therefore:

```
(root_epoch, service_id, scope_id, generation, state_digest)
```

The digest detects:

- same-generation forks;
- wrong update ancestry;
- incorrect destination state;
- split-brain between backends.

---

# 7. Root trust namespace

## 7.1 `root_epoch`

**[v0.1 security hardening]**

`root_epoch` is an unsigned 64-bit value controlled **only** by DNSSEC-authenticated Freshness discovery.

A Freshness-signed object MUST NOT create, advance, or modify `root_epoch`.

A client stores the highest valid DNSSEC-authenticated `root_epoch` it has accepted for the service.

## 7.2 Root-epoch precedence

If a DNSSEC-valid discovery record contains:

```
incoming.root_epoch > local.root_epoch
```

the incoming root epoch supersedes the local Freshness trust namespace.

If the new record is marked as an emergency reset, the client MUST:

1. discard all Freshness signing keys from older root epochs;
2. invalidate all Freshness leases from older root epochs;
3. mark all Freshness-managed scope state from older root epochs unusable as Freshness-authoritative state;
4. perform normal DNS recovery / cold admission;
5. require a new signed Snapshot under the new root epoch before re-entering Freshness-Authorized state.

No `key_sequence`, scope `generation`, or `state_digest` from an older root epoch can block this reset.

## 7.3 Why this hierarchy is necessary

A compromised lower-level key can sign arbitrary lower-level counters.

It cannot sign DNSSEC.

Therefore the protocol must not compare a DNSSEC reset to an attacker-controlled lower-level scalar in the same namespace.

---

# 8. Freshness signing keys

## 8.1 Root key

DNSSEC discovery authenticates a Freshness root public key for the active `root_epoch`.

The corresponding private key MUST NOT be present at an untrusted application relay.

## 8.2 Direct signing profile

A minimal implementation MAY use the DNSSEC-authenticated root key directly to sign Freshness objects.

This is simple but increases exposure of the root private key if frequent Checkpoints are generated.

## 8.3 Delegated operational signing profile

**[v0.1 recommended design]**

A production implementation SHOULD support an operational signing key authorized by the Freshness root.

The root signs an `OperationalKeyAuthorization` object containing:

- `root_epoch`;
- `service_id`;
- `key_sequence`;
- operational public key;
- `not_before`;
- `not_after`;
- permitted object types.

The operational key:

- MAY sign Checkpoints, Deltas, Snapshots, and Resync objects as authorized;
- MUST NOT advance `root_epoch`;
- MUST NOT authorize another operational key unless a future extension explicitly permits it.

This limits blast radius if an online signer is compromised.

## 8.4 Key validity

Every accepted signed object MUST be covered by a signing-key authorization whose validity includes the object's issuance time.

A state assertion's `valid_until` MUST NOT exceed the signing key's authorization `not_after`.

## 8.5 Emergency reset

If a root or operational signing key is believed compromised, DNSSEC may publish a higher `root_epoch`.

A higher root epoch is the protocol's highest-precedence trust reset.

---

# 9. Scope state model

## 9.1 Member state

For each explicit scope member `(name,type,class)`, the result state is one of:

### POSITIVE

The member has an RRset:

```
status = POSITIVE
ttl
rdata[]
```

### NODATA

The owner name exists but the specific member RRtype does not:

```
status = NODATA
negative_ttl
```

### NXDOMAIN

The owner name does not exist.

NXDOMAIN is name-level state. All scope members with that owner name are NXDOMAIN.

The snapshot encoding SHOULD represent this once at the name level to avoid inconsistent combinations.

## 9.2 TTL metadata

TTL is semantically relevant and SHOULD be included in canonical scope state.

A change in authoritative TTL SHOULD advance the scope generation.

While a valid Freshness assertion authorizes the state, the Freshness validity interval controls usability.

When Freshness coverage ends, implementations MUST return to ordinary DNS cache semantics. They MUST NOT invent an indefinite TTL extension.

## 9.3 Negative state

**[PoC-validated]**

The protocol supports transitions including:

- POSITIVE -> NODATA;
- NODATA -> POSITIVE;
- POSITIVE/NODATA -> NXDOMAIN;
- NXDOMAIN -> POSITIVE or NODATA through a newer authorized generation.

A stale signed positive update MUST NOT resurrect a newer NXDOMAIN state.

---

# 10. Canonical scope-state representation

## 10.1 Goal

All independent implementations must calculate the same `state_digest` for the same DNS state.

## 10.2 DNS canonicalization

**[Standards-derived + v0.1 design]**

v0.1 SHOULD reuse DNSSEC canonical DNS name and RR ordering rules from RFC 4034 where applicable:

- fully qualified DNS names;
- lowercase canonical form where DNS canonical rules require it;
- no name compression;
- deterministic RR ordering;
- deterministic RRset ordering.

## 10.3 Protocol canonicalization

The complete scope state is encoded using deterministic CBOR.

The deterministic encoding MUST follow the Core Deterministic Encoding requirements of RFC 8949.

The digest input MUST include, at minimum:

```
protocol_version
root_epoch
service_id
scope_id
member descriptors
member/name status
RR TTL / negative TTL
canonical RDATA
```

It MUST NOT include:

- local cache timestamps;
- transport connection identifiers;
- client identifiers;
- HTTP metadata;
- relay identifiers.

## 10.4 Digest

For v0.1:

```
state_digest = SHA-256(deterministic_scope_state_cbor)
```

A future version may define another digest algorithm using explicit algorithm agility. v0.1 does not permit silent substitution.

---

# 11. Freshness object encoding

## 11.1 Deterministic CBOR

**[PoC-validated target profile — Gate 13]**

Freshness payloads use deterministic CBOR.

Reasons:

- compact binary representation;
- existing IETF specification;
- deterministic serialization rules;
- direct byte-string representation;
- avoidance of JSON whitespace/order/base64 ambiguity present in the early PoC.

Gate 13 demonstrated that semantically identical DNS states with different owner-name case, RRset ordering, RDATA ordering, and embedded DNS-name case produced byte-identical deterministic CBOR state encodings and identical SHA-256 state digests. An actual DNS state change changed the digest.

The Gate 13 decoder profile rejected non-deterministic encodings, duplicate map keys, and indefinite-length containers. Gate 15 additionally bounded CBOR nesting depth. Final numeric parser limits remain profile parameters, but the requirement for deterministic and bounded decoding is normative.

## 11.2 Canonical DNS state representation

**[PoC-validated target profile — Gate 13]**

DNS owner names and RDATA used in `state_digest` computation MUST be transformed into DNSSEC-canonical wire form before deterministic CBOR encoding. The PoC used dnspython DNSSEC digestable representations aligned with RFC 4034 canonical DNS ordering semantics.

RR order, RRset input order, presentation-format capitalization, and equivalent textual presentation MUST NOT change the resulting state identity.

## 11.3 COSE_Sign1

**[PoC-validated target profile — Gate 13]**

Signed Freshness objects use `COSE_Sign1` with CBOR Tag 18.

The base signature profile uses the fully specified COSE **Ed25519** algorithm identifier **-19**. The deprecated polymorphic `EdDSA` identifier `-8` is not accepted by the v0.1 profile.

The COSE protected header MUST identify at least:

- algorithm = Ed25519 (`-19`);
- key identifier;
- protocol content/object type binding once the Internet-Draft freezes that field.

Gate 13 produced valid COSE_Sign1 Checkpoint and Delta objects, rejected modified signed payloads, rejected correctly signed but non-deterministic payload/protected-header encodings, and rejected a correctly signed object using deprecated algorithm id `-8`.

## 11.4 Measured v0.1 experimental wire sizes

**[PoC-validated — Gate 13]**

For the tested compact integer-label schema:

| Object | Deterministic CBOR payload | COSE_Sign1 total | HTTP Structured Field Byte Sequence value |
|---|---:|---:|---:|
| Checkpoint | 111 B | 204 B | 274 B |
| Delta | 173 B | 266 B | 358 B |

Against a semantically comparable minified JSON representation plus a raw 64-byte Ed25519 signature, the measured COSE objects were 48.6% smaller for the Checkpoint and 54.1% smaller for the Delta. These are PoC measurements for the tested schema, not universal compression guarantees.

Gate 13 also generated reusable binary vectors:

- `checkpoint.cose`: 204 B;
- `delta.cose`: 266 B;
- `dns-state.cbor`: 174 B;
- SHA-256 metadata for payload and complete COSE objects.

## 11.5 Signature verification and commit order

A client MUST NOT mutate DNS state until:

1. the complete encoded object is received;
2. outer byte-size limits are satisfied;
3. deterministic CBOR/COSE structure is syntactically valid;
4. COSE protected headers are acceptable;
5. the signing key is authorized for the active `root_epoch`;
6. the signature is valid;
7. service/root/admission/scope identifiers are valid;
8. generation/digest ancestry is valid;
9. every operation is semantically valid and within resource limits;
10. the resulting state digest equals the signed destination digest.

Only after all checks pass may one atomic commit occur.

**[PoC-validated property: partial delivery up to 99% never committed.]**

# 12. Freshness object types

v0.1 defines the following logical objects.

Gate 13 exercised an experimental compact integer-label schema and generated binary vectors. The Internet-Draft MAY still renumber labels before publication, but once v00 test vectors are published, label assignments MUST be treated as wire-format commitments for that draft version.

## 12.1 `Snapshot`

Purpose:

- initial Freshness admission;
- bounded resynchronization when the Authority elects to send a full state;
- state establishment after a root reset.

Fields:

```
version
object_type = SNAPSHOT
root_epoch
service_id
admission_context
scope_id
generation
state_digest
issued_at
valid_until
members
complete_scope_state
```

Rules:

- Snapshot MUST contain the complete state for every member of the scope.
- On first admission, Snapshot `admission_context` MUST equal the DNSSEC-authenticated context accepted during bootstrap.
- The client MUST independently recompute `state_digest`.
- Admission is atomic.
- A Snapshot from a different scope MUST NOT silently overwrite an active scope unless the client is explicitly performing new admission/recovery.

## 12.2 `Checkpoint`

Purpose:

- assert the Authority's known head without repeating unchanged RR data.

Fields:

```
version
object_type = CHECKPOINT
root_epoch
service_id
scope_id
generation
state_digest
issued_at
valid_until
```

Interpretation:

- if generation and digest equal local state: lease may be renewed;
- if generation is equal but digest differs: FORK;
- if generation is newer and no applicable Delta is supplied: recovery/resync required;
- if generation is older: stale object, ignore;
- if root epoch differs: apply root-epoch rules.

A Checkpoint is a signed bounded-validity assertion, not proof that no future change occurs after issuance.

## 12.3 `Delta`

Purpose:

- transition one known scope state to a newer state.

Fields:

```
version
object_type = DELTA
root_epoch
service_id
scope_id

from_generation
from_digest

to_generation
to_digest

issued_at
valid_until

operations[]
```

Rules:

- `from_generation` MUST equal local generation.
- `from_digest` MUST equal local digest.
- `to_generation` MUST be greater than `from_generation`.
- all operations MUST validate against the pre-commit candidate state;
- recomputed resulting digest MUST equal `to_digest`;
- commit MUST be atomic.

## 12.4 `ResyncRequired`

Purpose:

Tell the client that the relay/Authority cannot safely bridge its cursor.

Fields:

```
version
object_type = RESYNC_REQUIRED
root_epoch
service_id
scope_id
reason
head_generation OPTIONAL
head_digest OPTIONAL
issued_at
valid_until
```

Example reasons:

- `HISTORY_GAP`;
- `OBJECT_TOO_LARGE`;
- `SCOPE_MISMATCH`;
- `POLICY`;
- `FORK_RECOVERY`;
- `TRUST_REBOOTSTRAP`.

Receiving `ResyncRequired` MUST NOT modify DNS RR state.

The client performs ordinary DNS recovery and later new Snapshot admission.

## 12.5 `OperationalKeyAuthorization`

See Section 8.

---

# 13. Delta operations

The logical operation set is:

## 13.1 `ADD_RRSET`

Adds a previously absent explicit scope member RRset.

Must include:

```
owner
type
class
ttl
rdata[]
```

## 13.2 `REPLACE_RRSET`

Atomically replaces the full RRset for an existing positive member.

Partial RR mutations are intentionally not required in v0.1. Replacing the entire RRset simplifies deterministic state and atomicity.

## 13.3 `REMOVE_RRSET`

Changes an explicit member from POSITIVE to NODATA.

Must include the new negative caching metadata required by the Freshness state model.

## 13.4 `REMOVE_NAME`

Changes all explicit members of the owner name to NXDOMAIN atomically.

## 13.5 `CREATE_NAME_STATE`

Recreates a previously NXDOMAIN owner under a newer generation and establishes the explicit member states supplied by the operation.

## 13.6 Scope membership changes

Delta operations MUST NOT add arbitrary new query members to an existing scope.

Changing the member set requires a new `scope_id` and Snapshot admission.

---

# 14. Freshness lifecycle

## 14.1 States

The client tracks at least these conceptual states:

```
INACTIVE
DNS_BOOTSTRAP
ACTIVE_UNASSURED
ACTIVE_AUTHORIZED
RECOVERY_REQUIRED
```

### INACTIVE

No Freshness interest exists.

There is no cursor and no obligation to observe generations.

### DNS_BOOTSTRAP

Normal DNS is being used to obtain current reachability and, when available, DNSSEC Freshness discovery.

### ACTIVE_UNASSURED

The client retains scope state/metadata but has no currently valid Freshness assertion authorizing its use as current Freshness state.

This state MUST NOT bypass normal DNS validity rules.

### ACTIVE_AUTHORIZED

The client has:

- trusted root/key material;
- an admitted scope state;
- a valid signed Snapshot/Checkpoint/Delta lease;
- no detected gap or fork.

### RECOVERY_REQUIRED

The Freshness path cannot safely continue.

The client returns to DNS.

## 14.2 Admission

Fresh admission occurs when:

1. normal DNS provides a usable service path;
2. Freshness capability is securely discovered;
3. a natural application request is made;
4. the client indicates Freshness support with no prior scope cursor;
5. the relay returns a valid signed Snapshot;
6. the Snapshot is verified and committed.

At that point the scope becomes ACTIVE_AUTHORIZED.

## 14.3 Active use

On a natural request the client sends its cursor.

The server/relay may return:

- no Freshness field;
- matching Checkpoint;
- applicable Delta;
- Snapshot only when explicit re-admission/resync is allowed;
- ResyncRequired.

## 14.4 Eviction

**[PoC-validated lifecycle rule]**

When a scope is evicted because it is no longer useful:

- Freshness interest ends;
- cursor state is deleted;
- missed generations after eviction are not errors;
- later reuse begins with cold DNS admission/current state;
- the client does not reconstruct intermediate historical versions.

## 14.5 Continuous interest and gaps

If interest remained active and the client receives evidence of a newer generation that cannot be bridged from its exact `(generation,digest)`, this is a recovery condition.

The client MUST NOT guess or skip intermediate state unless it receives a complete Snapshot explicitly authorized for resynchronization.

## 14.6 Lease expiration

When `valid_until` is reached:

- the scope ceases to be ACTIVE_AUTHORIZED;
- the protocol MUST NOT treat the old state as current merely because a former application endpoint remains reachable;
- normal DNS / existing Serve-Stale policy applies before the state is used as a current DNS answer.

An implementation MAY retain old endpoint information as an internal candidate according to separate application connection policies, but this protocol does not authorize stale application use after the Freshness lease has expired.

---

# 15. Cursor

## 15.1 Purpose

The cursor tells the service what exact Freshness state the client currently has.

It is not a subscription.

## 15.2 Cursor entry

A cursor entry contains:

```
root_epoch
scope_id
generation
state_digest
```

Optionally:

```
client_max_object_size
```

`service_id` need not be repeated per entry if the HTTP binding already identifies the service and the enclosing cursor object contains it.

## 15.3 Privacy

A cursor MUST contain only scopes belonging to the service receiving the request.

A client MUST NOT disclose its general DNS cache contents to unrelated services.

`scope_id` MUST NOT be per-client.

## 15.4 Bounded size

Clients MUST bound the total Freshness request-field size.

If too many active scopes exist, the client may omit lower-priority cursors. Omission simply means no Freshness maintenance for the omitted scope on that transaction.

No correctness dependency may exist on every cursor being sent on every request.

---

# 16. History and reconciliation

## 16.1 Bounded history

**[PoC-validated]**

The Authority may retain the latest `K` transitions per scope.

`K` is implementation/operator policy.

Server memory must scale primarily with:

```
number_of_scopes * bounded_history
```

not with client count.

## 16.2 Reconciliation

Given client cursor `(g,d)` and head `(G,D)`:

### Case A: exact match

```
g == G and d == D
```

Return Checkpoint when useful.

### Case B: same generation, different digest

```
g == G and d != D
```

Fork detected.

Return `ResyncRequired(FORK_RECOVERY)` or fail closed.

### Case C: client behind and bridge retained

Return one Delta or a bounded sequence/batched Delta that exactly chains from `(g,d)` to the current head.

### Case D: client behind but bridge unavailable

Return `ResyncRequired(HISTORY_GAP)`.

### Case E: client claims future generation

Do not accept the cursor as authoritative.

Return recovery/resync response or ignore Freshness.

## 16.3 No reconstruction requirement after eviction

An inactive client may jump from an old remembered historical version to the current Snapshot during new admission. Intermediate generations have no protocol significance unless an audit extension is separately defined.

---

# 17. Fork and split-brain handling

**[PoC-validated]**

A valid signature does not guarantee globally unique state if different authorized backends sign conflicting state.

Therefore generation must be bound to a state digest.

## 17.1 Fork condition

A fork exists if the client has:

```
(root_epoch, service_id, scope_id, generation = N, digest = A)
```

and receives a valid signed Authority object asserting:

```
same root_epoch
same service_id
same scope_id
same generation = N
digest = B
A != B
```

## 17.2 Required behavior

The client MUST:

- not overwrite local state with the conflicting object;
- enter recovery;
- re-resolve through DNS;
- require a new trusted Snapshot/current state.

The client MAY log/report the fork for diagnostics.

---

# 18. Natural-traffic requirement

## 18.1 Definition

A **natural application transaction** is traffic the application would have generated even if the Freshness protocol did not exist.

## 18.2 Opportunistic Mode requirement

The protocol may add Freshness metadata to a natural transaction.

It MUST NOT manufacture application transactions solely to preserve Freshness.

This requirement is part of the protocol's efficiency claim and prevents an implementation from disguising polling as "in-band."

---

# 19. DNSSEC discovery

## 19.1 Security requirement

Freshness trust MUST NOT be bootstrapped from unauthenticated DNS data in the DNSSEC profile.

The client must either:

- perform DNSSEC validation itself; or
- rely on a trusted validating resolver and trusted channel according to existing DNSSEC rules.

## 19.2 HTTPS/SVCB discovery

**[PoC-validated experimental mechanism; v0.1 design for standard form]**

For HTTPS services, Freshness capability is advertised using an HTTPS RR SvcParam.

During experimentation, a Private-Use SvcParamKey may be used.

A standards-track specification would request an IANA-assigned SvcParamKey.

The Freshness SvcParam SHOULD carry a compact deterministic binary discovery object containing:

```
protocol_version
service_id
admission_context
root_epoch
root_public_key / root_key_identifier
root_not_after
capability_flags
```

## 19.3 Mandatory behavior

The Freshness SvcParam MUST NOT be placed in the SVCB `mandatory` list in the backwards-compatible profile.

Legacy clients must be able to ignore it and still use the ServiceMode record.

## 19.4 DNSSEC states

### SECURE

Freshness capability may be trusted after successful validation.

### BOGUS

Freshness MUST NOT activate from that discovery result.

Normal DNS error/security policy continues to apply.

### INSECURE / unsigned

The client MUST NOT derive cryptographic Freshness authority from the SvcParam.

The client continues using conventional DNS/application behavior.

### DNSSEC replay window

DNSSEC authentication prevents forgery but does not make an older still-valid signed RRset impossible to replay.

For a client that has already persisted a higher `root_epoch`, a lower epoch is rejected.

For a brand-new client with no remembered epoch, replay resistance is bounded by normal DNSSEC validity properties, including TTL and RRSIG validity. Operators requiring rapid emergency trust replacement SHOULD use appropriately short DNS TTL/signature validity and Freshness root authorization lifetimes.

The Freshness protocol does not claim stronger cold-bootstrap freshness than the DNSSEC material on which it relies.

## 19.5 AliasMode and delegation

Clients follow normal SVCB/HTTPS AliasMode and ServiceMode processing.

Freshness trust is accepted only when the final capability-bearing record and the required delegation path are securely authenticated.

If alias/delegation behavior cannot be represented safely inside an already admitted scope, the client falls back to DNS rather than attempting an in-band topology rewrite.

---

# 20. HTTP secure carrier binding

## 20.1 Transport security

The HTTP binding requires authenticated HTTPS.

Plaintext HTTP is not an eligible Freshness carrier in v0.1.

## 20.2 HTTP versions

**[PoC-validated carrier feasibility, with profile caveats]**

The semantic binding is defined at HTTP field level and is intended to work over:

- HTTP/1.1;
- HTTP/2;
- HTTP/3.

The protocol does not define custom HTTP/2 or HTTP/3 frame types in v0.1.

The lab demonstrated three transport cases:

- **HTTP/1.1:** the earlier Piggyback proof carried a valid signed Freshness Delta on an already-established TLS/TCP keep-alive application connection, without another DNS query or transport connection. That proof used the earlier PoC object encoding, not the final Gate-13 COSE profile.
- **HTTP/2 (Gate 17):** TLS negotiated ALPN `h2`; application requests used streams `1`, `3`, and `5` on one TCP/TLS connection; the Gate-13 Delta (266-byte COSE object, SHA-256 `94f0882665abfa18913323a6776629f5087fee73710846273cee72e50b1cb92c`) arrived byte-identically in `DNS-Freshness-Object` on stream 3; the server accepted one TCP connection.
- **HTTP/3 (Gate 18):** QUIC/TLS negotiated ALPN `h3`; application requests used streams `0`, `4`, and `8` on one QUIC connection and one handshake; the same Gate-13 Delta arrived byte-identically on stream 4; the client's UDP source port remained unchanged throughout the test.

**Claim boundary:** Gates 17 and 18 used the experimental request value `DNS-Freshness: v=1;e=101`. They validate field carriage, connection reuse, response-object transport, and normal application behavior, but they do not yet constitute an end-to-end test of the final deterministic-CBOR request cursor. Likewise, the final Gate-13 COSE response profile has not been separately rerun over HTTP/1.1.

## 20.3 Request field

Working name:

```
DNS-Freshness
```

The request field is a Structured Field Byte Sequence containing a deterministic CBOR cursor bundle.

A client with no active scope may send a minimal support/admission offer.

## 20.4 Response field

Working name:

```
DNS-Freshness-Object
```

The response field is a Structured Field Byte Sequence containing a COSE_Sign1 Freshness object.

Field names are provisional and require IANA registration in a standards-track version.

## 20.5 Why Structured Fields

RFC 9651 provides strict parsing and a standard Byte Sequence representation for binary data.

Using a Byte Sequence avoids inventing another ad-hoc base64 grammar.

## 20.6 Intermediaries

HTTP permits new fields to be ignored by endpoints that do not understand them and generally requires proxies to forward unrecognized fields unless configured otherwise.

Therefore:

- Freshness fields are end-to-end metadata;
- they MUST NOT be listed as HTTP/1.1 `Connection` options;
- absence of a field is not a protocol failure;
- a proxy stripping the field causes degradation to ordinary DNS, not incorrect state.

## 20.7 HTTP caches

A cached HTTP response may replay an older still-valid signed Freshness object.

Correctness is preserved because:

- object signatures are verified;
- service/scope/root identifiers are checked;
- Deltas bind exact from-generation/from-digest;
- stale generations are rejected;
- same-generation different-digest forks are detected;
- `valid_until` is absolute and cannot be extended by replay.

A still-valid old Checkpoint may delay observation of a newer state until expiry. This is part of the explicit bounded-staleness model.

The protocol MUST NOT require `Cache-Control: no-store` on application content solely for Freshness, because doing so would destroy unrelated HTTP caching efficiency.

---

# 21. Object size and denial-of-service limits

## 21.1 Resource-bounded protocol requirement

**[PoC-validated architecture — Gate 15]**

The protocol MUST be implementable with finite per-message resource cost. Implementations MUST enforce limits both at the producer and consumer. A correctly signed object does not bypass resource policy.

## 21.2 Experimental Gate-15 profile

Gate 15 exercised the following profile:

```
MAX_COSE_BYTES    = 4096
MAX_OPERATIONS    = 64
MAX_CURSOR_SCOPES = 32
MAX_CBOR_DEPTH    = 32
```

For a 4096-byte decoded COSE ceiling, the tested textual Structured Field Byte Sequence ceiling was 5466 bytes including delimiters. These numbers are experimental starting points, not yet final standards-track constants.

## 21.3 Producer behavior

Before sending an in-band Delta, the producer MUST enforce operation-count and encoded-object-size limits.

If the required transition exceeds an in-band limit, the producer MUST return a small signed:

```
ResyncRequired(TOO_MANY_OPERATIONS)
```

or:

```
ResyncRequired(OBJECT_TOO_LARGE)
```

rather than fragmenting an unbounded update across application headers. Gate 15 demonstrated both transitions.

## 21.4 Consumer pre-parse limits

A receiver MUST enforce an outer encoded-object byte limit **before CBOR parsing and before cryptographic verification**.

Gate 15 supplied a malicious 1 MiB object and observed:

```
REJECT_OVERSIZE_PREPARSE
decode_calls = 0
verify_calls = 0
```

Thus the architecture can reject gross oversize input before parser allocation or signature work.

## 21.5 HTTP field pre-decode limit

The HTTPS binding MUST bound the textual Structured Field value before Base64 decoding. Gate 15 demonstrated oversize HTTP-field rejection with zero CBOR-decode and zero signature-verification work.

## 21.6 Semantic limits

A receiver MUST independently bound at least:

- number of cursor scopes;
- number of Delta operations;
- total RR/RDATA work;
- encoded object bytes;
- CBOR nesting depth;
- history traversal;
- cryptographic work per object.

Gate 15 demonstrated:

- exact acceptance at 64 operations and rejection at 65 even when the oversized semantic object was validly signed;
- exact acceptance at 32 cursor scopes and rejection at 33 before any per-scope lookup;
- rejection of excessive CBOR nesting before cryptographic verification;
- rejection of duplicate CBOR map keys;
- rejection of indefinite-length CBOR.

## 21.7 No partial mutation

Any resource-limit failure MUST leave DNS/Freshness state unchanged. Resource policy is part of validation and therefore precedes atomic commit.

## 21.8 Final numeric limits

The Internet-Draft may adjust the experimental 4096/64/32/32 profile based on H2/H3 interoperability and implementation data. The existence and enforcement order of finite limits is already an architectural invariant; only the numeric constants remain open.

# 22. Concurrency and reordering

HTTP/2 and HTTP/3 may have multiple concurrent streams.

Freshness objects can therefore arrive out of order.

Example:

```
response A: 100 -> 101
response B: 101 -> 102
```

If `101 -> 102` arrives while local state is still 100, the client MUST NOT apply it.

An implementation MAY maintain a small bounded reorder buffer, but is not required to.

The simplest conforming behavior is:

1. reject/defer the non-applicable Delta;
2. apply the exact matching Delta when received;
3. send the new cursor on a later natural request;
4. obtain the later transition again.

The digest chain preserves correctness without transport ordering assumptions.

---

# 23. Multi-path behavior

**[PoC-validated concept]**

A scope may provide multiple usable endpoints.

When one known endpoint fails but another eligible endpoint succeeds:

- the client MAY use the successful application path;
- it sends the same scope cursor;
- a valid Freshness object may reconcile the scope;
- a separate DNS lookup is not required solely because one cached endpoint failed.

If no known usable path works, normal DNS recovery occurs.

The client MUST still honor Freshness lease and trust validity. A dead-path fallback does not extend an expired lease.

---

# 24. Interaction with TTL

## 24.1 Ordinary bootstrap

Before Freshness admission, ordinary DNS TTL rules apply.

## 24.2 Active Freshness

A newly verified signed Snapshot, Delta, or Checkpoint is a new Authority-authorized freshness statement.

While its validity interval is active, the Freshness-managed state may remain usable according to this specification even if the TTL from the original DNS bootstrap would otherwise have expired.

This is conceptually similar to the existing DNS Push precedent in which TTL aging is suspended while a valid active update relationship exists, but the mechanism here is different: signed bounded-validity assertions replace a stateful subscription.

## 24.3 No indefinite suspension

Interest alone never suspends TTL forever.

Once the Freshness assertion expires:

- the client no longer has Freshness authorization to treat the state as current;
- conventional DNS/cache policy becomes authoritative again.

---

# 25. Freshness assertion timing

## 25.1 `issued_at`

The Authority time at which the object was produced.

## 25.2 `valid_until`

An absolute time after which the object MUST NOT authorize Freshness state.

It is not a sliding lifetime.

Receiving or replaying the same object again MUST NOT extend `valid_until`.

## 25.3 Clock requirements

Clients need a sufficiently correct clock to enforce signed validity times.

An Internet-Draft must define acceptable clock-error behavior and failure policy.

Implementations MUST fail conservatively when time validity cannot be established.

## 25.4 Authority publication

Checkpoints are shareable per scope.

The Authority SHOULD generate one signed Checkpoint per scope/time interval, not one per client.

This preserves server statelessness with respect to clients.

The internal Authority-to-relay distribution mechanism is outside the protocol.

---

# 26. Relay security model

The relay is allowed to:

- forward a current signed object;
- cache signed objects;
- choose to omit Freshness;
- fail;
- return an older still-valid object.

The relay is not allowed to successfully:

- modify signed scope state;
- invent a generation;
- change a digest;
- add/remove an RRset;
- create an authorized signing key;
- extend object expiry;
- cross one service/scope into another.

A malicious relay can cause:

- bounded staleness through replay;
- loss of Freshness optimization;
- DNS recovery;
- denial of service.

It cannot forge Authority state without key compromise.

---

# 27. DNSSEC emergency trust reset

## 27.1 Trigger

The operator increments `root_epoch` in DNSSEC-authenticated discovery.

## 27.2 Required client behavior

On a securely validated higher root epoch:

```
new_root_epoch > local_root_epoch
```

the client MUST:

- replace root trust;
- discard old Freshness key authorizations;
- invalidate old Freshness leases;
- invalidate all old-root scope generations and digests as Freshness-authoritative;
- perform DNS recovery;
- require new Snapshot admission.

## 27.3 Replay protection

A DNSSEC-authenticated lower `root_epoch` MUST NOT roll back a client that has persistently recorded a higher root epoch.

The persistence and reset behavior of this anti-rollback state must be specified carefully for device restore/factory-reset scenarios in the Internet-Draft.

## 27.4 Compromised lower key

Even if a compromised key signed:

```
key_sequence = 2^64-1
scope_generation = 2^64-1
arbitrary valid-looking state
```

a higher DNSSEC `root_epoch` still supersedes it.

This is the reason `root_epoch` and lower-level counters are separate namespaces.

---

# 28. Failure semantics

| Condition | Freshness action | DNS state action |
|---|---|---|
| No discovery | Disable Freshness | normal DNS |
| DNSSEC insecure | Do not trust Freshness key | normal DNS |
| DNSSEC bogus | Freshness unavailable; follow DNSSEC failure policy | no unauthenticated downgrade |
| Field stripped by proxy | No Freshness update | retain only while already valid; otherwise DNS |
| Signature invalid | Reject object | unchanged |
| Wrong service | Reject | unchanged |
| Wrong root epoch | apply root rules | possibly recover |
| Wrong scope | Reject / resync | unchanged |
| Same generation, different digest | Fork | DNS recovery |
| Missing history bridge | Resync | DNS recovery |
| Oversized update | Resync | DNS recovery |
| Partial body/field | Reject | unchanged |
| Operation invalid | Reject whole object | unchanged |
| `to_digest` mismatch | Reject whole object | unchanged |
| Lease expired | leave ACTIVE_AUTHORIZED | DNS/current normal policy |
| All cached paths dead | recovery | DNS |
| Evicted scope later reused | new admission | DNS current head |

---

# 29. Scope/view behavior

## 29.1 No client-invented geography

The client MUST NOT derive `scope_id` from country, network, or ECS data.

## 29.2 Authority-issued cohort

The Authority chooses scope assignment.

The DNS bootstrap additionally supplies an opaque DNSSEC-authenticated `admission_context`. This context constrains which first-admission Snapshot the client may accept. The application relay therefore cannot select an arbitrary valid scope from another Authority-defined view.

The scope can correspond to:

- a CDN response cohort;
- an ECS-derived response class;
- an Anycast/backend coherence domain;
- any other operator-defined grouping.

The meaning remains opaque to the client.

## 29.3 Network/view change

If the service determines that the client's old scope is no longer suitable, it SHOULD return `ResyncRequired(SCOPE_MISMATCH)`.

The client then uses DNS to obtain the current authoritative selection and performs new admission.

This prevents a stale scope from being silently reinterpreted as another view.

---

# 30. CNAME, DNAME, aliases, and delegation

v0.1 follows a conservative rule:

- Alias RRsets MAY be members of a Freshness Scope when the Authority explicitly includes them.
- Cross-zone alias/delegation changes that cannot be represented completely and safely inside the scope MUST trigger DNS recovery.
- Delegation NS/DS topology is not rewritten opportunistically in v0.1.
- Glue handling remains conventional DNS behavior.
- A Freshness scope MUST NOT claim authority over names/types outside its explicit signed member set.

This sacrifices some optimization in complicated namespace transitions in exchange for clear correctness.

---

# 31. Interaction with DNS Push

## 31.1 Complementary roles

Opportunistic Freshness and DNS Push solve overlapping but not identical problems.

### Opportunistic Freshness is favored when:

- application traffic already exists;
- a separate DNS session would be redundant;
- server-side per-client subscription state is undesirable;
- zero idle Freshness traffic is preferred.

### DNS Push is favored when:

- a change must reach the client while the application itself is silent;
- asynchronous notification latency is more important than maintaining an additional stateful DNS relationship.

## 31.2 Hybrid policy

A future implementation MAY use a policy such as:

```
natural application traffic active
    -> Opportunistic Freshness

application silent, immediate DNS change delivery required
    -> DNS Push subscription

application silent, no immediate requirement
    -> no Freshness traffic
```

## 31.3 v0.1 boundary

The base protocol does not define a new DSO carrier or modify RFC 8765 messages.

A future companion specification may define a common signed-object carrier over DSO so the same `(root_epoch, scope_id, generation, digest)` state model can be shared.

---

# 32. Privacy considerations

## 32.1 Cursor minimization

A request MUST reveal only Freshness information needed by the receiving service.

## 32.2 No global cache fingerprint

The protocol MUST NOT expose:

- unrelated DNS names;
- unrelated scope IDs;
- a complete client DNS cache;
- stable client identifiers.

## 32.3 Scope IDs

Operators SHOULD design scope IDs so many clients share one ID.

They MUST NOT encode:

- user account IDs;
- device IDs;
- exact IP addresses;
- stable cross-service identifiers.

## 32.4 Timing leakage

A service can already observe requests to itself.

The Freshness cursor additionally reveals the generation of that service's DNS state known by the client.

The Internet-Draft must discuss whether this can reveal:

- approximate last contact;
- network/view transitions;
- software support.

Short-lived or rotated opaque scope IDs may reduce correlation, but rotations must not create per-client uniqueness.

---

# 33. Security considerations

## 33.1 Forgery

Protected by COSE signature validation and DNSSEC trust bootstrap.

## 33.2 Replay

Protected by:

- absolute object expiry;
- root epoch;
- generation;
- state digest;
- exact Delta ancestry.

A valid older Checkpoint can still be replayed until expiry. This is an explicitly bounded replay window.

## 33.3 Fork

Detected by same generation + different digest.

## 33.4 Partial update

No state mutation before complete verification and atomic commit.

## 33.5 Key compromise

Operational-key compromise is bounded by key validity and root control.

Root compromise requires DNSSEC higher-root-epoch recovery.

## 33.6 Suppression

A relay can suppress Freshness objects.

The protocol cannot distinguish suppression from absence without another trusted communication path.

The maximum effect is bounded by validity times, after which DNS recovery is required.

## 33.7 Downgrade

Once a service has a persistently remembered secure root epoch, an unauthenticated response MUST NOT silently reset it.

The precise downgrade-persistence policy must account for legitimate DNSSEC removal, device resets, and service decommissioning in the Internet-Draft.

## 33.8 Resource exhaustion

See Section 21.

## 33.9 Cross-service replay

Every signed object contains `service_id`.

## 33.10 Cross-scope replay

Every state object contains `scope_id`.

## 33.11 Compromised application TLS endpoint

TLS endpoint compromise alone does not authorize DNS Freshness state unless the attacker also compromises an authorized Freshness key.

It can still suppress Freshness and attack the application itself; this protocol is not an application-layer compromise defense.

---

# 34. State machine

A simplified state machine:

```
                    ┌─────────────┐
                    │  INACTIVE   │
                    └──────┬──────┘
                           │ application needs service
                           ▼
                    ┌─────────────┐
                    │ DNS_BOOTSTRAP│
                    └──────┬──────┘
                           │ DNS path usable
                           │ + secure capability
                           │ + natural app request
                           ▼
                    ┌─────────────┐
               ┌───►│ SNAPSHOT    │
               │    │ VALIDATION  │
               │    └──────┬──────┘
               │           │ valid + atomic commit
               │           ▼
               │    ┌─────────────┐
               │    │   ACTIVE    │
               │    │   ASSURED   │
               │    └─────┬─┬─────┘
               │          │ │
               │          │ ├─ Checkpoint/Delta valid
               │          │ │        -> remain
               │          │
               │          ├─ eviction
               │          │        -> INACTIVE
               │          │
               │          └─ expiry/gap/fork/path failure
               │                   ▼
               │            ┌─────────────┐
               └────────────│  RECOVERY   │
                            └──────┬──────┘
                                   │ normal DNS
                                   └──────────────► DNS_BOOTSTRAP
```

A higher DNSSEC `root_epoch` can transition any Freshness state directly to recovery/new admission.

---

# 35. Example active flow

## 35.1 Cold start

```
Client                         DNS                    Service
  |                             |                       |
  |---- normal DNS ------------>|                       |
  |<--- A/AAAA/HTTPS + DNSSEC --|                       |
  |                                                     |
  |---- natural HTTPS request ------------------------->|
  |     DNS-Freshness: support-v1                       |
  |                                                     |
  |<--- normal app response + signed Snapshot ----------|
  |                                                     |
  | verify, atomically admit scope                      |
```

## 35.2 Unchanged state

```
Client                                               Service
  |                                                     |
  |---- natural request -------------------------------->|
  |     cursor(scope S, gen 100, digest A)              |
  |                                                     |
  |<--- normal response + Checkpoint 100/A -------------|
  |                                                     |
  | renew bounded Freshness authorization               |
```

No separate DNS transaction occurs.

## 35.3 Changed state

```
Client                                               Service
  |                                                     |
  |---- natural request -------------------------------->|
  |     cursor S / 100 / A                              |
  |                                                     |
  |<--- normal response + Delta ------------------------|
  |     100/A -> 101/B                                  |
  |                                                     |
  | verify entire object                                |
  | calculate B                                         |
  | atomic commit                                       |
```

---

# 36. Example recovery flow

```
Client has S / 100 / A

Service head = 120 / Z
retained history starts at 112

Client request cursor 100/A
        |
        v
server cannot bridge
        |
        v
signed ResyncRequired(HISTORY_GAP)
        |
        v
normal DNS
        |
        v
new natural app connection
        |
        v
signed current Snapshot
        |
        v
new admission at 120/Z
```

The protocol does not reconstruct 101-119.

---

# 37. PoC evidence matrix

The following evidence comes from the DNS Freshness Lab and is not a claim of Internet-scale production deployment.

## 37.1 Functional state/security gates

**[PoC-validated]**

Demonstrated:

- DNS bootstrap and recovery;
- active/cold lifecycle;
- monotonic generation handling;
- wrong view/scope rejection;
- signed multi-RR transactional update;
- replay rejection;
- tamper rejection;
- fake Authority key rejection;
- wrong service/scope/old-state rejection;
- atomic state commit;
- crash/locking safety in the PoC;
- single and multi-path fallback behavior.

## 37.2 Existing application session delivery

**[PoC-validated]**

A signed update was delivered on the same established TLS/TCP application session without a separate DNS query and without a separate Freshness transport channel.

## 37.3 RTT experiments

**[PoC-validated controlled lab]**

At configured RTTs from 0 to 100 ms:

- classic DNS refresh and separate Push cost approximately one network RTT;
- in-band update total latency includes the application's normal RTT;
- marginal in-band Freshness processing remained roughly a few tenths of a millisecond in the measured implementation.

This is a controlled-lab property, not a universal Internet benchmark.

## 37.4 Idle behavior

**[PoC-validated]**

With update ready and five seconds of no application activity:

```
Freshness idle packets = 0
```

The next natural application request on the same TLS connection carried the update.

## 37.5 Wire cost

**[PoC-validated current unoptimized encoding]**

Measured:

- normal in-band transaction: 670 captured Ethernet bytes/transaction;
- update in-band transaction: 1052 bytes/transaction;
- marginal in-band update: +382 bytes, +0 packets;
- simple unsigned A DNS refresh: 178 bytes / 2 packets;
- separate persistent TLS push transaction: 1055 bytes.

The PoC used JSON/Base64 and should not be treated as final wire efficiency.

## 37.6 Stateless cursor

**[PoC-validated]**

A simple header experiment added approximately 26 bytes/request and zero packets.

The final v0.1 cursor contains more fields and will be larger; the 26-byte number MUST NOT be advertised as the final standardized cursor cost.

## 37.7 Bounded history

**[PoC-validated]**

100,000 simulated client cursor requests did not expand protocol history or per-client server state.

Old cursors outside the retained window caused resync.

## 37.8 Interrupted delivery

**[PoC-validated]**

25%, 75%, and approximately 99% delivery followed by connection reset did not advance state.

Only complete + verified delivery committed.

## 37.9 Signed Checkpoint

**[PoC-validated primitive]**

Signature, head mismatch, expiry, tampering, and bounded replay window were tested.

**Specification correction:** v0.1 describes the result as a bounded-validity Authority assertion, not absolute proof that no later change occurred.

## 37.10 Version scope

**[PoC-validated]**

Demonstrated:

- atomic A+AAAA update in one scope;
- independent HTTPS group unchanged;
- another view unchanged;
- valid signed cross-scope object rejected;
- 100,000 irrelevant changes produced zero client invalidations;
- cursor growth followed active scopes rather than total zone changes.

## 37.11 Key rotation

**[PoC-validated primitive]**

Demonstrated:

- signed key transition;
- fake key rejection;
- transition replay rejection;
- bounded overlap;
- retired-key rejection.

**Specification refinement:** final multi-scope key validity is time/root-epoch based rather than tied to one scope's generation.

## 37.12 DNSSEC bootstrap

**[PoC-validated]**

The client began without the Freshness public key.

Demonstrated chain:

```
DNSSEC trust anchor
 -> parent DNSKEY
 -> signed child DS
 -> DS-matching child KSK
 -> child DNSKEY set
 -> signed HTTPS/SVCB
 -> Freshness key
 -> signed Freshness Checkpoint
```

Tampering with the Freshness key while retaining the old DNSSEC signature was rejected.

## 37.13 Fork detection

**[PoC-validated]**

A second valid Authority-signed state with the same generation but different digest was detected as a fork and did not overwrite local state.

Wrong `from_digest` and wrong `to_digest` were rejected.

## 37.14 NODATA/NXDOMAIN

**[PoC-validated]**

Demonstrated:

- RRset removal -> NODATA;
- unrelated RRtype remains positive;
- whole-name removal -> NXDOMAIN;
- stale positive update cannot resurrect newer NXDOMAIN;
- newer authorized generation can recreate name;
- failed negative operation does not partially commit.

## 37.15 Emergency trust reset

**[PoC-validated — Gates 11 and 12]**

Gate 11 demonstrated that:

- a compromised Freshness key could create a cryptographically valid rogue successor;
- a DNSSEC-authenticated newer trust state replaced the compromised chain;
- old compromised keys lost authority;
- a stale but DNSSEC-valid lower trust state was rejected.

Specification work then identified a counter-jump weakness in the original scalar `trust_generation` model. Gate 12 implemented the hardened two-level model and demonstrated that:

- a compromised key could advance `key_sequence` to `2^63-1`;
- the compromised chain could also advance a scope generation to `2^63-1`;
- a higher DNSSEC-authenticated `root_epoch` still superseded both;
- the root reset removed all old Freshness keys;
- all old scope state was invalidated;
- fresh admission was required;
- lower counters safely restarted under the new root;
- old-root objects could not re-enter;
- a stale DNSSEC-authenticated lower `root_epoch` could not roll back the client.

This closes the specification-discovered counter-jump lockout flaw experimentally.

## 37.16 Deterministic CBOR / COSE wire profile

**[PoC-validated — Gate 13]**

Demonstrated:

- DNSSEC-canonical name/RDATA-based state identity;
- semantically identical DNS states produce identical canonical bytes and SHA-256 digest;
- actual DNS state changes alter the digest;
- deterministic CBOR payloads;
- COSE_Sign1 Tag 18;
- fully specified COSE Ed25519 algorithm id `-19`;
- modified payload rejection;
- rejection of correctly signed non-deterministic payload/protected encodings;
- rejection of deprecated polymorphic EdDSA id `-8`;
- RFC 9651 Structured Field Byte Sequence roundtrip;
- reproducible binary vectors.

Measured objects:

```
Checkpoint: 111 B CBOR, 204 B COSE, 274 B SF value
Delta:      173 B CBOR, 266 B COSE, 358 B SF value
```

Measured COSE size reduction versus the comparable JSON+raw-signature representation was 48.6% for Checkpoint and 54.1% for Delta.

## 37.17 DNSSEC-bound admission context

**[PoC-validated — Gate 14]**

Two legitimate DNSSEC-authenticated views shared the same service, `root_epoch`, and Freshness signing key but carried different opaque `admission_context` values and different valid scopes.

Demonstrated:

- a valid Authority signature alone could not bypass `admission_context`;
- a valid Snapshot from the other view was rejected;
- rewriting the context token broke the signature;
- a genuine DNSSEC context change invalidated the old scoped state;
- the context change required fresh signed admission;
- the old context could not re-enter;
- revalidating an unchanged context preserved working state.

## 37.18 Resource bounds and oversize behavior

**[PoC-validated — Gate 15]**

Using the experimental profile `4096 B COSE / 64 operations / 32 cursor scopes / depth 32`, Gate 15 demonstrated:

- normal bounded Delta acceptance;
- exact-boundary acceptance;
- producer fallback to small signed `ResyncRequired` on operation or byte-size overflow;
- 1 MiB input rejection before CBOR parse and before signature work;
- HTTP Structured Field oversize rejection before Base64 decode;
- independent client rejection of validly signed over-limit semantics;
- excessive nesting rejection before crypto;
- duplicate-key rejection;
- indefinite-length CBOR rejection;
- excess cursor-cardinality rejection with zero per-scope lookups.

The numeric profile remains experimental, but the resource-bounded architecture and enforcement ordering are PoC-validated.


## 37.19 Independent COSE implementation

**[PoC-validated — Gate 16, bounded claim]**

A second implementation was written in Go without reusing the Gate-13 Python encoder/decoder. It used:

- `fxamacker/cbor` for CBOR parsing/canonical encoding of the COSE `Sig_structure`;
- Go `crypto/ed25519` for signature verification;
- the published Gate-13 `checkpoint.cose`, `delta.cose`, and vector metadata.

Observed:

```
checkpoint.cose SHA-256 = 6d7fd17b85c798242044cce0aa0938163954adbd7a0ff396dd7905f7003ef45d
delta.cose      SHA-256 = 94f0882665abfa18913323a6776629f5087fee73710846273cee72e50b1cb92c
```

The Go implementation independently:

- parsed COSE_Sign1 Tag 18;
- interpreted the protected COSE algorithm as fully specified Ed25519 `-19`;
- verified the 111-byte Checkpoint payload and 173-byte Delta payload signatures with Go's Ed25519 implementation;
- matched the vector hashes and lengths;
- rejected a byte-tampered object because Ed25519 verification failed.

**Claim boundary:** Gate 16 proves cross-language/cross-library COSE framing and signature interoperability. It did not independently reimplement the complete DNS-state canonicalization algorithm, recompute `state_digest` from raw DNS RRsets, or enforce every Checkpoint/Delta semantic invariant. Those remain valid targets for a second full reference implementation.

## 37.20 HTTP/2 carrier interoperability

**[PoC-validated — Gate 17, lab stacks]**

Gate 17 used a real TLS connection with certificate and hostname validation and ALPN negotiation to HTTP/2.

Observed client state:

```
TLS_ALPN=h2
TCP_CONNECTS=1
STREAM_IDS=[1, 3, 5]
LOCAL_PORTS=[53530, 53530, 53530]
```

The first application response contained no Freshness object. After the server marked an update ready, the second natural application request on stream 3 received the Gate-13 Delta as an HTTP field. It decoded to exactly 266 bytes and SHA-256:

```
94f0882665abfa18913323a6776629f5087fee73710846273cee72e50b1cb92c
```

The third application request used stream 5 and did not receive a duplicate update. The server reported one accepted TCP connection and streams `1/3/5`.

Demonstrated:

- one TCP/TLS connection for three application exchanges;
- Freshness response object on the next natural H2 stream;
- no dedicated Freshness connection;
- normal application responses preserved before, during, and after delivery;
- Gate-13 COSE Delta preserved byte-for-byte.

**Claim boundary:** this is lab interoperability using the Python `h2` stack, not production CDN/browser/proxy interoperability. The request cursor used the experimental text value `v=1;e=101`, not the final CBOR cursor bundle.

## 37.21 HTTP/3 / QUIC carrier interoperability

**[PoC-validated — Gate 18, lab stacks]**

Gate 18 used `aioquic` with authenticated TLS/QUIC and ALPN `h3`.

Observed client state:

```
CONNECT_CALLS=1
CLIENT_HANDSHAKE_COUNT=1
H3_STREAM_IDS=[0, 4, 8]
UDP_LOCAL_PORTS=[47685, 47685, 47685, 47685]
```

Observed server state:

```
SERVER_PROTOCOL_COUNT=1
SERVER_HANDSHAKE_COUNT=1
H3_STREAM_IDS=[0, 4, 8]
FRESHNESS_STREAM_ID=4
```

The first application response contained no Freshness object. The second natural request on stream 4 received the same 266-byte Gate-13 Delta with SHA-256 `94f0882665abfa18913323a6776629f5087fee73710846273cee72e50b1cb92c`. The third request used stream 8 and received no duplicate.

Demonstrated:

- one QUIC connection and one handshake;
- normal H3 request streams `0/4/8`;
- Freshness response object on the next natural H3 request/response stream;
- no dedicated second QUIC connection or Freshness handshake;
- normal application semantics preserved;
- Gate-13 COSE Delta preserved byte-for-byte.

**Claim boundary:** this is lab interoperability using `aioquic`, not production browser/CDN/QUIC-stack interoperability. Connection migration, 0-RTT, multipath, real middleboxes, concurrent request reordering, and the final CBOR request cursor were not exercised by Gate 18.

# 38. What has NOT yet been proven

The project has not yet demonstrated:

- Internet-scale deployment;
- browser integration;
- operating-system resolver integration;
- BIND/Unbound/PowerDNS integration;
- real CDN control-plane integration;
- widespread proxy/WAF field survival and transformation behavior;
- IANA-assigned discovery/HTTP field identifiers;
- real DNSSEC root-chain operation outside the isolated lab hierarchy;
- millions of live concurrent clients;
- formal verification of the full state machine;
- a **second full semantic implementation** that independently recomputes DNS-state canonicalization/digests and enforces all Snapshot/Checkpoint/Delta rules;
- end-to-end use of the **final deterministic-CBOR request cursor** over H1/H2/H3 (Gates 17/18 used `v=1;e=101` as an experimental request value);
- a rerun of the final Gate-13 COSE response profile specifically over HTTP/1.1 (the H1 Piggyback proof used the earlier signed PoC encoding);
- concurrent H2/H3 stream reordering behavior for competing Freshness objects;
- QUIC connection migration, 0-RTT, or heterogeneous QUIC implementations;
- operationally optimal final numeric resource limits;
- long-duration clock-skew/lease behavior across heterogeneous systems;
- long-lived production H2/H3 connections through real reverse proxies/CDNs/load balancers.

The following are **no longer unproven architecture/interoperability claims** after Gates 12–18:

- hardened `root_epoch` precedence and old-state invalidation;
- deterministic CBOR/COSE wire-object feasibility and measured sizes;
- DNSSEC-bound `admission_context`;
- bounded-resource/oversize behavior;
- independent Go verification of Gate-13 COSE framing and Ed25519 signatures;
- lab HTTP/2 carriage of the Gate-13 COSE Delta on one existing TLS/TCP connection;
- lab HTTP/3 carriage of the Gate-13 COSE Delta on one existing QUIC connection.

The remaining work is primarily full semantic interoperability, integration, middlebox/deployment behavior, long-duration operations, and external review rather than discovery of an obvious internal protocol contradiction.

# 39. Comparative positioning

## 39.1 Conventional TTL/polling

Strengths:

- universal;
- simple;
- stateless at Authority with respect to clients.

Weakness addressed by this protocol:

- active clients still need a separate DNS transaction when cache validity requires refresh.

## 39.2 Serve-Stale

Strength:

- resilience when Authority refresh fails.

Not replaced:

- Serve-Stale is a failure-resilience policy, not an active change-delivery mechanism.

## 39.3 NOTIFY / IXFR

Strength:

- efficient authoritative/secondary synchronization.

Different layer:

- not designed as application-client cache Freshness over existing app traffic.

## 39.4 DNS Push

Strength:

- immediate asynchronous delivery while application traffic is absent.

Cost:

- active subscription and DSO session state;
- session/keepalive management.

This protocol's advantage:

- when natural application traffic already exists, Freshness can be carried without a separate DNS subscription/session.

## 39.5 ZONEVERSION

Strength:

- atomically identifies the zone version associated with an authoritative answer and aids diagnosis in multi-backend/Anycast systems.

This protocol extends the idea in a different direction:

- per-Freshness-Scope generation;
- explicit state digest;
- signed state transition;
- application-carried reconciliation.

It does not replace ZONEVERSION and may reference or align with its semantics where useful.

---

# 40. Why the design can be superior in its target region

The correct claim is conditional, not universal.

For a service with continuing natural application traffic, the protocol is designed to offer:

- no separate Freshness connection;
- no per-client subscription at the Freshness Authority;
- no Freshness keepalive while idle;
- no additional Freshness RTT on the natural request path;
- bounded update history;
- cryptographic relay independence;
- DNS fallback;
- asynchronous Push remaining available as a separate option when actually needed.

The protocol is **not** superior to Push when the application is silent and an update must arrive immediately.

A credible standards claim is therefore:

> Opportunistic In-Band DNS Freshness is intended to be a lower-state, lower-transaction freshness mechanism for active services, complementary to asynchronous DNS Push rather than a universal replacement for it.

---

# 41. Implementation invariants

A conforming implementation should be reviewable against the following invariants.

1. **No partial commit.**
2. **No unsigned state mutation.**
3. **No cross-service mutation.**
4. **No cross-scope mutation.**
5. **No first-admission Snapshot outside the DNSSEC-authenticated `admission_context`.**
6. **No generation-only identity.**
7. **No implicit scope-member inference.**
8. **No per-client Authority subscription state in Opportunistic Mode.**
9. **No synthetic Freshness traffic while idle in Opportunistic Mode.**
10. **No unlimited history.**
11. **No unlimited object size.**
12. **No lower-level counter can override a higher DNSSEC root epoch.**
13. **Emergency root reset invalidates prior-root Freshness state.**
14. **Eviction terminates interest; later version gaps are not errors.**
15. **Active-interest unbridgeable gaps require recovery.**
16. **Expired lease is not silently extended by endpoint reachability.**
17. **Freshness cursor leaks only service-local scope state.**
18. **Unknown/stripped HTTP extension degrades safely to DNS.**
19. **A relay without an Authority key cannot forge DNS state.**
20. **A relay cannot steer first admission into another valid view/scope.**

---

# 42. Proposed implementation constants and tested experimental profile

The following values are current v0.1 engineering choices or Gate-tested profile values. They are not yet IANA or standards-track commitments unless stated otherwise.

Core identifiers/crypto:

- `service_id`: 16 bytes;
- `scope_id`: 16 bytes;
- `state_digest`: SHA-256, 32 bytes;
- `generation`: uint64;
- `root_epoch`: uint64;
- Ed25519 signature: 64 bytes;
- COSE Sign1 Tag 18;
- COSE Ed25519 algorithm id: `-19`;
- deterministic CBOR;
- HTTP Structured Field Byte Sequence carrier.

Gate-15 experimental resource profile:

- `MAX_COSE_BYTES = 4096`;
- `MAX_OPERATIONS = 64`;
- `MAX_CURSOR_SCOPES = 32`;
- `MAX_CBOR_DEPTH = 32`;
- 4096 decoded COSE bytes correspond to a tested maximum Structured Field value of 5466 bytes including delimiters.

Gate-13 measured common-object sizes:

- Checkpoint: 111 B payload / 204 B COSE / 274 B SF value;
- Delta: 173 B payload / 266 B COSE / 358 B SF value.

Exact lease defaults, clock-skew tolerance, final maximum object size, final operation/cursor limits, and any digest-agility mechanism require interoperability and operational measurements before standards-track freezing.

# 43. IANA work expected for an Internet-Draft

A standards-track proposal is expected to request at least:

1. an SVCB/HTTPS SvcParamKey for Freshness discovery;
2. HTTP Field Name registrations for the request cursor and response object;
3. a registry or version space for Freshness object types if extension is expected;
4. a registry for Delta operation codes if not fully closed;
5. possibly media/content identifiers for COSE/CBOR object typing.

Private-use SvcParam values are suitable only for experiments.

---

# 44. Internet-Draft decomposition

A practical IETF submission may be clearer as two documents.

## Draft A — Core

Working title:

**Opportunistic DNS Freshness: Architecture and Signed State Model**

Contains:

- scope;
- state model;
- digest;
- lifecycle;
- snapshots/checkpoints/deltas;
- trust;
- DNSSEC bootstrap;
- recovery;
- security/privacy.

## Draft B — HTTPS Binding

Working title:

**HTTPS Carrier Binding for Opportunistic DNS Freshness**

Contains:

- HTTPS/SVCB discovery;
- HTTP Structured Fields;
- H1/H2/H3 behavior;
- limits;
- intermediary/cache behavior.

This separation keeps the core transport-independent and permits future non-HTTP carrier bindings without rewriting the DNS state model.

---

# 45. Next work after the local Gate freeze

The exploratory local PoC is frozen through **Gate 18**. No additional local gate should be added merely to accumulate PASS results. Further tests should target a specific remaining claim boundary or a defect discovered during drafting/review.

None of the following is a prerequisite for writing Internet-Draft v00; they are explicit interoperability and deployment work items that should accompany or follow v00.

## 45.1 Second full semantic implementation

Gate 16 independently verified COSE framing/signatures, but a second implementation should go further and independently implement:

- DNS canonical state construction from RRsets;
- `state_digest` recomputation;
- Snapshot admission rules;
- Checkpoint lease validation;
- Delta digest chaining and atomic operations;
- `root_epoch` / key rotation / reset behavior;
- negative DNS state semantics;
- resource limits.

The strongest interoperability milestone will be two implementations that exchange objects without sharing serialization/state-machine code.

## 45.2 Final request-cursor carrier profile

Before claiming the final H1/H2/H3 binding as fully exercised, run the final deterministic-CBOR Structured Field cursor rather than the Gate-17/18 experimental text cursor. This is a narrow binding-completeness test, not a new architecture gate.

Similarly, if the whitepaper wants to claim the exact final COSE/SF object over all three HTTP versions, rerun the Gate-13 response object over HTTP/1.1 rather than relying on the earlier JSON-era H1 Piggyback proof.

## 45.3 Real intermediary integration

Test at least representative:

- reverse proxies;
- CDN/load-balancer paths;
- WAF/header policies;
- HTTP/2 and HTTP/3 stacks from vendors other than the lab libraries.

The key questions are extension-field survival, size constraints, caching interactions, and safe degradation when fields are stripped.

## 45.4 Resolver/server integration prototype

Integrate the core state machine with at least one real resolver or DNS library path and one real application stack. This is not required to justify v00, but it materially strengthens later standards discussion.

## 45.5 Long-duration operational tests

Before standards-track maturity, test:

- clock skew;
- key/lease expiry across restarts;
- persisted highest `root_epoch`;
- repeated view/context changes;
- long-lived H2/H3 connections;
- realistic CDN/proxy chains;
- QUIC migration/0-RTT only if the binding intends to rely on them.

# 46. Whitepaper claims that are safe

The whitepaper may state, with appropriate experimental qualification:

- A controlled PoC demonstrated signed DNS state updates transported on existing application sessions.
- The PoC generated zero Freshness packets during an idle interval.
- In the tested active-path conditions, the in-band mechanism avoided a separate DNS/Push round trip.
- Protocol history remained bounded under 100,000 simulated client cursors without per-client subscription state.
- Partial delivery did not partially commit.
- DNSSEC bootstrap, hardened DNSSEC `root_epoch` reset, fork detection, negative DNS state, and DNSSEC-bound admission-context behavior were demonstrated.
- The architecture retains conventional DNS as bootstrap and recovery.
- Deterministic CBOR + COSE_Sign1/Ed25519 wire objects were generated and verified with reproducible binary vectors; measured Checkpoint and Delta COSE sizes were 204 B and 266 B respectively.
- Resource limits can be enforced before parsing/crypto, and oversized producer output can degrade to a small signed `ResyncRequired`.
- A separate Go implementation independently parsed and verified the Python-generated Gate-13 COSE Checkpoint and Delta with Go's Ed25519 implementation and rejected tampering.
- In the lab, HTTP/2 carried the Gate-13 COSE Delta on one TLS/TCP connection across streams `1/3/5`, and HTTP/3 carried it on one QUIC connection across streams `0/4/8`, without a second Freshness connection/handshake.
- The approach is complementary to DNS Push, especially for active services.

The whitepaper should **not** claim:

- universal superiority over DNS Push;
- zero staleness;
- Internet-scale validation;
- final 26-byte standardized cursor cost;
- production-ready browser support;
- that a Checkpoint proves no newer state exists after its issuance;
- that the Gate-13 experimental integer labels or Gate-15 numeric limits are already final standards-track values;
- that Gate 16 constitutes a second complete semantic implementation of the protocol;
- that the final CBOR request cursor was exercised over H1/H2/H3;
- production browser/CDN/proxy H2/H3 interoperability.

---

# 47. Architecture freeze statement

Subject to the explicit v0.1 hardening recorded in this document, the architecture is frozen around these principles:

```
DNS/DNSSEC
    = bootstrap, root trust, recovery, emergency reset

Freshness Scope
    = immutable authority-defined coherence membership

State Identity
    = root_epoch + service_id + scope_id + generation + state_digest

Natural Application Traffic
    = preferred carrier while it already exists

Signed Snapshot
    = admission/full bounded state

Signed Checkpoint
    = bounded-validity head assertion

Signed Delta
    = exact digest-chained atomic transition

ResyncRequired
    = fail-safe escape to DNS

Eviction
    = ends interest; later use is new admission

Admission Context
    = DNSSEC-authenticated opaque view binding; context change invalidates old scoped state

Resource Profile
    = finite object/operation/cursor/depth limits; oversize -> signed ResyncRequired or reject

Idle
    = zero protocol-generated Freshness traffic

Push
    = complementary option for asynchronous delivery during silence

Wire Interop
    = Gate-13 COSE objects independently verified by a Go implementation

HTTP Carrier Evidence
    = H1 semantic piggyback + Gate-13 COSE over real H2 and H3 lab connections
```

No new mechanism should be added unless it solves a concrete correctness, security, interoperability, or deployability problem that cannot be handled by these primitives.


## 47.1 Evidence-freeze qualification

The local PoC freeze is **not** a declaration that the protocol is an Internet Standard or production-ready. It means that the current architecture has survived the deliberately selected local falsification tests through Gate 18 and that no further local test is justified without a concrete unresolved claim.

The separate **Evidence Freeze v0.1** is the authoritative claim ledger for what each Gate did and did not demonstrate. If this specification and the Evidence Freeze ever conflict about experimental evidence, the narrower claim in the Evidence Freeze should be used until the discrepancy is resolved.

---

# 48. Normative reference set for draft preparation

The following RFCs are directly relevant to the Internet-Draft work:

- RFC 1034 / RFC 1035 — DNS concepts and protocol.
- RFC 1995 — IXFR.
- RFC 1996 — DNS NOTIFY.
- RFC 2308 — negative caching, NXDOMAIN/NODATA.
- RFC 4033 / RFC 4034 / RFC 4035 — DNSSEC architecture, canonical DNS representation, validation.
- RFC 5011 — trust-anchor rollover principles.
- RFC 7871 — EDNS Client Subnet and scoped caching.
- RFC 8198 — aggressive DNSSEC-validated negative caching.
- RFC 8490 — DNS Stateful Operations.
- RFC 8765 — DNS Push Notifications.
- RFC 8767 — Serve-Stale and modern TTL interpretation.
- RFC 8949 — CBOR and deterministic encoding.
- RFC 9052 — COSE structures.
- RFC 9053 — COSE algorithm framework/background.
- RFC 9864 — fully specified COSE Ed25519 (`alg=-19`); deprecates polymorphic `EdDSA=-8`.
- RFC 9110 — HTTP semantics and extension fields.
- RFC 9113 — HTTP/2.
- RFC 9114 — HTTP/3 and field section limits.
- RFC 9460 — SVCB/HTTPS service binding and extensibility.
- RFC 9651 — Structured Field Values for HTTP.
- RFC 9660 — DNS ZONEVERSION.

---

# 49. Final assessment at v0.1

The PoC has crossed the threshold from "interesting idea" to "coherent protocol candidate."

The architecture now has explicit answers for the principal failure classes:

- stale cache;
- missed update;
- inactive/evicted interest;
- path failure;
- multi-path service;
- partial transfer;
- tampering;
- replay;
- wrong service/scope;
- bounded history;
- split-brain;
- positive-to-negative DNS transitions;
- key rotation;
- DNSSEC bootstrap;
- compromised-key recovery;
- untrusted relays;
- HTTP extension loss;
- lower-counter lockout attempts against emergency reset;
- DNS-view steering via a different valid signed scope;
- non-deterministic CBOR ambiguity;
- oversized-object/resource-exhaustion behavior;
- independent COSE framing/signature interoperability;
- HTTP/2 single-connection Freshness carriage;
- HTTP/3 single-connection Freshness carriage.

The strongest remaining risks are no longer obvious logical contradictions. They are:

- deployability;
- a second **full semantic** implementation;
- final request-cursor binding completeness across H1/H2/H3;
- control-plane operational cost;
- browser/OS integration;
- proxy/CDN/middlebox behavior;
- long-duration operational behavior;
- IETF architectural review.

That is the appropriate point to move from exploratory PoC work into specification, interoperability, and external review.

---

# Appendix A — Mental model for non-protocol specialists

Think of classic DNS like a printed road map with an expiry date.

You ask:

> "Where is service X?"

DNS gives an answer and says:

> "You may trust this map for N seconds."

When N seconds expire, you normally ask DNS again.

DNS Push is closer to subscribing to a live traffic-control radio channel:

> "Keep this channel open and tell me whenever this road changes."

That gives fast updates, but both sides must maintain the subscription/channel.

Opportunistic Freshness says:

> "I am already talking to the destination. While that conversation is happening anyway, let a cryptographically trusted Authority attach the latest road-map version or changed route to that traffic."

If nobody is talking, the protocol creates no traffic.

If the map becomes too old, the update chain breaks, trust expires, or no known destination works, the client asks DNS again.

The important security separation is:

```
Application server:
    can carry the sealed envelope

DNS/Freshness Authority:
    signs what is inside the envelope

Client:
    opens and verifies the seal before changing its map
```

The server carrying the envelope cannot rewrite the DNS instructions without invalidating the signature.

The digest is the map's fingerprint.

The generation is the map's sequence number.

Using both means two servers cannot safely claim:

> "This is version 101"

while silently giving two different maps. If the fingerprints differ, the client sees a fork and returns to DNS.

The root epoch is the emergency master-reset counter controlled through DNSSEC. A stolen lower-level key cannot pick a giant number and outrank it because the counters live in different namespaces.

---

# Appendix B — Compact decision register

| Decision | v0.1 |
|---|---|
| Replace DNS? | No |
| Bootstrap | DNS |
| Root trust | DNSSEC |
| Emergency trust reset | higher DNSSEC `root_epoch` |
| Active carrier | existing authenticated application traffic |
| Base idle traffic | none |
| Push | complementary, not required |
| Authority state per client | none |
| History | bounded per scope |
| Scope granularity | authority-defined coherence group |
| View binding | DNSSEC-authenticated opaque `admission_context`; Gate 14 validated wrong-view rejection and context-change re-admission |
| State identity | generation + SHA-256 digest, under root epoch |
| Positive DNS | supported |
| NODATA | supported |
| NXDOMAIN | supported |
| Partial update | never commits |
| Wire payload | deterministic CBOR; DNSSEC-canonical state hashing; Gate 13 vectors available |
| Signature container | COSE_Sign1 Tag 18 |
| Base signature | fully specified COSE Ed25519 `alg=-19` |
| HTTP syntax | Structured Field Byte Sequence |
| Oversized update | bounded profile; producer -> signed `ResyncRequired`, consumer pre-parse reject |
| Expired lease | no Freshness authority; normal DNS policy |
| Scope eviction | interest ends |
| Later reuse | new admission/current head |
| Cross-zone complex topology | DNS recovery |
| Universal immediate idle update | not a goal; use Push if required |

