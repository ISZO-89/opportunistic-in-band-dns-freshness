import base64
import hashlib
import json
import struct
import time
from pathlib import Path

import cbor2

import dns.name
import dns.rdata
import dns.rdataclass
import dns.rdatatype

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization


PRIVATE = "/certs/authority-private.pem"
PUBLIC = "/certs/authority-public.pem"

OUT = Path("/vectors")


# ============================================================
# Standards constants
# ============================================================

COSE_SIGN1_TAG = 18

# COSE common header labels
COSE_HDR_ALG = 1
COSE_HDR_KID = 4

# RFC 9864:
# fully specified Ed25519 COSE algorithm.
COSE_ALG_ED25519 = -19

# Deprecated polymorphic RFC 9053 EdDSA identifier.
COSE_ALG_OLD_EDDSA = -8


with open(PRIVATE, "rb") as f:
    private_key = serialization.load_pem_private_key(
        f.read(),
        password=None
    )

with open(PUBLIC, "rb") as f:
    public_key = serialization.load_pem_public_key(
        f.read()
    )


def spki(pub):
    return pub.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )


# 128-bit key identifier is sufficient as a lookup hint.
# Trust still comes from the actual public key, not from KID.
KEY_ID = hashlib.sha256(spki(public_key)).digest()[:16]

SERVICE_ID = hashlib.sha256(
    b"service.test"
).digest()[:16]

SCOPE_ID = hashlib.sha256(
    b"scope-endpoint"
).digest()[:16]


# ============================================================
# Deterministic CBOR
# ============================================================

def det(obj):
    return cbor2.dumps(
        obj,
        canonical=True
    )


def nondet(obj):
    return cbor2.dumps(
        obj,
        canonical=False
    )


def strict_loads(raw):
    # Protocol decoder profile:
    #
    # - no indefinite-length containers
    # - no duplicate map keys
    # - bounded nesting depth
    #
    # Deterministic encoding is checked separately by
    # decode -> deterministic re-encode -> byte comparison.
    return cbor2.loads(
        raw,
        allow_indefinite=False,
        allow_duplicate_keys=False,
        max_depth=32
    )


def is_deterministic(raw):
    try:
        decoded = strict_loads(raw)
    except Exception:
        return False

    return det(decoded) == raw


# ============================================================
# Canonical DNS state
#
# This is intentionally built from DNS wire values, NOT text.
#
# owner:
#   Name.to_digestable()
#
# rdata:
#   Rdata.to_digestable()
#
# Both use DNSSEC canonical form.
# ============================================================

def canonical_dns_state(source):
    nodes = []

    for source_node in source["names"]:
        name = dns.name.from_text(
            source_node["name"]
        ).canonicalize()

        name_wire = name.to_digestable()

        if not source_node["exists"]:
            nodes.append(
                (
                    name,
                    [
                        name_wire,
                        0,       # NXDOMAIN / name absent
                        []
                    ]
                )
            )
            continue

        rrsets = []

        for source_rrset in source_node["rrsets"]:
            rdclass = dns.rdataclass.IN

            rdtype = dns.rdatatype.from_text(
                source_rrset["type"]
            )

            ttl = int(source_rrset["ttl"])

            rdatas = []

            for value in source_rrset["values"]:
                rdata = dns.rdata.from_text(
                    rdclass,
                    rdtype,
                    value,
                    origin=dns.name.root,
                    relativize=False
                )

                rdatas.append(
                    rdata.to_digestable(
                        origin=dns.name.root
                    )
                )

            # RR ordering must not affect state identity.
            rdatas.sort()

            rrsets.append([
                int(rdclass),
                int(rdtype),
                ttl,
                rdatas
            ])

        rrsets.sort(
            key=lambda x: (
                x[0],
                x[1]
            )
        )

        nodes.append(
            (
                name,
                [
                    name_wire,
                    1,          # name exists
                    rrsets
                ]
            )
        )

    # dnspython Name ordering is DNSSEC canonical ordering.
    nodes.sort(
        key=lambda x: x[0]
    )

    # Small integer labels are intentionally used for compact
    # binary representation.
    #
    # These are experimental v0.1 object labels, NOT IANA
    # allocations.
    return {
        1: SERVICE_ID,
        2: SCOPE_ID,
        3: [entry for _, entry in nodes]
    }


def state_digest(source):
    canonical = canonical_dns_state(source)
    raw = det(canonical)

    return (
        hashlib.sha256(raw).digest(),
        raw
    )


# ============================================================
# Two semantically IDENTICAL DNS states.
#
# Differences:
# - owner-name capitalization
# - input name ordering
# - RRset ordering
# - A RDATA ordering
# - embedded CNAME capitalization
#
# They MUST produce identical canonical bytes + digest.
# ============================================================

STATE_A = {
    "names": [
        {
            "name": "Alias.Service.Test.",
            "exists": True,
            "rrsets": [
                {
                    "type": "CNAME",
                    "ttl": 60,
                    "values": [
                        "TARGET.Service.Test."
                    ]
                }
            ]
        },
        {
            "name": "A.Service.Test.",
            "exists": True,
            "rrsets": [
                {
                    "type": "AAAA",
                    "ttl": 60,
                    "values": [
                        "2001:db8::10"
                    ]
                },
                {
                    "type": "A",
                    "ttl": 60,
                    "values": [
                        "192.0.2.11",
                        "192.0.2.10"
                    ]
                }
            ]
        },
        {
            "name": "gone.service.test.",
            "exists": False,
            "rrsets": []
        }
    ]
}


STATE_B = {
    "names": [
        {
            "name": "GONE.SERVICE.TEST.",
            "exists": False,
            "rrsets": []
        },
        {
            "name": "a.service.test.",
            "exists": True,
            "rrsets": [
                {
                    "type": "A",
                    "ttl": 60,
                    "values": [
                        "192.0.2.10",
                        "192.0.2.11"
                    ]
                },
                {
                    "type": "AAAA",
                    "ttl": 60,
                    "values": [
                        "2001:db8::10"
                    ]
                }
            ]
        },
        {
            "name": "alias.service.test.",
            "exists": True,
            "rrsets": [
                {
                    "type": "CNAME",
                    "ttl": 60,
                    "values": [
                        "target.service.test."
                    ]
                }
            ]
        }
    ]
}


STATE_CHANGED = json.loads(
    json.dumps(STATE_B)
)

for node in STATE_CHANGED["names"]:
    if node["name"].lower() == "a.service.test.":
        for rrset in node["rrsets"]:
            if rrset["type"] == "A":
                rrset["values"][0] = "192.0.2.99"


print("=== DNS STATE CANONICALIZATION ===")

digest_a, state_raw_a = state_digest(STATE_A)
digest_b, state_raw_b = state_digest(STATE_B)
digest_changed, state_raw_changed = state_digest(
    STATE_CHANGED
)

print(f"STATE_A_CBOR_BYTES={len(state_raw_a)}")
print(f"STATE_B_CBOR_BYTES={len(state_raw_b)}")
print(f"STATE_A_DIGEST={digest_a.hex()}")
print(f"STATE_B_DIGEST={digest_b.hex()}")

assert state_raw_a == state_raw_b
assert digest_a == digest_b

print(
    "SEMANTICALLY_IDENTICAL_DNS_STATE_HAS_IDENTICAL_CANONICAL_BYTES: PASS"
)
print(
    "SEMANTICALLY_IDENTICAL_DNS_STATE_HAS_IDENTICAL_DIGEST: PASS"
)

assert digest_changed != digest_a

print(
    "ACTUAL_DNS_STATE_CHANGE_CHANGES_DIGEST: PASS"
)

assert is_deterministic(state_raw_a)

print(
    "DNS_STATE_CBOR_IS_DETERMINISTIC: PASS"
)


# Save reusable state test vector.
(OUT / "dns-state.cbor").write_bytes(
    state_raw_a
)

(OUT / "dns-state.sha256").write_text(
    digest_a.hex() + "\n"
)


# ============================================================
# Freshness payload layouts
#
# Experimental compact integer labels.
#
# Common:
# 0 protocol version
# 1 object type
# 2 root_epoch
# 3 service_id
# 4 scope_id
#
# Checkpoint:
# 5 generation
# 6 state_digest
# 7 issued_at
# 8 valid_until
# 9 key_id
#
# Delta:
# 10 from_generation
# 11 from_digest
# 12 to_generation
# 13 to_digest
# 14 operations
# 9 key_id
# ============================================================

NOW = int(time.time())

checkpoint = {
    0: 1,
    1: 1,                 # CHECKPOINT
    2: 5,                 # root_epoch
    3: SERVICE_ID,
    4: SCOPE_ID,
    5: 101,
    6: digest_a,
    7: NOW,
    8: NOW + 10,
    9: KEY_ID
}


# Build canonical A RDATA for a realistic delta.
owner = dns.name.from_text(
    "a.service.test."
).canonicalize()

owner_wire = owner.to_digestable()

old_a = dns.rdata.from_text(
    dns.rdataclass.IN,
    dns.rdatatype.A,
    "192.0.2.10"
).to_digestable()

new_a = dns.rdata.from_text(
    dns.rdataclass.IN,
    dns.rdatatype.A,
    "192.0.2.20"
).to_digestable()


next_state = json.loads(
    json.dumps(STATE_B)
)

for node in next_state["names"]:
    if node["name"].lower() == "a.service.test.":
        for rrset in node["rrsets"]:
            if rrset["type"] == "A":
                rrset["values"] = [
                    "192.0.2.20",
                    "192.0.2.11"
                ]

next_digest, _ = state_digest(next_state)


delta = {
    0: 1,
    1: 2,                 # DELTA
    2: 5,
    3: SERVICE_ID,
    4: SCOPE_ID,

    10: 101,
    11: digest_a,

    12: 102,
    13: next_digest,

    # operation:
    # 1 = REPLACE_RRSET
    #
    # [op, owner, class, type, ttl, values]
    14: [
        [
            1,
            owner_wire,
            int(dns.rdataclass.IN),
            int(dns.rdatatype.A),
            60,
            [
                new_a,
                dns.rdata.from_text(
                    dns.rdataclass.IN,
                    dns.rdatatype.A,
                    "192.0.2.11"
                ).to_digestable()
            ]
        ]
    ],

    9: KEY_ID
}


checkpoint_payload = det(checkpoint)
delta_payload = det(delta)


assert is_deterministic(checkpoint_payload)
assert is_deterministic(delta_payload)

print()
print("=== DETERMINISTIC CBOR PAYLOADS ===")

print(
    f"CHECKPOINT_CBOR_BYTES={len(checkpoint_payload)}"
)
print(
    f"DELTA_CBOR_BYTES={len(delta_payload)}"
)

print("DETERMINISTIC_CBOR_PAYLOADS: PASS")


# ============================================================
# COSE_Sign1 implementation following RFC 9052.
#
# COSE_Sign1:
# tag 18 (
#   [
#     protected : bstr,
#     unprotected : map,
#     payload : bstr,
#     signature : bstr
#   ]
# )
#
# Sig_structure:
# [
#   "Signature1",
#   protected,
#   external_aad,
#   payload
# ]
# ============================================================

def make_sign1_from_bytes(
    payload_raw,
    alg=COSE_ALG_ED25519,
    protected_raw=None
):
    if protected_raw is None:
        protected_raw = det({
            COSE_HDR_ALG: alg,
            COSE_HDR_KID: KEY_ID
        })

    sig_structure = [
        "Signature1",
        protected_raw,
        b"",              # external_aad
        payload_raw
    ]

    to_be_signed = det(
        sig_structure
    )

    signature = private_key.sign(
        to_be_signed
    )

    cose = cbor2.CBORTag(
        COSE_SIGN1_TAG,
        [
            protected_raw,
            {},
            payload_raw,
            signature
        ]
    )

    return det(cose)


def reject(reason):
    return False, reason, None


def verify_sign1(raw):
    # v0.1 requires deterministic outer CBOR too.
    if not is_deterministic(raw):
        return reject(
            "REJECT_NON_DETERMINISTIC_COSE"
        )

    try:
        tagged = strict_loads(raw)
    except Exception:
        return reject(
            "REJECT_CBOR_PARSE"
        )

    if not isinstance(tagged, cbor2.CBORTag):
        return reject(
            "REJECT_MISSING_COSE_TAG"
        )

    if tagged.tag != COSE_SIGN1_TAG:
        return reject(
            "REJECT_COSE_TAG"
        )

    body = tagged.value

    if not isinstance(body, (list, tuple)) or len(body) != 4:
        try:
            body_len = len(body)
        except Exception:
            body_len = "NA"

        return reject(
            "REJECT_COSE_STRUCTURE:"
            f"type={type(body).__name__}:"
            f"len={body_len}"
        )

    protected_raw, unprotected, payload_raw, signature = body

    if not isinstance(protected_raw, bytes):
        return reject(
            "REJECT_PROTECTED_TYPE"
        )

    if not is_deterministic(protected_raw):
        return reject(
            "REJECT_NON_DETERMINISTIC_PROTECTED"
        )

    try:
        protected = strict_loads(
            protected_raw
        )
    except Exception:
        return reject(
            "REJECT_PROTECTED_PARSE"
        )

    if protected.get(COSE_HDR_ALG) != \
       COSE_ALG_ED25519:
        return reject(
            "REJECT_ALGORITHM"
        )

    if protected.get(COSE_HDR_KID) != KEY_ID:
        return reject(
            "REJECT_KID"
        )

    if unprotected != {}:
        return reject(
            "REJECT_UNEXPECTED_UNPROTECTED_HEADERS"
        )

    if not isinstance(payload_raw, bytes):
        return reject(
            "REJECT_PAYLOAD_TYPE"
        )

    # Critical v0.1 rule:
    # even a mathematically valid signature does not authorize
    # a payload encoded outside our deterministic profile.
    if not is_deterministic(payload_raw):
        return reject(
            "REJECT_NON_DETERMINISTIC_PAYLOAD"
        )

    try:
        payload = strict_loads(
            payload_raw
        )
    except Exception:
        return reject(
            "REJECT_PAYLOAD_PARSE"
        )

    if not isinstance(signature, bytes):
        return reject(
            "REJECT_SIGNATURE_TYPE"
        )

    if len(signature) != 64:
        return reject(
            "REJECT_SIGNATURE_LENGTH"
        )

    sig_structure = [
        "Signature1",
        protected_raw,
        b"",
        payload_raw
    ]

    to_be_signed = det(
        sig_structure
    )

    try:
        public_key.verify(
            signature,
            to_be_signed
        )
    except InvalidSignature:
        return reject(
            "REJECT_SIGNATURE"
        )

    return True, "ACCEPT", payload


# ============================================================
# Valid COSE objects
# ============================================================

checkpoint_cose = make_sign1_from_bytes(
    checkpoint_payload
)

delta_cose = make_sign1_from_bytes(
    delta_payload
)


print()
print("=== VALID COSE_SIGN1 ===")

ok, reason, decoded = verify_sign1(
    checkpoint_cose
)

print(
    f"CHECKPOINT_RESULT={reason}"
)

assert ok
assert decoded == checkpoint

print(
    "CHECKPOINT_COSE_SIGN1_VALID: PASS"
)


ok, reason, decoded = verify_sign1(
    delta_cose
)

print(
    f"DELTA_RESULT={reason}"
)

assert ok
assert decoded == delta

print(
    "DELTA_COSE_SIGN1_VALID: PASS"
)

print(
    "COSE_TAG_18: PASS"
)
print(
    "COSE_ED25519_ALG_MINUS_19: PASS"
)


# Save reusable binary vectors.
(OUT / "checkpoint.payload.cbor").write_bytes(
    checkpoint_payload
)

(OUT / "checkpoint.cose").write_bytes(
    checkpoint_cose
)

(OUT / "delta.payload.cbor").write_bytes(
    delta_payload
)

(OUT / "delta.cose").write_bytes(
    delta_cose
)


# ============================================================
# Attack 1:
# deterministically modify payload while retaining signature.
# ============================================================

print()
print("=== TAMPERED PAYLOAD ===")

tagged = cbor2.loads(
    checkpoint_cose
)

tampered_body = list(
    tagged.value
)

tampered_payload_obj = cbor2.loads(
    tampered_body[2]
)

tampered_payload_obj[5] = 999

tampered_body[2] = det(
    tampered_payload_obj
)

tampered_cose = det(
    cbor2.CBORTag(
        COSE_SIGN1_TAG,
        tampered_body
    )
)

ok, reason, _ = verify_sign1(
    tampered_cose
)

print(
    f"RESULT={reason}"
)

assert not ok
assert reason == "REJECT_SIGNATURE"

print(
    "MODIFIED_SIGNED_PAYLOAD_REJECTED: PASS"
)


# ============================================================
# Attack 2:
# semantically valid CBOR but NON-DETERMINISTIC map ordering.
#
# We SIGN it correctly.
#
# Therefore the crypto signature itself is valid, but our
# protocol profile MUST reject the encoding.
# ============================================================

print()
print("=== VALID SIGNATURE / NON-DETERMINISTIC PAYLOAD ===")

checkpoint_reverse = {}

for k in reversed(
    list(checkpoint.keys())
):
    checkpoint_reverse[k] = checkpoint[k]


noncanonical_payload = nondet(
    checkpoint_reverse
)

assert cbor2.loads(
    noncanonical_payload
) == checkpoint

assert noncanonical_payload != \
       checkpoint_payload

assert not is_deterministic(
    noncanonical_payload
)


signed_noncanonical = make_sign1_from_bytes(
    noncanonical_payload
)

ok, reason, _ = verify_sign1(
    signed_noncanonical
)

print(
    f"RESULT={reason}"
)

assert not ok
assert reason == \
       "REJECT_NON_DETERMINISTIC_PAYLOAD"

print(
    "SIGNED_NON_DETERMINISTIC_PAYLOAD_REJECTED: PASS"
)


# ============================================================
# Attack 3:
# non-deterministic PROTECTED header, correctly signed.
# ============================================================

print()
print("=== NON-DETERMINISTIC PROTECTED HEADER ===")

# Intentionally insert map keys in reverse canonical order.
protected_noncanonical = {
    COSE_HDR_KID: KEY_ID,
    COSE_HDR_ALG: COSE_ALG_ED25519
}

protected_noncanonical_raw = nondet(
    protected_noncanonical
)

protected_canonical_raw = det(
    protected_noncanonical
)

assert protected_noncanonical_raw != \
       protected_canonical_raw

signed_bad_protected = make_sign1_from_bytes(
    checkpoint_payload,
    protected_raw=protected_noncanonical_raw
)

ok, reason, _ = verify_sign1(
    signed_bad_protected
)

print(
    f"RESULT={reason}"
)

assert not ok
assert reason == \
       "REJECT_NON_DETERMINISTIC_PROTECTED"

print(
    "SIGNED_NON_DETERMINISTIC_PROTECTED_HEADER_REJECTED: PASS"
)


# ============================================================
# Attack / compatibility policy 4:
#
# Old EdDSA=-8 is mathematically usable with the same Ed25519
# key, but RFC 9864 deprecates the polymorphic identifier.
#
# We deliberately create a correctly signed -8 object.
# v0.1 MUST reject it and require fully specified -19.
# ============================================================

print()
print("=== DEPRECATED COSE EdDSA ALG -8 ===")

old_alg_cose = make_sign1_from_bytes(
    checkpoint_payload,
    alg=COSE_ALG_OLD_EDDSA
)

ok, reason, _ = verify_sign1(
    old_alg_cose
)

print(
    f"RESULT={reason}"
)

assert not ok
assert reason == "REJECT_ALGORITHM"

print(
    "DEPRECATED_POLYMORPHIC_EDDSA_MINUS_8_REJECTED: PASS"
)
print(
    "FULLY_SPECIFIED_ED25519_MINUS_19_REQUIRED: PASS"
)


# ============================================================
# Size comparison
#
# JSON here represents the SAME logical v0.1 checkpoint/delta,
# encoded in minified text form with binary fields represented
# as hex.
#
# It is a reference comparison, not a claim about every
# possible JSON schema.
# ============================================================

def jsonable_checkpoint():
    return {
        "version": 1,
        "type": "checkpoint",
        "root_epoch": 5,
        "service_id": SERVICE_ID.hex(),
        "scope_id": SCOPE_ID.hex(),
        "generation": 101,
        "state_digest": digest_a.hex(),
        "issued_at": NOW,
        "valid_until": NOW + 10,
        "key_id": KEY_ID.hex()
    }


def jsonable_delta():
    return {
        "version": 1,
        "type": "delta",
        "root_epoch": 5,
        "service_id": SERVICE_ID.hex(),
        "scope_id": SCOPE_ID.hex(),
        "from_generation": 101,
        "from_digest": digest_a.hex(),
        "to_generation": 102,
        "to_digest": next_digest.hex(),
        "operations": [
            {
                "op": "REPLACE_RRSET",
                "name": "a.service.test.",
                "class": "IN",
                "type": "A",
                "ttl": 60,
                "values": [
                    "192.0.2.20",
                    "192.0.2.11"
                ]
            }
        ],
        "key_id": KEY_ID.hex()
    }


json_checkpoint = json.dumps(
    jsonable_checkpoint(),
    sort_keys=True,
    separators=(",", ":")
).encode()

json_delta = json.dumps(
    jsonable_delta(),
    sort_keys=True,
    separators=(",", ":")
).encode()


# Old PoC model used detached 64-byte Ed25519 signature.
json_checkpoint_plus_sig = \
    len(json_checkpoint) + 64

json_delta_plus_sig = \
    len(json_delta) + 64


def structured_field_value(raw):
    return (
        b":" +
        base64.b64encode(raw) +
        b":"
    )


checkpoint_sf = structured_field_value(
    checkpoint_cose
)

delta_sf = structured_field_value(
    delta_cose
)


print()
print("=== WIRE SIZE RESULTS ===")

print(
    f"JSON_CHECKPOINT_PAYLOAD={len(json_checkpoint)}"
)
print(
    f"JSON_CHECKPOINT_PLUS_RAW_SIG={json_checkpoint_plus_sig}"
)

print(
    f"CBOR_CHECKPOINT_PAYLOAD={len(checkpoint_payload)}"
)
print(
    f"COSE_CHECKPOINT_TOTAL={len(checkpoint_cose)}"
)
print(
    f"COSE_CHECKPOINT_OVERHEAD={len(checkpoint_cose)-len(checkpoint_payload)}"
)
print(
    f"SF_CHECKPOINT_VALUE={len(checkpoint_sf)}"
)

print()

print(
    f"JSON_DELTA_PAYLOAD={len(json_delta)}"
)
print(
    f"JSON_DELTA_PLUS_RAW_SIG={json_delta_plus_sig}"
)

print(
    f"CBOR_DELTA_PAYLOAD={len(delta_payload)}"
)
print(
    f"COSE_DELTA_TOTAL={len(delta_cose)}"
)
print(
    f"COSE_DELTA_OVERHEAD={len(delta_cose)-len(delta_payload)}"
)
print(
    f"SF_DELTA_VALUE={len(delta_sf)}"
)


checkpoint_saving = (
    1 -
    len(checkpoint_cose) /
    json_checkpoint_plus_sig
) * 100

delta_saving = (
    1 -
    len(delta_cose) /
    json_delta_plus_sig
) * 100


print()

print(
    f"COSE_VS_JSON_CHECKPOINT_SAVING={checkpoint_saving:.1f}%"
)
print(
    f"COSE_VS_JSON_DELTA_SAVING={delta_saving:.1f}%"
)


# RFC 9651 textual Structured Field Byte Sequence:
# colon + padded base64 + colon.
assert checkpoint_sf.startswith(b":")
assert checkpoint_sf.endswith(b":")

decoded_sf = base64.b64decode(
    checkpoint_sf[1:-1]
)

assert decoded_sf == checkpoint_cose

print(
    "STRUCTURED_FIELD_BYTE_SEQUENCE_ROUNDTRIP: PASS"
)


# ============================================================
# Reproducibility:
# re-encode and re-sign identical payload.
#
# Ed25519 is deterministic, so the same key, protected header,
# payload and external AAD should produce identical signature
# and therefore identical complete COSE object.
# ============================================================

checkpoint_again = make_sign1_from_bytes(
    checkpoint_payload
)

delta_again = make_sign1_from_bytes(
    delta_payload
)

assert checkpoint_again == \
       checkpoint_cose

assert delta_again == \
       delta_cose

print(
    "IDENTICAL_INPUT_PRODUCES_IDENTICAL_COSE_SIGN1: PASS"
)


# ============================================================
# Write machine-readable results / hashes for future
# independent implementations.
# ============================================================

vectors = {
    "algorithm": "Ed25519",
    "cose_algorithm_id": -19,

    "dns_state_sha256":
        digest_a.hex(),

    "checkpoint_payload_sha256":
        hashlib.sha256(
            checkpoint_payload
        ).hexdigest(),

    "checkpoint_cose_sha256":
        hashlib.sha256(
            checkpoint_cose
        ).hexdigest(),

    "delta_payload_sha256":
        hashlib.sha256(
            delta_payload
        ).hexdigest(),

    "delta_cose_sha256":
        hashlib.sha256(
            delta_cose
        ).hexdigest(),

    "checkpoint_payload_bytes":
        len(checkpoint_payload),

    "checkpoint_cose_bytes":
        len(checkpoint_cose),

    "delta_payload_bytes":
        len(delta_payload),

    "delta_cose_bytes":
        len(delta_cose),

    "structured_field_checkpoint_value_bytes":
        len(checkpoint_sf),

    "structured_field_delta_value_bytes":
        len(delta_sf)
}


(OUT / "vectors.json").write_text(
    json.dumps(
        vectors,
        indent=2,
        sort_keys=True
    ) + "\n"
)


print()
print("=== GATE 13 RESULT ===")

print(
    "PASS: DNS STATE IDENTITY USES DNSSEC-CANONICAL NAME/RDATA FORMS"
)
print(
    "PASS: SEMANTICALLY IDENTICAL DNS STATES PRODUCE IDENTICAL DIGESTS"
)
print(
    "PASS: ACTUAL DNS STATE CHANGE CHANGES THE STATE DIGEST"
)
print(
    "PASS: FRESHNESS OBJECTS USE DETERMINISTIC CBOR"
)
print(
    "PASS: COSE_SIGN1 TAG 18 WITH FULLY-SPECIFIED Ed25519 ALG -19 VERIFIES"
)
print(
    "PASS: MODIFIED COSE PAYLOAD IS REJECTED"
)
print(
    "PASS: VALIDLY SIGNED NON-DETERMINISTIC CBOR IS REJECTED"
)
print(
    "PASS: NON-DETERMINISTIC PROTECTED HEADERS ARE REJECTED"
)
print(
    "PASS: DEPRECATED POLYMORPHIC EdDSA ALG -8 IS REJECTED"
)
print(
    "PASS: RFC9651 STRUCTURED-FIELD BYTE-SEQUENCE CARRIES THE COSE OBJECT"
)
print(
    "PASS: REPRODUCIBLE BINARY TEST VECTORS WERE GENERATED"
)
