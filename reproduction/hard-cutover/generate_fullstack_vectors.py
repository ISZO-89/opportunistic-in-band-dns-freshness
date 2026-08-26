#!/usr/bin/env python3

import hashlib
import ipaddress
import json
import time
from pathlib import Path

import cbor2
import dns.name

from cryptography.hazmat.primitives import serialization


PRIVATE = "/certs/authority-private.pem"
PUBLIC = "/certs/authority-public.pem"
OUT = Path("/work/vectors")

COSE_SIGN1_TAG = 18
COSE_HDR_ALG = 1
COSE_HDR_KID = 4
COSE_ALG_ED25519 = -19

PROTOCOL_VERSION = 1

DELTA = 2
SNAPSHOT = 3

ROOT_EPOCH = 1

SERVICE_ID = hashlib.sha256(
    b"service.test"
).digest()[:16]

SCOPE_ID = hashlib.sha256(
    b"scope-endpoint"
).digest()[:16]

ADMISSION_CONTEXT = b"native-fullstack-lab"

OWNER_WIRE = dns.name.from_text(
    "a.service.test."
).canonicalize().to_digestable()

TTL = 60

OLD_RDATA = ipaddress.IPv4Address(
    "172.18.0.61"
).packed

NEW_RDATA = ipaddress.IPv4Address(
    "172.18.0.12"
).packed


with open(PRIVATE, "rb") as f:
    private_key = serialization.load_pem_private_key(
        f.read(),
        password=None,
    )

with open(PUBLIC, "rb") as f:
    public_key = serialization.load_pem_public_key(
        f.read()
    )


def det(value):
    return cbor2.dumps(
        value,
        canonical=True,
    )


def spki(pub):
    return pub.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )


KEY_ID = hashlib.sha256(
    spki(public_key)
).digest()[:16]


def canonical_state(rdata):
    return {
        0: PROTOCOL_VERSION,
        1: ROOT_EPOCH,
        2: SERVICE_ID,
        3: SCOPE_ID,
        4: [
            [
                OWNER_WIRE,
                1,
                [
                    [
                        1,
                        1,
                        TTL,
                        [rdata],
                    ]
                ],
            ]
        ],
    }


STATE100_RAW = det(
    canonical_state(OLD_RDATA)
)

STATE101_RAW = det(
    canonical_state(NEW_RDATA)
)

DIGEST100 = hashlib.sha256(
    STATE100_RAW
).digest()

DIGEST101 = hashlib.sha256(
    STATE101_RAW
).digest()


def make_sign1(payload):
    payload_raw = det(payload)

    protected_raw = det(
        {
            COSE_HDR_ALG:
                COSE_ALG_ED25519,
            COSE_HDR_KID:
                KEY_ID,
        }
    )

    sig_structure = det(
        [
            "Signature1",
            protected_raw,
            b"",
            payload_raw,
        ]
    )

    signature = private_key.sign(
        sig_structure
    )

    return det(
        cbor2.CBORTag(
            COSE_SIGN1_TAG,
            [
                protected_raw,
                {},
                payload_raw,
                signature,
            ],
        )
    )


ISSUED_AT = int(time.time()) - 5
VALID_UNTIL = ISSUED_AT + (6 * 60 * 60)


snapshot = {
    0: PROTOCOL_VERSION,
    1: SNAPSHOT,
    2: ROOT_EPOCH,
    3: SERVICE_ID,
    4: SCOPE_ID,

    5: 100,
    6: DIGEST100,
    7: ISSUED_AT,
    8: VALID_UNTIL,
    9: KEY_ID,

    15: ADMISSION_CONTEXT,

    16: [
        [
            OWNER_WIRE,
            1,
            1,
        ]
    ],

    17: STATE100_RAW,
}


delta = {
    0: PROTOCOL_VERSION,
    1: DELTA,
    2: ROOT_EPOCH,
    3: SERVICE_ID,
    4: SCOPE_ID,

    7: ISSUED_AT,
    8: VALID_UNTIL,
    9: KEY_ID,

    10: 100,
    11: DIGEST100,
    12: 101,
    13: DIGEST101,

    14: [
        [
            1,
            OWNER_WIRE,
            1,
            1,
            TTL,
            [NEW_RDATA],
        ]
    ],
}


snapshot_cose = make_sign1(snapshot)
delta_cose = make_sign1(delta)

OUT.mkdir(
    parents=True,
    exist_ok=True,
)

(OUT / "fullstack-snapshot.cose").write_bytes(
    snapshot_cose
)

(OUT / "fullstack-delta.cose").write_bytes(
    delta_cose
)

meta = {
    "protocol_version": PROTOCOL_VERSION,
    "root_epoch": ROOT_EPOCH,
    "service_id": SERVICE_ID.hex(),
    "scope_id": SCOPE_ID.hex(),
    "admission_context":
        ADMISSION_CONTEXT.decode(),
    "key_id": KEY_ID.hex(),

    "generation_100": 100,
    "endpoint_100": "172.18.0.61",
    "digest_100": DIGEST100.hex(),

    "generation_101": 101,
    "endpoint_101": "172.18.0.12",
    "digest_101": DIGEST101.hex(),

    "issued_at": ISSUED_AT,
    "valid_until": VALID_UNTIL,

    "canonical_state_100_bytes":
        len(STATE100_RAW),
    "canonical_state_101_bytes":
        len(STATE101_RAW),

    "snapshot_cose_bytes":
        len(snapshot_cose),
    "delta_cose_bytes":
        len(delta_cose),

    "snapshot_sha256":
        hashlib.sha256(
            snapshot_cose
        ).hexdigest(),

    "delta_sha256":
        hashlib.sha256(
            delta_cose
        ).hexdigest(),
}

(OUT / "fullstack-vectors.json").write_text(
    json.dumps(meta, indent=2) + "\n"
)

print("FULLSTACK_VECTORS=PASS")
print("STATE100_BYTES=" + str(len(STATE100_RAW)))
print("STATE101_BYTES=" + str(len(STATE101_RAW)))
print("SNAPSHOT_COSE_BYTES=" + str(len(snapshot_cose)))
print("DELTA_COSE_BYTES=" + str(len(delta_cose)))
print("DIGEST100=" + DIGEST100.hex())
print("DIGEST101=" + DIGEST101.hex())
