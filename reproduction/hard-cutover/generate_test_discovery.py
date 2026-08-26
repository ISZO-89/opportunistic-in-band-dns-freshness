#!/usr/bin/env python3
import argparse
import hashlib
import time
from pathlib import Path

import cbor2
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

PROTOCOL_VERSION = 1
SERVICE_ID = hashlib.sha256(b"service.test").digest()[:16]
ADMISSION_CONTEXT = b"native-fullstack-lab"
ROOT_EPOCH = 1
CAPABILITY_FLAGS = 0
MAX_UNIX_SECONDS = 253402300799

def load_raw_public_key(args):
    if args.raw_public_key_hex:
        raw = bytes.fromhex(args.raw_public_key_hex)
    else:
        pem = Path(args.public_key).read_bytes()
        key = serialization.load_pem_public_key(pem)
        if not isinstance(key, Ed25519PublicKey):
            raise ValueError("public key is not Ed25519")
        raw = key.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
    if len(raw) != 32:
        raise ValueError("Ed25519 public key must be exactly 32 bytes")
    return raw

def main():
    p = argparse.ArgumentParser()
    group = p.add_mutually_exclusive_group(required=True)
    group.add_argument("--public-key")
    group.add_argument("--raw-public-key-hex")
    p.add_argument("--root-not-after", type=int, required=True)
    p.add_argument("--output-dir", required=True)
    args = p.parse_args()

    now = int(time.time())
    if args.root_not_after <= now:
        raise ValueError("root-not-after must be in the future")
    if args.root_not_after > MAX_UNIX_SECONDS:
        raise ValueError("root-not-after exceeds Chromium bound")

    raw_key = load_raw_public_key(args)

    discovery = {
        0: PROTOCOL_VERSION,
        1: SERVICE_ID,
        2: ADMISSION_CONTEXT,
        3: ROOT_EPOCH,
        4: raw_key,
        5: args.root_not_after,
        6: CAPABILITY_FLAGS,
    }

    encoded = cbor2.dumps(discovery, canonical=True)
    out = Path(args.output_dir)
    out.mkdir(parents=True, exist_ok=True)
    (out / "discovery.bin").write_bytes(encoded)
    (out / "discovery.hex").write_text(encoded.hex() + "\n")

    print("DISCOVERY_GENERATED=PASS")
    print("DISCOVERY_BYTES=" + str(len(encoded)))
    print("DISCOVERY_SHA256=" + hashlib.sha256(encoded).hexdigest())
    print("SERVICE_ID=" + SERVICE_ID.hex())
    print("ADMISSION_CONTEXT=" + ADMISSION_CONTEXT.decode())
    print("ROOT_EPOCH=" + str(ROOT_EPOCH))
    print("ROOT_PUBLIC_KEY=" + raw_key.hex())
    print("ROOT_NOT_AFTER=" + str(args.root_not_after))
    print("CAPABILITY_FLAGS=" + str(CAPABILITY_FLAGS))

if __name__ == "__main__":
    main()
