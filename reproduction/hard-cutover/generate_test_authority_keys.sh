#!/usr/bin/env bash
set -Eeuo pipefail

OUT="${1:-/tmp/dnsfresh-test-authority-keys}"

rm -rf "$OUT"
mkdir -p "$OUT"

openssl genpkey \
  -algorithm ED25519 \
  -out "$OUT/authority-private.pem"

openssl pkey \
  -in "$OUT/authority-private.pem" \
  -pubout \
  -out "$OUT/authority-public.pem"

chmod 600 "$OUT/authority-private.pem"
chmod 644 "$OUT/authority-public.pem"

echo "TEST_ONLY_AUTHORITY_KEYS_CREATED=PASS"
echo "PRIVATE=$OUT/authority-private.pem"
echo "PUBLIC=$OUT/authority-public.pem"

openssl pkey \
  -in "$OUT/authority-private.pem" \
  -check \
  -noout

openssl pkey \
  -pubin \
  -in "$OUT/authority-public.pem" \
  -text \
  -noout >/dev/null

echo "TEST_ONLY_AUTHORITY_KEYS_VALID=PASS"
