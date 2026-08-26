#!/usr/bin/env bash
set -Eeuo pipefail

REPRO="$(cd "$(dirname "$0")" && pwd)"
WORK="${1:-/tmp/dnsfresh-clean-bootstrap}"

for cmd in openssl dnssec-keygen dnssec-signzone named-checkzone python3; do
  command -v "$cmd" >/dev/null || {
    echo "MISSING_REQUIRED_TOOL=$cmd"
    exit 1
  }
done

rm -rf "$WORK"
mkdir -p "$WORK/certs" "$WORK/dns"

echo "=== 1. FRESH FRESHNESS AUTHORITY KEY ==="
"$REPRO/generate_test_authority_keys.sh" "$WORK/certs"

echo "=== 2. FRESH DISCOVERY ==="
ROOT_NOT_AFTER=$(( $(date +%s) + 604800 ))
sudo -n docker run --rm \
  -v "$REPRO:/work:ro" \
  -v "$WORK/certs:/certs:ro" \
  -v "$WORK/dns:/out" \
  dns-service-sync-realworld-h3:lab \
  python /work/generate_test_discovery.py \
  --public-key /certs/authority-public.pem \
  --root-not-after "$ROOT_NOT_AFTER" \
  --output-dir /out

ESCAPED=$(
  python3 -c 'import sys; d=open(sys.argv[1],"rb").read(); print("".join("\\%03d" % b for b in d))' \
    "$WORK/dns/discovery.bin"
)

echo "=== 3. UNSIGNED SERVICE.TEST ZONE ==="
SERIAL=$(date -u +%Y%m%d%H)
ZONE="$WORK/dns/db.service.test.unsigned"

printf "%s\n" \
  "\$ORIGIN service.test." \
  "\$TTL 60" \
  "@ IN SOA ns.service.test. hostmaster.service.test. (" \
  "  $SERIAL 60 60 60 60 )" \
  "@ IN NS ns.service.test." \
  "ns IN A 172.18.0.54" \
  "a IN A 172.18.0.61" \
  "b IN A 172.18.0.12" \
  "c IN A 172.18.0.13" \
  "a IN HTTPS 1 . key65400=\"$ESCAPED\"" \
  "_4433._https.a IN HTTPS 1 a.service.test. key65400=\"$ESCAPED\"" \
  > "$ZONE"

named-checkzone service.test. "$ZONE"

echo "=== 4. FRESH DNSSEC KEYS ==="
cd "$WORK/dns"

KSK=$(dnssec-keygen -q -a ED25519 -f KSK -n ZONE service.test.)
ZSK=$(dnssec-keygen -q -a ED25519 -n ZONE service.test.)

echo "KSK=$KSK"
echo "ZSK=$ZSK"

echo "=== 5. SIGN ZONE ==="
dnssec-signzone -S -o service.test. \
  -e +2592000 \
  -f db.service.test \
  db.service.test.unsigned >/dev/null

named-checkzone service.test. db.service.test

grep " DNSKEY 257 " "$KSK.key" > trust-anchor.key

echo "=== 6. FRESH DOH TLS ==="
openssl req -x509 -newkey rsa:2048 -nodes \
  -keyout doh.key \
  -out doh.crt \
  -days 30 \
  -subj "/CN=doh.service.test" \
  -addext "subjectAltName=DNS:doh.service.test,IP:172.18.0.55" \
  >/dev/null 2>&1

chmod 600 doh.key

openssl x509 -in doh.crt -pubkey -noout | \
  openssl pkey -pubin -outform DER 2>/dev/null | \
  openssl dgst -sha256 -binary | \
  base64 -w0 > doh_spki.txt
echo >> doh_spki.txt

echo "=== 7. VERIFY DISCOVERY IS EMBEDDED ==="
grep -q "key65400=" db.service.test
test "$(wc -c < discovery.bin)" = "88"

echo "CLEAN_DNSSEC_ZONE=PASS"
echo "CLEAN_DOH_TLS=PASS"
echo "CLEAN_DISCOVERY_EMBEDDED=PASS"
echo "ROOT_NOT_AFTER=$ROOT_NOT_AFTER"
echo "DOH_SPKI=$(cat doh_spki.txt)"
echo "WORK=$WORK"
