#!/usr/bin/env bash
set -Eeuo pipefail

BASE=/mnt/user/appdata/dns-service-sync-lab
RW="$BASE/benchmark/realworld-freshness"
FS="$BASE/benchmark/fullstack-discovery"
G18="$BASE/benchmark/gate18-http3"
CHROMIUM=/home/dnsadmin/chromium/src

NET=dns-service-sync-net

AUTH=dns-fullstack-auth
DOH=dns-fullstack-doh
H3=dns-fullstack-h3
BROWSER=dns-zero-dns-cutover-browser

AUTH_IP=172.18.0.54
DOH_IP=172.18.0.55
PRE_IP=172.18.0.61
POST_IP=172.18.0.12

H3_IMAGE=dns-service-sync-realworld-h3:lab
BROWSER_IMAGE=dns-service-sync-real-browser:lab

EXPECTED_H3_PIN='NdxVLANqQ92KAB0XLPUtbP/X5h/SQXbJd46oMo8EBcs='
EXPECTED_DOH_PIN='b20c5FWqendhxrtGyB/k65HeF/WGiVc1TeC+Zi+kJbY='

STAMP="${EVIDENCE_STAMP:-$(date -u +%Y%m%dT%H%M%SZ)}"

RESULTS="$BASE/benchmark/results/browser-zero-dns-cutover/$STAMP"
CONTROL="$RESULTS/control"

TRACE="$RESULTS/run.log"
BROWSER_LOG="$RESULTS/browser.log"
PRE_H3_LOG="$RESULTS/h3-pre-61.log"
POST_H3_LOG="$RESULTS/h3-post-12.log"
AUTH_PCAP="$RESULTS/authority-dns.pcap"
BROWSER_JS="$RESULTS/cutover_browser.js"

d() {
    sudo -n docker "$@"
}

sudo -n mkdir -p "$RESULTS" "$CONTROL"
sudo -n chown -R "$(id -u):$(id -g)" "$RESULTS"

exec > >(tee -a "$TRACE") 2>&1

CAP_ACTIVE=0
CAP_PID=""
AUTH_PID=""

wait_h3_ready() {
    local i

    for i in $(seq 1 100); do
        if d logs "$H3" 2>&1 |
            grep -q 'BROWSER_H3_SERVER_READY'
        then
            return 0
        fi
        sleep 0.1
    done

    d logs "$H3" 2>&1 || true
    return 1
}

restore_h3() {
    set +e

    d rm -f "$H3" >/dev/null 2>&1 || true

    d run -d \
        --name "$H3" \
        --network "$NET" \
        --ip "$PRE_IP" \
        -e NATIVE_PHASE=pre \
        -v "$RW:/work:ro" \
        -v "$G18/tls:/tls:ro" \
        "$H3_IMAGE" \
        python /work/native_browser_server.py \
        >/dev/null 2>&1

    set -e
}

stop_capture() {
    if [ "$CAP_ACTIVE" = "1" ]; then
        sudo -n nsenter -t "$AUTH_PID" -n \
            pkill -INT tcpdump \
            >/dev/null 2>&1 || true

        wait "$CAP_PID" 2>/dev/null || true

        CAP_ACTIVE=0
    fi
}

on_exit() {
    local rc=$?

    trap - EXIT
    set +e

    stop_capture

    d rm -f "$BROWSER" >/dev/null 2>&1 || true

    restore_h3

    exit "$rc"
}

trap on_exit EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

echo "============================================================"
echo "DNS FRESHNESS HARD ZERO-DNS CUTOVER EVIDENCE REPRODUCTION"
echo "UTC=$STAMP"
echo "============================================================"

echo
echo "=== 1. PRECHECK ==="

for c in "$AUTH" "$DOH" "$H3"; do
    test "$(d inspect -f '{{.State.Running}}' "$c")" = true || {
        echo "FAIL: $c not running"
        exit 1
    }
done

AUTH_ACTUAL=$(
    d inspect -f \
    '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' \
    "$AUTH"
)

DOH_ACTUAL=$(
    d inspect -f \
    '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' \
    "$DOH"
)

H3_ACTUAL=$(
    d inspect -f \
    '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' \
    "$H3"
)

test "$AUTH_ACTUAL" = "$AUTH_IP"
test "$DOH_ACTUAL" = "$DOH_IP"
test "$H3_ACTUAL" = "$PRE_IP"

grep -Eq \
    "^${PRE_IP}[[:space:]]+a\.service\.test$" \
    "$BASE/dns/hosts"

if d network inspect "$NET" \
    --format \
    '{{range .Containers}}{{.IPv4Address}}{{"\n"}}{{end}}' |
    grep -q "^${POST_IP}/"
then
    echo "FAIL: $POST_IP already occupied"
    exit 1
fi

echo "AUTHORITY=$AUTH_ACTUAL"
echo "DOH=$DOH_ACTUAL"
echo "H3_INITIAL_IP=$H3_ACTUAL"
echo "POST_IP_FREE=PASS"
echo "CUTOVER_PRECHECK=PASS"

echo
echo "=== 2. VERIFY TLS PINS ==="

H3_PIN=$(
    openssl x509 \
        -in "$G18/tls/server.pem" \
        -pubkey \
        -noout |
    openssl pkey \
        -pubin \
        -outform DER \
        2>/dev/null |
    openssl dgst \
        -sha256 \
        -binary |
    base64 -w0
)

DOH_PIN=$(
    openssl x509 \
        -in "$FS/doh.crt" \
        -pubkey \
        -noout |
    openssl pkey \
        -pubin \
        -outform DER \
        2>/dev/null |
    openssl dgst \
        -sha256 \
        -binary |
    base64 -w0
)

echo "H3_SPKI=$H3_PIN"
echo "DOH_SPKI=$DOH_PIN"

test "$H3_PIN" = "$EXPECTED_H3_PIN" || {
    echo "FAIL: H3 SPKI mismatch"
    exit 1
}

test "$DOH_PIN" = "$EXPECTED_DOH_PIN" || {
    echo "FAIL: DoH SPKI mismatch"
    exit 1
}

ALL_SPKI="$H3_PIN,$DOH_PIN"

echo "TLS_PINS=PASS"

echo
echo "=== 3. GENERATE FRESH FULLSTACK VECTORS ==="

d run --rm \
    -v "$RW:/work" \
    -v "$BASE/certs:/certs:ro" \
    "$H3_IMAGE" \
    python /work/generate_fullstack_vectors.py

NOW=$(date +%s)

python3 - "$RW/vectors/fullstack-vectors.json" "$NOW" <<'PYV'
import json
import sys

with open(sys.argv[1]) as f:
    d = json.load(f)

now = int(sys.argv[2])
issued = int(d["issued_at"])
valid = int(d["valid_until"])

print(f"VECTOR_NOW={now}")
print(f"VECTOR_ISSUED_AT={issued}")
print(f"VECTOR_VALID_UNTIL={valid}")
print(f"VECTOR_AGE_SECONDS={now-issued}")
print(f"VECTOR_REMAINING_SECONDS={valid-now}")
print(f"VECTOR_LEASE_SECONDS={valid-issued}")

assert issued <= now
assert now < valid
assert valid - issued == 21600
assert now - issued < 60

print("FRESH_VECTOR_TIME_WINDOW=PASS")
PYV

SNAPSHOT_SIZE=$(
    stat -c %s "$RW/vectors/fullstack-snapshot.cose"
)

DELTA_SIZE=$(
    stat -c %s "$RW/vectors/fullstack-delta.cose"
)

echo "SNAPSHOT_BYTES=$SNAPSHOT_SIZE"
echo "DELTA_BYTES=$DELTA_SIZE"

test "$SNAPSHOT_SIZE" = "325"
test "$DELTA_SIZE" = "273"

echo "FRESH_FULLSTACK_VECTORS=PASS"

echo
echo "=== 4. FREEZE RUN INPUTS ==="

{
    echo "utc=$STAMP"
    echo "authority_ip=$AUTH_IP"
    echo "doh_ip=$DOH_IP"
    echo "pre_endpoint=$PRE_IP"
    echo "post_endpoint=$POST_IP"
    echo "h3_image=$H3_IMAGE"
    echo "browser_image=$BROWSER_IMAGE"
    echo "h3_spki=$H3_PIN"
    echo "doh_spki=$DOH_PIN"
    echo "doh_mode=secure"
    echo \
      "doh_template=https://172.18.0.55:8443/dns-query{?dns}"
    echo \
      "chromium_commit=$(cd "$CHROMIUM" && git rev-parse HEAD)"
    echo \
      "chromium_version=$("$CHROMIUM/out/Freshness/chrome" --version)"
    echo \
      "h3_image_id=$(d image inspect "$H3_IMAGE" -f '{{.Id}}')"
    echo \
      "browser_image_id=$(d image inspect "$BROWSER_IMAGE" -f '{{.Id}}')"
    echo \
      "auth_image=$(d inspect -f '{{.Config.Image}}' "$AUTH")"
    echo \
      "doh_image=$(d inspect -f '{{.Config.Image}}' "$DOH")"
} > "$RESULTS/environment.txt"

d inspect "$AUTH" "$DOH" "$H3" \
    > "$RESULTS/containers-before.json"

d network inspect "$NET" \
    > "$RESULTS/network-before.json"

cp "$BASE/dns/hosts" \
    "$RESULTS/authority-hosts.txt"

cp "$RW/generate_fullstack_vectors.py" \
    "$RESULTS/"

cp "$RW/native_browser_server.py" \
    "$RESULTS/"

cp "$RW/native_browser_test.js" \
    "$RESULTS/native_browser_test-reference.js"

cp "$RW/vectors/fullstack-snapshot.cose" \
    "$RESULTS/"

cp "$RW/vectors/fullstack-delta.cose" \
    "$RESULTS/"

cp "$RW/vectors/fullstack-vectors.json" \
    "$RESULTS/"

for f in \
    Corefile \
    db.service.test \
    discovery.bin \
    discovery.hex \
    trust-anchor.key \
    unbound.conf \
    doh.crt \
    doh_spki.txt
do
    if [ -f "$FS/$f" ]; then
        cp "$FS/$f" "$RESULTS/fullstack-$f"
    fi
done

(
    cd "$CHROMIUM"
    git status --short \
        > "$RESULTS/chromium-status.txt"
    git diff --binary \
        > "$RESULTS/chromium.patch"
)

echo "INPUT_FREEZE=PASS"

echo
echo "=== 5. CREATE SECURE-DOH CUTOVER BROWSER HARNESS ==="

cat > "$BROWSER_JS" <<'JS'
const fs = require("fs");
const path = require("path");
const { chromium } = require("playwright");

const sleep = ms =>
  new Promise(resolve => setTimeout(resolve, ms));

async function waitFile(file, label) {
  for (let i = 0; i < 300; i++) {
    if (fs.existsSync(file)) {
      console.log(label + "=PASS");
      return;
    }

    await sleep(100);
  }

  throw new Error(label + "_TIMEOUT");
}

async function nav(page, url, label) {
  const t0 = performance.now();

  const response = await page.goto(url, {
    waitUntil: "domcontentloaded",
    timeout: 20000
  });

  const elapsed =
    performance.now() - t0;

  const status =
    response ? response.status() : "NONE";

  console.log(label + "_STATUS=" + status);
  console.log(
    label + "_MS=" + elapsed.toFixed(3)
  );

  if (status !== 200) {
    throw new Error(
      label + "_HTTP_STATUS_" + status
    );
  }
}

(async () => {
  const profile =
    "/tmp/dnsfresh-zero-dns-profile";

  const origin =
    "https://a.service.test:4433";

  fs.rmSync(
    profile,
    {
      recursive: true,
      force: true
    }
  );

  fs.mkdirSync(
    profile,
    {
      recursive: true
    }
  );

  const localState = {
    dns_over_https: {
      mode: "secure",
      templates:
        "https://172.18.0.55:8443/dns-query{?dns}"
    }
  };

  fs.writeFileSync(
    path.join(profile, "Local State"),
    JSON.stringify(localState)
  );

  console.log(
    "LOCAL_STATE_DOH_MODE=secure"
  );

  console.log(
    "LOCAL_STATE_DOH_TEMPLATE=" +
    "https://172.18.0.55:8443/dns-query{?dns}"
  );

  const context =
    await chromium.launchPersistentContext(
      profile,
      {
        executablePath:
          "/native-chromium/chrome",

        headless: true,

        args: [
          "--no-sandbox",
          "--enable-logging=stderr",
          "--log-level=0",
          "--enable-quic",
          "--no-proxy-server",
          "--ignore-certificate-errors",
          "--disable-background-networking",
          "--disable-component-update",
          "--disable-default-apps",
          "--disable-sync",
          "--no-first-run",
          "--no-default-browser-check",
          "--origin-to-force-quic-on=" +
            "a.service.test:4433",
          "--ignore-certificate-errors-spki-list=" +
            process.env.ALL_SPKI
        ]
      }
    );

  console.log(
    "BROWSER_ENGINE=Chromium"
  );

  const pages =
    context.pages();

  const page =
    pages.length
      ? pages[0]
      : await context.newPage();

  try {
    console.log(
      "=== REQUEST 1 / SNAPSHOT ==="
    );

    await nav(
      page,
      origin + "/app/1",
      "REQUEST1"
    );

    fs.writeFileSync(
      "/control/request1.done",
      "PASS\n"
    );

    console.log(
      "BROWSER_WAIT_AFTER_REQUEST1=PASS"
    );

    await waitFile(
      "/control/continue",
      "CONTROL_REQUEST2_RELEASED"
    );

    console.log(
      "=== REQUEST 2 / DELTA ==="
    );

    await nav(
      page,
      origin + "/app/2",
      "REQUEST2"
    );

    fs.writeFileSync(
      "/control/request2.done",
      "PASS\n"
    );

    console.log(
      "BROWSER_WAIT_AFTER_REQUEST2=PASS"
    );

    await waitFile(
      "/control/continue3",
      "CONTROL_REQUEST3_RELEASED"
    );

    console.log(
      "=== REQUEST 3 / HARD CUTOVER ==="
    );

    await nav(
      page,
      origin + "/app/3",
      "REQUEST3"
    );

    console.log(
      "BROWSER_ZERO_DNS_SEQUENCE=PASS"
    );
  } finally {
    await context.close();
  }
})().catch(err => {
  console.error(
    "BROWSER_TEST_FAIL=" +
    err.stack
  );

  process.exit(1);
});
JS

echo "BROWSER_HARNESS_CREATED=PASS"

echo
echo "=== 6. CLEAN PRE-CUTOVER H3 ON .61 ==="

d rm -f "$BROWSER" \
    >/dev/null 2>&1 || true

d rm -f "$H3" \
    >/dev/null 2>&1 || true

d run -d \
    --name "$H3" \
    --network "$NET" \
    --ip "$PRE_IP" \
    -e NATIVE_PHASE=pre \
    -v "$RW:/work:ro" \
    -v "$G18/tls:/tls:ro" \
    "$H3_IMAGE" \
    python /work/native_browser_server.py \
    >/dev/null

wait_h3_ready

echo "PRE_H3_61_READY=PASS"

echo
echo "=== 7. START ONE SECURE-DOH CHROMIUM PROCESS ==="

rm -f "$CONTROL"/*

d run -d \
    --name "$BROWSER" \
    --init \
    --ipc=host \
    --network "$NET" \
    --dns "$DOH_IP" \
    -e "ALL_SPKI=$ALL_SPKI" \
    -e "DEBUG=pw:browser" \
    -v "$CHROMIUM/out/Freshness:/native-chromium:ro" \
    -v "$RESULTS:/evidence:ro" \
    -v "$CONTROL:/control" \
    "$BROWSER_IMAGE" \
    node /evidence/cutover_browser.js \
    >/dev/null

echo "CHROMIUM_PROCESS_STARTED=PASS"

echo
echo "=== 8. WAIT REQUEST 1 / SNAPSHOT GEN100 ==="

for i in $(seq 1 300); do
    if [ -f "$CONTROL/request1.done" ]; then
        break
    fi

    if [ "$(d inspect -f '{{.State.Running}}' "$BROWSER")" != "true" ]; then
        d logs "$BROWSER" > "$BROWSER_LOG" 2>&1 || true
        tail -n 120 "$BROWSER_LOG"
        echo "FAIL: browser exited before request1"
        exit 1
    fi

    sleep 0.1
done

test -f "$CONTROL/request1.done"

d logs "$BROWSER" \
    > "$BROWSER_LOG" 2>&1

grep -q \
    'DNSFRESH_DOH_EFFECTIVE mode=2' \
    "$BROWSER_LOG"

grep -Eq \
    'DNSSEC_GATE host=a\.service\.test type=7.*secure=1.*ad=1.*authenticated=1' \
    "$BROWSER_LOG"

grep -q \
    'DISCOVERY_BOOTSTRAP=PASS HOST=a.service.test ROOT_EPOCH=1' \
    "$BROWSER_LOG"

grep -q \
    'SNAPSHOT_ADMITTED=PASS GEN=100 ENDPOINT=172.18.0.61 ROOT_EPOCH=1' \
    "$BROWSER_LOG"

echo "SECURE_DOH_DNSSEC_DISCOVERY=PASS"
echo "SNAPSHOT_GEN100=PASS"

touch "$CONTROL/continue"

echo
echo "=== 9. WAIT REQUEST 2 / DELTA GEN101 ==="

for i in $(seq 1 300); do
    if [ -f "$CONTROL/request2.done" ]; then
        break
    fi

    if [ "$(d inspect -f '{{.State.Running}}' "$BROWSER")" != "true" ]; then
        d logs "$BROWSER" > "$BROWSER_LOG" 2>&1 || true
        tail -n 120 "$BROWSER_LOG"
        echo "FAIL: browser exited before request2"
        exit 1
    fi

    sleep 0.1
done

test -f "$CONTROL/request2.done"

d logs "$BROWSER" \
    > "$BROWSER_LOG" 2>&1

d logs "$H3" \
    > "$PRE_H3_LOG" 2>&1

grep -q \
    'FROM_GENERATION_DIGEST=PASS GEN=100' \
    "$BROWSER_LOG"

grep -q \
    'REPLACE_RRSET=PASS' \
    "$BROWSER_LOG"

grep -q \
    'TO_DIGEST=PASS' \
    "$BROWSER_LOG"

grep -q \
    'COMMIT=PASS GEN=101 ENDPOINT=172.18.0.12 ROOT_EPOCH=1' \
    "$BROWSER_LOG"

APP1_PROTOCOL=$(
    sed -n \
      's/.*BROWSER_REQUEST protocol=\([0-9][0-9]*\) stream=0 path=\/app\/1.*/\1/p' \
      "$PRE_H3_LOG" |
    tail -n1
)

APP2_PROTOCOL=$(
    sed -n \
      's/.*BROWSER_REQUEST protocol=\([0-9][0-9]*\) stream=4 path=\/app\/2.*/\1/p' \
      "$PRE_H3_LOG" |
    tail -n1
)

test -n "$APP1_PROTOCOL"
test -n "$APP2_PROTOCOL"
test "$APP1_PROTOCOL" = "$APP2_PROTOCOL"

grep -Eq \
    "BROWSER_REQUEST protocol=${APP1_PROTOCOL} stream=0 path=/app/1 .*cursor_raw_bytes=23 .*cursor_scopes=0 .*cursor_gen=none" \
    "$PRE_H3_LOG"

grep -Eq \
    "FRESHNESS_SNAPSHOT_ATTACHED protocol=${APP1_PROTOCOL} stream=0 bytes=325" \
    "$PRE_H3_LOG"

grep -Eq \
    "BROWSER_REQUEST protocol=${APP2_PROTOCOL} stream=4 path=/app/2 .*cursor_raw_bytes=86 .*cursor_scopes=1 .*cursor_gen=100" \
    "$PRE_H3_LOG"

grep -Eq \
    "FRESHNESS_DELTA_ATTACHED protocol=${APP2_PROTOCOL} stream=4 bytes=273" \
    "$PRE_H3_LOG"

echo "APP1_PROTOCOL=$APP1_PROTOCOL"
echo "APP2_PROTOCOL=$APP2_PROTOCOL"
echo "GEN101_COMMITTED_BEFORE_CUTOVER=PASS"
echo "SNAPSHOT_DELTA_SAME_H3_CONNECTION=PASS"

echo
echo "=== 10. DISCARD DOH CACHE AFTER GEN101 COMMIT ==="

d restart "$DOH" \
    >/dev/null

for i in $(seq 1 100); do
    if [ "$(d inspect -f '{{.State.Running}}' "$DOH")" = "true" ]; then
        break
    fi

    sleep 0.1
done

test "$(d inspect -f '{{.State.Running}}' "$DOH")" = "true"

DOH_AFTER=$(
    d inspect -f \
    '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' \
    "$DOH"
)

test "$DOH_AFTER" = "$DOH_IP"

sleep 0.5

echo "DOH_CACHE_RESTART=PASS"

echo
echo "=== 11. START AUTHORITY DNS CAPTURE ==="

AUTH_PID=$(
    d inspect -f '{{.State.Pid}}' "$AUTH"
)

sudo -n nsenter \
    -t "$AUTH_PID" \
    -n \
    tcpdump \
    -ni any \
    -U \
    -w "$AUTH_PCAP" \
    port 53 \
    >"$RESULTS/authority-tcpdump.stdout" \
    2>"$RESULTS/authority-tcpdump.stderr" &

CAP_PID=$!
CAP_ACTIVE=1

sleep 0.5

kill -0 "$CAP_PID" || {
    echo "FAIL: authority tcpdump not alive"
    exit 1
}

echo "AUTHORITY_CAPTURE_RUNNING=PASS"

echo
echo "=== 12. HARD CUTOVER .61 -> .12 ==="

d rm -f "$H3" \
    >/dev/null

if d network inspect "$NET" \
    --format \
    '{{range .Containers}}{{.IPv4Address}}{{"\n"}}{{end}}' |
    grep -q "^${PRE_IP}/"
then
    echo "FAIL: old endpoint .61 still present"
    exit 1
fi

echo "OLD_ENDPOINT_172.18.0.61_REMOVED=PASS"

d run -d \
    --name "$H3" \
    --network "$NET" \
    --ip "$POST_IP" \
    -e NATIVE_PHASE=post \
    -v "$RW:/work:ro" \
    -v "$G18/tls:/tls:ro" \
    "$H3_IMAGE" \
    python /work/native_browser_server.py \
    >/dev/null

wait_h3_ready

POST_ACTUAL=$(
    d inspect -f \
    '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' \
    "$H3"
)

test "$POST_ACTUAL" = "$POST_IP"

d inspect "$H3" \
    > "$RESULTS/h3-post-container.json"

d network inspect "$NET" \
    > "$RESULTS/network-during-cutover.json"

echo "NEW_ENDPOINT_172.18.0.12_ACTIVE=PASS"

echo
echo "=== 13. RELEASE SAME CHROMIUM PROCESS FOR APP/3 ==="

touch "$CONTROL/continue3"

for i in $(seq 1 300); do
    if [ "$(d inspect -f '{{.State.Running}}' "$BROWSER")" != "true" ]; then
        break
    fi

    sleep 0.1
done

if [ "$(d inspect -f '{{.State.Running}}' "$BROWSER")" = "true" ]; then
    echo "FAIL: Chromium did not finish"
    exit 1
fi

BROWSER_EXIT=$(
    d inspect -f '{{.State.ExitCode}}' "$BROWSER"
)

d logs "$BROWSER" \
    > "$BROWSER_LOG" 2>&1

d logs "$H3" \
    > "$POST_H3_LOG" 2>&1

test "$BROWSER_EXIT" = "0" || {
    tail -n 150 "$BROWSER_LOG"
    echo "FAIL: Chromium exit=$BROWSER_EXIT"
    exit 1
}

grep -q \
    'REQUEST3_STATUS=200' \
    "$BROWSER_LOG"

grep -q \
    'BROWSER_ZERO_DNS_SEQUENCE=PASS' \
    "$BROWSER_LOG"

grep -Eq \
    'BROWSER_REQUEST protocol=[0-9]+ stream=0 path=/app/3 .*cursor_raw_bytes=86 .*cursor_scopes=1 .*cursor_gen=101' \
    "$POST_H3_LOG"

grep -q \
    'NATIVE_POST_12_REQUEST3=PASS' \
    "$POST_H3_LOG"

echo "GEN101_ALREADY_COMMITTED=PASS"
echo "NEW_ENDPOINT_172.18.0.12_USED=PASS"
echo "POST_CUTOVER_HTTP_200=PASS"

echo
echo "=== 14. POSITIVE AUTHORITY-CAPTURE CONTROL ==="

dig @"$AUTH_IP" \
    b.service.test A \
    +time=2 \
    +tries=1 \
    +noall \
    +answer \
    > "$RESULTS/control-query-b-service.txt"

sleep 0.5

stop_capture

sudo -n chown \
    "$(id -u):$(id -g)" \
    "$AUTH_PCAP" \
    2>/dev/null || true

test -s "$AUTH_PCAP"

sudo -n tcpdump \
    -nn \
    -vv \
    -r "$AUTH_PCAP" \
    > "$RESULTS/authority-dns-all.txt" \
    2>&1 || true

sudo -n tcpdump \
    -nn \
    -vv \
    -r "$AUTH_PCAP" \
    'udp dst port 53' \
    > "$RESULTS/authority-dns-queries.txt" \
    2>&1 || true

TARGET_Q=$(
    grep -F -c \
        'a.service.test.' \
        "$RESULTS/authority-dns-queries.txt" \
        || true
)

CONTROL_Q=$(
    grep -F -c \
        'b.service.test.' \
        "$RESULTS/authority-dns-queries.txt" \
        || true
)

echo "A_SERVICE_TEST_DNS_QUERIES=$TARGET_Q"
echo "CONTROL_B_SERVICE_TEST_DNS_QUERIES=$CONTROL_Q"

test "$CONTROL_Q" -ge 1 || {
    echo "FAIL: positive capture control missing"
    exit 1
}

test "$TARGET_Q" -eq 0 || {
    echo "FAIL: target DNS re-resolution observed"
    exit 1
}

echo "AUTHORITY_CAPTURE_CONTROL=PASS"
echo "DNS_QUERIES_DURING_CUTOVER=0"

echo
echo "=== 15. WRITE RESULT ==="

cat > "$RESULTS/RESULT.txt" <<EOF
DNS FRESHNESS HARD ZERO-DNS ENDPOINT CUTOVER
UTC=$STAMP

SECURE_DOH_DNSSEC_DISCOVERY=PASS
SNAPSHOT_GEN100=PASS
GEN101_COMMITTED_BEFORE_CUTOVER=PASS
SNAPSHOT_DELTA_SAME_H3_CONNECTION=PASS
APP1_PROTOCOL=$APP1_PROTOCOL
APP2_PROTOCOL=$APP2_PROTOCOL
DOH_CACHE_RESTART=PASS
OLD_ENDPOINT_172.18.0.61_REMOVED=PASS
NEW_ENDPOINT_172.18.0.12_USED=PASS
POST_CUTOVER_HTTP_200=PASS
AUTHORITY_CAPTURE_CONTROL=PASS
DNS_QUERIES_DURING_CUTOVER=0
FRESHNESS_ZERO_DNS_ENDPOINT_CUTOVER=PASS

TARGET_DNS_QUERIES=$TARGET_Q
CONTROL_DNS_QUERIES=$CONTROL_Q

SNAPSHOT_BYTES=$SNAPSHOT_SIZE
DELTA_BYTES=$DELTA_SIZE

CLAIM:
A local modified Chromium 151 bootstrapped Freshness through
Secure DoH and a validating resolver, admitted Gen100 from a
signed Snapshot, committed Gen101 from a signed Delta changing
a.service.test from 172.18.0.61 to 172.18.0.12, then after the
DoH cache was discarded and the old endpoint was physically
removed, completed the next HTTP/3 application request via
172.18.0.12 with HTTP 200 while the Authority observed zero
DNS queries for a.service.test.

CLAIM_BOUNDARY:
Local isolated DNS-Lab PoC only. No production, Internet-scale,
CDN/proxy/middlebox, universal performance, or standards-consensus
claim.
EOF

cp "$0" \
    "$RESULTS/run_zero_dns_cutover_freeze_v2.sh"

echo "RESULT_FILE=PASS"

echo
echo "=== 16. RESTORE NORMAL FULLSTACK H3 .61 ==="

d rm -f "$BROWSER" \
    >/dev/null 2>&1 || true

restore_h3

wait_h3_ready

RESTORED_IP=$(
    d inspect -f \
    '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' \
    "$H3"
)

test "$RESTORED_IP" = "$PRE_IP"

d inspect "$AUTH" "$DOH" "$H3" \
    > "$RESULTS/containers-after.json"

d network inspect "$NET" \
    > "$RESULTS/network-after.json"

echo "LAB_TOPOLOGY_RESTORED=PASS"

trap - EXIT

echo
echo "============================================================"
echo "SECURE_DOH_DNSSEC_DISCOVERY=PASS"
echo "SNAPSHOT_GEN100=PASS"
echo "GEN101_COMMITTED_BEFORE_CUTOVER=PASS"
echo "SNAPSHOT_DELTA_SAME_H3_CONNECTION=PASS"
echo "OLD_ENDPOINT_172.18.0.61_REMOVED=PASS"
echo "NEW_ENDPOINT_172.18.0.12_USED=PASS"
echo "POST_CUTOVER_HTTP_200=PASS"
echo "DNS_QUERIES_DURING_CUTOVER=0"
echo "AUTHORITY_CAPTURE_CONTROL=PASS"
echo "FRESHNESS_ZERO_DNS_ENDPOINT_CUTOVER=PASS"
echo "LAB_TOPOLOGY_RESTORED=PASS"
echo "EVIDENCE_DIR=$RESULTS"
echo "============================================================"
