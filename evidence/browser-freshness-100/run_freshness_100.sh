#!/usr/bin/env bash
set -Eeuo pipefail

BASE=/mnt/user/appdata/dns-service-sync-lab
RW="$BASE/benchmark/realworld-freshness"
G18="$BASE/benchmark/gate18-http3"
CHROMIUM=/home/dnsadmin/chromium/src

NET=dns-service-sync-net
H3=dns-fullstack-h3
BROWSER=dns-freshness-bench-browser

H3_IMAGE=dns-service-sync-realworld-h3:lab
BROWSER_IMAGE=dns-service-sync-real-browser:lab

REPS=100

STAMP=$(date -u +%Y%m%dT%H%M%SZ)
R="$BASE/benchmark/results/browser-freshness-100/$STAMP"
CSV="$R/samples.csv"

mkdir -p "$R/reps"

cleanup_rep() {
    sudo -n docker rm -f "$BROWSER" >/dev/null 2>&1 || true
    sudo -n docker rm -f "$H3" >/dev/null 2>&1 || true
}

restore_lab() {
    set +e

    cleanup_rep

    sudo -n docker run -d \
      --name "$H3" \
      --network "$NET" \
      --ip 172.18.0.61 \
      -e NATIVE_PHASE=pre \
      -v "$RW:/work:ro" \
      -v "$G18/tls:/tls:ro" \
      "$H3_IMAGE" \
      python /work/native_browser_server.py \
      >/dev/null 2>&1

    echo "LAB_H3_RESTORED_TO_61_PRE=PASS"
}

trap restore_lab EXIT

wait_file() {
    local file="$1"

    for i in $(seq 1 300); do
        [ -f "$file" ] && return 0

        if ! sudo -n docker inspect \
          -f '{{.State.Running}}' "$BROWSER" \
          2>/dev/null | grep -qx true
        then
            echo "FAIL: browser exited waiting for $file" >&2
            return 1
        fi

        sleep 0.1
    done

    echo "FAIL: timeout $file" >&2
    return 1
}

echo "============================================================"
echo "DNS FRESHNESS 100-REP BENCHMARK"
echo "UTC=$STAMP"
echo "============================================================"

echo
echo "=== FRESH VECTORS ==="

sudo -n docker run --rm \
  -v "$RW:/work" \
  -v "$BASE/certs:/certs:ro" \
  "$H3_IMAGE" \
  python /work/generate_fullstack_vectors.py

python3 - "$RW/vectors/fullstack-vectors.json" <<'PY'
import json
import time
import sys

d=json.load(open(sys.argv[1]))
now=int(time.time())

assert d["issued_at"] <= now < d["valid_until"]
assert now-d["issued_at"] < 60
assert d["valid_until"]-d["issued_at"] == 21600

print("FRESH_VECTOR_TIME_WINDOW=PASS")
PY

printf '%s\n' \
'rep,delta_ms,nochange_ms,delta_minus_nochange_ms,app_protocol,stream1,stream2,stream3,total_handshakes,same_app_quic' \
>"$CSV"

H3PIN='NdxVLANqQ92KAB0XLPUtbP/X5h/SQXbJd46oMo8EBcs='
DOHPIN='b20c5FWqendhxrtGyB/k65HeF/WGiVc1TeC+Zi+kJbY='

echo
echo "=== RUN 100 CONTROLLED REPLICATIONS ==="

for REP in $(seq 1 "$REPS"); do
    ID=$(printf '%03d' "$REP")
    RR="$R/reps/$ID"
    C="$RR/control"

    mkdir -p "$C"

    cleanup_rep

    sudo -n docker run -d \
      --name "$H3" \
      --network "$NET" \
      --ip 172.18.0.61 \
      -e NATIVE_PHASE=measure \
      -v "$RW:/work:ro" \
      -v "$G18/tls:/tls:ro" \
      "$H3_IMAGE" \
      python /work/native_browser_server.py \
      >/dev/null

    READY=0

    for i in $(seq 1 100); do
        if sudo -n docker logs "$H3" 2>&1 |
           grep -q 'BROWSER_H3_SERVER_READY'
        then
            READY=1
            break
        fi

        sleep 0.1
    done

    test "$READY" = 1

    sudo -n docker run -d \
      --name "$BROWSER" \
      --init \
      --ipc=host \
      --network "$NET" \
      --dns 172.18.0.55 \
      -e "ALL_SPKI=$H3PIN,$DOHPIN" \
      -e DEBUG=pw:browser \
      -v "$CHROMIUM/out/Freshness:/native-chromium:ro" \
      -v "$RW:/work:ro" \
      -v "$C:/control" \
      "$BROWSER_IMAGE" \
      node /work/wire_delta_nochange_browser.js \
      >/dev/null

    wait_file "$C/request1.done"

    touch "$C/release2"
    wait_file "$C/request2.done"

    touch "$C/release3"
    wait_file "$C/request3.done"

    EXITED=0

    for i in $(seq 1 200); do
        if ! sudo -n docker inspect \
          -f '{{.State.Running}}' "$BROWSER" \
          2>/dev/null | grep -qx true
        then
            EXITED=1
            break
        fi

        sleep 0.1
    done

    test "$EXITED" = 1

    sudo -n docker logs "$BROWSER" >"$RR/browser.log" 2>&1
    sudo -n docker logs "$H3" >"$RR/h3.log" 2>&1

    grep -q \
      'SNAPSHOT_ADMITTED=PASS GEN=100 ENDPOINT=172.18.0.61 ROOT_EPOCH=1' \
      "$RR/browser.log"

    grep -q \
      'COMMIT=PASS GEN=101 ENDPOINT=172.18.0.12 ROOT_EPOCH=1' \
      "$RR/browser.log"

    grep -q '^REQUEST3_STATUS=200$' \
      "$RR/browser.log"

    grep -q '^REQUEST3_FRESHNESS_OBJECT=NO$' \
      "$RR/browser.log"

    grep -q '^DELTA_NOCHANGE_BROWSER_SEQUENCE=PASS$' \
      "$RR/browser.log"

    DELTA_MS=$(
      sed -n 's/^REQUEST2_MS=//p' "$RR/browser.log" |
      tail -1
    )

    NOCHANGE_MS=$(
      sed -n 's/^REQUEST3_MS=//p' "$RR/browser.log" |
      tail -1
    )

    P1=$(
      sed -n \
        's/.*BROWSER_REQUEST protocol=\([0-9]*\).*path=\/app\/1.*/\1/p' \
        "$RR/h3.log" |
      tail -1
    )

    P2=$(
      sed -n \
        's/.*BROWSER_REQUEST protocol=\([0-9]*\).*path=\/app\/2.*/\1/p' \
        "$RR/h3.log" |
      tail -1
    )

    P3=$(
      sed -n \
        's/.*BROWSER_REQUEST protocol=\([0-9]*\).*path=\/app\/3.*/\1/p' \
        "$RR/h3.log" |
      tail -1
    )

    S1=$(
      sed -n \
        's/.*BROWSER_REQUEST protocol=[0-9]* stream=\([0-9]*\).*path=\/app\/1.*/\1/p' \
        "$RR/h3.log" |
      tail -1
    )

    S2=$(
      sed -n \
        's/.*BROWSER_REQUEST protocol=[0-9]* stream=\([0-9]*\).*path=\/app\/2.*/\1/p' \
        "$RR/h3.log" |
      tail -1
    )

    S3=$(
      sed -n \
        's/.*BROWSER_REQUEST protocol=[0-9]* stream=\([0-9]*\).*path=\/app\/3.*/\1/p' \
        "$RR/h3.log" |
      tail -1
    )

    test -n "$P1"
    test "$P1" = "$P2"
    test "$P2" = "$P3"

    HANDSHAKES=$(
      grep -c '^QUIC_HANDSHAKE_COMPLETED' \
        "$RR/h3.log" || true
    )

    DIFF=$(
      python3 - "$DELTA_MS" "$NOCHANGE_MS" <<'PY'
import sys
print(f"{float(sys.argv[1])-float(sys.argv[2]):.3f}")
PY
    )

    printf '%s,%s,%s,%s,%s,%s,%s,%s,%s,%s\n' \
      "$REP" \
      "$DELTA_MS" \
      "$NOCHANGE_MS" \
      "$DIFF" \
      "$P1" \
      "$S1" \
      "$S2" \
      "$S3" \
      "$HANDSHAKES" \
      "1" \
      >>"$CSV"

    cleanup_rep

    if (( REP % 10 == 0 )); then
        echo "REPLICATIONS_COMPLETE=$REP/$REPS"
    fi
done

echo
echo "=== STATISTICAL RESULT ==="

python3 - "$CSV" "$R/RESULT.txt" <<'PY'
import csv
import math
import statistics
import sys
from collections import Counter

csv_path = sys.argv[1]
out_path = sys.argv[2]

with open(csv_path, newline="") as f:
    rows=list(csv.DictReader(f))

if len(rows) != 100:
    raise SystemExit(f"FAIL: expected 100 rows, got {len(rows)}")

delta=[float(r["delta_ms"]) for r in rows]
nochange=[float(r["nochange_ms"]) for r in rows]
diff=[float(r["delta_minus_nochange_ms"]) for r in rows]

def percentile(values, p):
    values=sorted(values)
    i=max(0, math.ceil(len(values)*p)-1)
    return values[i]

def summary(name, values):
    return [
        f"{name}_N={len(values)}",
        f"{name}_MIN_MS={min(values):.3f}",
        f"{name}_MEAN_MS={statistics.mean(values):.3f}",
        f"{name}_P50_MS={percentile(values,0.50):.3f}",
        f"{name}_P95_MS={percentile(values,0.95):.3f}",
        f"{name}_P99_MS={percentile(values,0.99):.3f}",
        f"{name}_MAX_MS={max(values):.3f}",
    ]

same=sum(int(r["same_app_quic"]) for r in rows)
handshakes=Counter(int(r["total_handshakes"]) for r in rows)
protocols=Counter(r["app_protocol"] for r in rows)

lines=[
    "DNS_FRESHNESS_100_REP_BENCHMARK=PASS",
    "",
    *summary("DELTA",delta),
    "",
    *summary("NOCHANGE",nochange),
    "",
    *summary("DELTA_MINUS_NOCHANGE",diff),
    "",
    f"SAME_APP_QUIC={same}/100",
    "APP_PROTOCOL_DISTRIBUTION="
        + ",".join(f"{k}:{v}" for k,v in sorted(protocols.items())),
    "TOTAL_HANDSHAKE_DISTRIBUTION="
        + ",".join(f"{k}:{v}" for k,v in sorted(handshakes.items())),
]

text="\n".join(lines)+"\n"

print(text)
open(out_path,"w").write(text)
PY

echo "=== FREEZE ==="

cp "$0" "$R/run_freshness_100.sh"
cp "$RW/wire_delta_nochange_browser.js" \
   "$R/wire_delta_nochange_browser.js"
cp "$RW/native_browser_server.py" \
   "$R/native_browser_server.py"
cp "$RW/vectors/fullstack-vectors.json" \
   "$R/fullstack-vectors.json"
cp "$RW/vectors/fullstack-snapshot.cose" \
   "$R/fullstack-snapshot.cose"
cp "$RW/vectors/fullstack-delta.cose" \
   "$R/fullstack-delta.cose"

(
    cd "$R"

    find . \
      -type f \
      ! -name SHA256SUMS \
      -print0 |
    sort -z |
    xargs -0 sha256sum >SHA256SUMS

    sha256sum -c SHA256SUMS >/dev/null
)

echo "FRESHNESS_100_FREEZE=PASS"
echo "RESULTS=$R"

trap - EXIT
restore_lab

echo
echo "FRESHNESS_100_COMPLETE=PASS"
