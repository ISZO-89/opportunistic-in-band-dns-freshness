#!/usr/bin/env bash
set -Eeuo pipefail

BASE=/mnt/user/appdata/dns-service-sync-lab
RW="$BASE/benchmark/realworld-freshness"
G18="$BASE/benchmark/gate18-http3"
CHROMIUM=/home/dnsadmin/chromium/src

NET=dns-service-sync-net
H3=dns-fullstack-h3
BROWSER=dns-wire-benchmark-browser

H3_IMAGE=dns-service-sync-realworld-h3:lab
BROWSER_IMAGE=dns-service-sync-real-browser:lab

STAMP=$(date -u +%Y%m%dT%H%M%SZ)
R="$BASE/benchmark/results/browser-wire-delta-nochange/$STAMP"
C="$R/control"

mkdir -p "$C"

restore_lab() {
    set +e

    sudo -n docker rm -f "$BROWSER" >/dev/null 2>&1 || true
    sudo -n docker rm -f "$H3" >/dev/null 2>&1 || true

    if sudo -n docker run -d \
        --name "$H3" \
        --network "$NET" \
        --ip 172.18.0.61 \
        -e NATIVE_PHASE=pre \
        -v "$RW:/work:ro" \
        -v "$G18/tls:/tls:ro" \
        "$H3_IMAGE" \
        python /work/native_browser_server.py \
        >/dev/null
    then
        echo "LAB_H3_RESTORED_TO_61_PRE=PASS"
        return 0
    fi

    echo "LAB_H3_RESTORED_TO_61_PRE=FAIL" >&2
    return 1
}

trap restore_lab EXIT

wait_control_file() {
    local file="$1"

    for i in $(seq 1 300); do
        if [ -f "$file" ]; then
            return 0
        fi

        if ! sudo -n docker inspect \
            -f '{{.State.Running}}' "$BROWSER" \
            2>/dev/null | grep -qx true
        then
            echo "FAIL: browser exited while waiting for $file" >&2
            sudo -n docker logs "$BROWSER" 2>&1 || true
            return 1
        fi

        sleep 0.1
    done

    echo "FAIL: timeout waiting for $file" >&2
    return 1
}

capture_request() {
    local name="$1"
    local release="$2"
    local done="$3"

    local pcap="$R/$name.pcap"
    local out="$R/$name-tcpdump.out"
    local err="$R/$name-tcpdump.err"
    local h3pid
    local tpid
    local ready=0

    h3pid=$(
        sudo -n docker inspect \
            -f '{{.State.Pid}}' "$H3"
    )

    # KNOWN-GOOD METHOD:
    # broad UDP capture on "any" inside H3 network namespace.
    sudo -n nsenter \
        -t "$h3pid" \
        -n \
        tcpdump \
        -ni any \
        -s 0 \
        -U \
        -w "$pcap" \
        udp \
        >"$out" 2>"$err" &

    tpid=$!

    for i in $(seq 1 100); do
        if grep -q 'listening on' "$err"; then
            ready=1
            break
        fi

        if ! kill -0 "$tpid" 2>/dev/null; then
            echo "FAIL: tcpdump exited before ready" >&2
            cat "$err" >&2 || true
            return 1
        fi

        sleep 0.05
    done

    if [ "$ready" != 1 ]; then
        echo "FAIL: tcpdump never became ready" >&2
        return 1
    fi

    echo "${name^^}_TCPDUMP_READY=PASS"

    touch "$C/$release"

    wait_control_file "$C/$done"

    # Allow libpcap/kernel capture buffer to be delivered to tcpdump.
    # Previous 0.5 s stop produced:
    #   0 packets captured
    #   5 packets received by filter
    sleep 2

    sudo -n nsenter \
        -t "$h3pid" \
        -n \
        pkill -INT tcpdump \
        >/dev/null 2>&1 || true

    wait "$tpid" 2>/dev/null || true

    sudo -n chown \
        "$(id -u):$(id -g)" \
        "$pcap" "$out" "$err" \
        2>/dev/null || true

    if [ ! -s "$pcap" ]; then
        echo "FAIL: empty $name pcap" >&2
        return 1
    fi

    local all_packets

    all_packets=$(
        sudo -n tcpdump -nn -r "$pcap" \
            2>/dev/null |
        wc -l
    )

    if [ "$all_packets" -eq 0 ]; then
        echo "FAIL: $name pcap contains zero packets" >&2
        return 1
    fi

    echo "${name^^}_ALL_UDP_PACKETS=$all_packets"
    echo "${name^^}_CAPTURE=PASS"
}

echo "============================================================"
echo "DNS FRESHNESS WIRE BENCHMARK V3"
echo "DELTA vs NO-CHANGE"
echo "UTC=$STAMP"
echo "============================================================"

echo
echo "=== 1. FRESH VECTORS ==="

sudo -n docker run --rm \
    -v "$RW:/work" \
    -v "$BASE/certs:/certs:ro" \
    "$H3_IMAGE" \
    python /work/generate_fullstack_vectors.py

NOW=$(date +%s)

python3 - "$RW/vectors/fullstack-vectors.json" "$NOW" <<'PY'
import json
import sys

with open(sys.argv[1]) as f:
    d = json.load(f)

now = int(sys.argv[2])
issued = int(d["issued_at"])
valid = int(d["valid_until"])

assert issued <= now < valid
assert now - issued < 60
assert valid - issued == 21600

print(f"VECTOR_AGE_SECONDS={now-issued}")
print(f"VECTOR_REMAINING_SECONDS={valid-now}")
print("FRESH_VECTOR_TIME_WINDOW=PASS")
PY

test "$(stat -c %s "$RW/vectors/fullstack-snapshot.cose")" = 325
test "$(stat -c %s "$RW/vectors/fullstack-delta.cose")" = 273

echo "VECTOR_SIZES=PASS"

echo
echo "=== 2. H3 MEASUREMENT MODE ==="

sudo -n docker rm -f "$BROWSER" >/dev/null 2>&1 || true
sudo -n docker rm -f "$H3" >/dev/null 2>&1 || true

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

H3_READY=0

for i in $(seq 1 100); do
    if sudo -n docker logs "$H3" 2>&1 |
        grep -q 'BROWSER_H3_SERVER_READY'
    then
        H3_READY=1
        break
    fi

    sleep 0.1
done

test "$H3_READY" = 1

echo "H3_MEASUREMENT_MODE=PASS"

echo
echo "=== 3. ONE CHROMIUM SESSION ==="

rm -f "$C"/*

H3PIN='NdxVLANqQ92KAB0XLPUtbP/X5h/SQXbJd46oMo8EBcs='
DOHPIN='b20c5FWqendhxrtGyB/k65HeF/WGiVc1TeC+Zi+kJbY='

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

wait_control_file "$C/request1.done"

sudo -n docker logs "$BROWSER" >"$R/browser.log" 2>&1
sudo -n docker logs "$H3" >"$R/h3.log" 2>&1

grep -q \
    'SNAPSHOT_ADMITTED=PASS GEN=100 ENDPOINT=172.18.0.61 ROOT_EPOCH=1' \
    "$R/browser.log"

grep -q \
    'cursor_raw_bytes=23 cursor_scopes=0 cursor_gen=none' \
    "$R/h3.log"

echo "SNAPSHOT_GEN100=PASS"

sleep 1

echo
echo "=== 4. DELTA WIRE WINDOW ==="

capture_request \
    delta \
    release2 \
    request2.done

sudo -n docker logs "$BROWSER" >"$R/browser.log" 2>&1
sudo -n docker logs "$H3" >"$R/h3.log" 2>&1

grep -q \
    'COMMIT=PASS GEN=101 ENDPOINT=172.18.0.12 ROOT_EPOCH=1' \
    "$R/browser.log"

grep -q \
    'cursor_raw_bytes=86 cursor_scopes=1 cursor_gen=100' \
    "$R/h3.log"

grep -q \
    'FRESHNESS_DELTA_ATTACHED' \
    "$R/h3.log"

echo "DELTA_GEN101_COMMIT=PASS"

sleep 1

echo
echo "=== 5. NO-CHANGE WIRE WINDOW ==="

capture_request \
    nochange \
    release3 \
    request3.done

sudo -n docker logs "$BROWSER" >"$R/browser.log" 2>&1
sudo -n docker logs "$H3" >"$R/h3.log" 2>&1

grep -q '^REQUEST3_STATUS=200$' "$R/browser.log"
grep -q '^REQUEST3_FRESHNESS_OBJECT=NO$' "$R/browser.log"

grep -q \
    'cursor_raw_bytes=86 cursor_scopes=1 cursor_gen=101' \
    "$R/h3.log"

grep -q \
    '^DELTA_NOCHANGE_BROWSER_SEQUENCE=PASS$' \
    "$R/browser.log"

echo "NOCHANGE_GEN101=PASS"

echo
echo "=== 6. SAME APP QUIC CONNECTION ==="

P1=$(
    sed -n \
        's/.*BROWSER_REQUEST protocol=\([0-9]*\).*path=\/app\/1.*/\1/p' \
        "$R/h3.log" |
    tail -1
)

P2=$(
    sed -n \
        's/.*BROWSER_REQUEST protocol=\([0-9]*\).*path=\/app\/2.*/\1/p' \
        "$R/h3.log" |
    tail -1
)

P3=$(
    sed -n \
        's/.*BROWSER_REQUEST protocol=\([0-9]*\).*path=\/app\/3.*/\1/p' \
        "$R/h3.log" |
    tail -1
)

S1=$(
    sed -n \
        's/.*BROWSER_REQUEST protocol=[0-9]* stream=\([0-9]*\).*path=\/app\/1.*/\1/p' \
        "$R/h3.log" |
    tail -1
)

S2=$(
    sed -n \
        's/.*BROWSER_REQUEST protocol=[0-9]* stream=\([0-9]*\).*path=\/app\/2.*/\1/p' \
        "$R/h3.log" |
    tail -1
)

S3=$(
    sed -n \
        's/.*BROWSER_REQUEST protocol=[0-9]* stream=\([0-9]*\).*path=\/app\/3.*/\1/p' \
        "$R/h3.log" |
    tail -1
)

test -n "$P1"
test "$P1" = "$P2"
test "$P2" = "$P3"

HANDSHAKES=$(
    grep -c '^QUIC_HANDSHAKE_COMPLETED' "$R/h3.log" ||
    true
)

echo "APP1_PROTOCOL=$P1 STREAM=$S1"
echo "APP2_PROTOCOL=$P2 STREAM=$S2"
echo "APP3_PROTOCOL=$P3 STREAM=$S3"
echo "TOTAL_H3_HANDSHAKES=$HANDSHAKES"
echo "APP_DELTA_NOCHANGE_SAME_QUIC_CONNECTION=PASS"

echo
echo "=== 7. OFFLINE PORT-4433 ANALYSIS ==="

for N in delta nochange; do
    sudo -n tcpdump \
        -nn \
        -r "$R/$N.pcap" \
        'udp port 4433' \
        >"$R/$N-wire.txt" 2>&1
done

python3 - "$R" <<'PY'
import re
import sys
from pathlib import Path

root = Path(sys.argv[1])

def stats(name):
    text = (root / f"{name}-wire.txt").read_text()
    rows = []

    for line in text.splitlines():
        m = re.search(r"UDP, length (\d+)$", line)
        if not m:
            continue

        size = int(m.group(1))

        if "> 172.18.0.61.4433:" in line:
            direction = "C2S"
        elif "172.18.0.61.4433 >" in line:
            direction = "S2C"
        else:
            continue

        rows.append((direction, size))

    if not rows:
        raise SystemExit(
            f"FAIL: {name} has zero UDP/4433 packets"
        )

    packets = len(rows)
    c2s = sum(n for d, n in rows if d == "C2S")
    s2c = sum(n for d, n in rows if d == "S2C")
    udp = c2s + s2c
    l3 = udp + packets * 28

    return packets, c2s, s2c, udp, l3

d = stats("delta")
n = stats("nochange")

labels = [
    "PACKETS",
    "C2S_UDP_BYTES",
    "S2C_UDP_BYTES",
    "UDP_BYTES",
    "APPROX_L3_BYTES",
]

lines = []

for label, dv, nv in zip(labels, d, n):
    lines.append(f"DELTA_{label}={dv}")
    lines.append(f"NOCHANGE_{label}={nv}")
    lines.append(f"DELTA_EXTRA_{label}={dv-nv}")
    lines.append("")

result = "\n".join(lines).rstrip() + "\n"

print(result)
(root / "wire-stats.txt").write_text(result)
PY

DELTA_MS=$(
    sed -n 's/^REQUEST2_MS=//p' "$R/browser.log" |
    tail -1
)

NOCHANGE_MS=$(
    sed -n 's/^REQUEST3_MS=//p' "$R/browser.log" |
    tail -1
)

{
    echo "DNS_FRESHNESS_WIRE_BENCHMARK=PASS"
    echo
    echo "DELTA_MS=$DELTA_MS"
    echo "NOCHANGE_MS=$NOCHANGE_MS"
    echo
    cat "$R/wire-stats.txt"
    echo
    echo "APP1_PROTOCOL=$P1"
    echo "APP1_STREAM=$S1"
    echo "APP2_PROTOCOL=$P2"
    echo "APP2_STREAM=$S2"
    echo "APP3_PROTOCOL=$P3"
    echo "APP3_STREAM=$S3"
    echo
    echo "TOTAL_H3_HANDSHAKES=$HANDSHAKES"
    echo "APP_DELTA_NOCHANGE_SAME_QUIC_CONNECTION=PASS"
    echo "WIRE_DELTA_NOCHANGE_MEASUREMENT=PASS"
} >"$R/RESULT.txt"

echo
echo "============================================================"
echo "FINAL RESULT"
echo "============================================================"

cat "$R/RESULT.txt"

echo
echo "=== 8. FREEZE ==="

cp "$0" "$R/run_wire_benchmark_v3.sh"

cp "$RW/native_browser_server.py" \
    "$R/native_browser_server.py"

cp "$RW/wire_delta_nochange_browser.js" \
    "$R/wire_delta_nochange_browser.js"

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
    xargs -0 sha256sum \
        >SHA256SUMS

    sha256sum -c SHA256SUMS
)

echo
echo "WIRE_BENCHMARK_FREEZE=PASS"
echo "RESULTS=$R"

trap - EXIT

restore_lab

echo
echo "WIRE_BENCHMARK_V3_COMPLETE=PASS"
