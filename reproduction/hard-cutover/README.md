# Hard-cutover reproduction notes

This directory contains the public reconstruction helpers for the Chromium/H3/DNSSEC hard-cutover experiment.

## What the canonical frozen experiment demonstrated

The frozen validated run in `../../evidence/hard-cutover/` demonstrated:

```text
DNSSEC/Secure-DoH bootstrap
        -> Snapshot Gen100 / 172.18.0.61
        -> natural H3 request
        -> signed Delta Gen100 -> Gen101 / 172.18.0.12
        -> Gen101 committed before cutover
        -> resolver cache discarded
        -> old endpoint 172.18.0.61 removed
        -> next request reaches 172.18.0.12
        -> HTTP 200
        -> zero authoritative queries for a.service.test during cutover
```

The files in this directory are for **clean reconstruction and further testing**. They do not overwrite the frozen evidence.

## 1. Prerequisites

You need:

- Linux with Docker;
- Python 3;
- OpenSSL;
- DNSSEC tooling used by the bootstrap helper;
- a Chromium source checkout and normal Chromium Linux build prerequisites;
- sufficient RAM/disk to build Chromium;
- network namespaces / Docker networking suitable for an isolated lab.

For Chromium build prerequisites, use the upstream Chromium Linux build documentation for the pinned source revision.

## 2. Check out the pinned Chromium base

The exact base revision is recorded in:

```text
../../implementation/chromium-base-revision.txt
```

Expected revision:

```text
782af9cb30a53f54487e5d2e44738645a8ec457c
```

From your Chromium `src` checkout:

```bash
git checkout 782af9cb30a53f54487e5d2e44738645a8ec457c
git status --short
git apply --check /path/to/repo/implementation/chromium-freshness-v0.1.patch
git apply /path/to/repo/implementation/chromium-freshness-v0.1.patch
```

`git apply --check` should succeed before the patch is applied.

## 3. GN args and build

The tested GN args are in:

```text
../../implementation/chromium-build-args.gn
```

They are:

```gn
is_debug = false
symbol_level = 0
```

Create your output directory, place those args in `args.gn`, run `gn gen`, and build Chromium using the normal Chromium toolchain for that revision.

The historical tested binary is **not** distributed by this repository.

## 4. Generate fresh test-only trust material

Do not reuse historical private keys from the frozen run.

The helper scripts generate fresh local test material under `/tmp` by default.

### Authority key helper

```bash
./generate_test_authority_keys.sh /tmp/dnsfresh-test-authority-keys
```

Expected markers from the validated helper:

```text
TEST_ONLY_AUTHORITY_KEYS_CREATED=PASS
TEST_ONLY_AUTHORITY_KEYS_VALID=PASS
```

### DNSSEC / discovery / DoH bootstrap helper

```bash
./generate_clean_dns_bootstrap.sh /tmp/dnsfresh-clean-bootstrap
```

Expected markers from the validated helper:

```text
CLEAN_DNSSEC_ZONE=PASS
CLEAN_DOH_TLS=PASS
CLEAN_DISCOVERY_EMBEDDED=PASS
```

This helper creates fresh test-only Freshness authority material, DNSSEC keys, a signed `service.test` zone, a trust anchor, and DoH TLS material. Private keys are local reproduction artifacts and must not be committed.

## 5. Deterministic discovery and fullstack vectors

`generate_test_discovery.py` reconstructs the deterministic native discovery CBOR format. The project validation reproduced the frozen discovery byte-identically:

```text
DISCOVERY_FROZEN_BYTE_IDENTITY=PASS
```

`generate_fullstack_vectors.py` creates fresh Snapshot/Delta material for the H3 server path. A validated clean generation produced:

```text
FULLSTACK_VECTORS=PASS
STATE100_BYTES=74
STATE101_BYTES=74
SNAPSHOT_COSE_BYTES=325
DELTA_COSE_BYTES=273
```

The exact command-line wiring depends on the test directory paths produced by your clean bootstrap. Read the script's path constants/arguments before running it and keep all generated private material outside the repository.

## 6. Lab topology used by the frozen run

The historical fullstack lab used one isolated Docker network and the following addresses:

```text
authoritative DNS       172.18.0.54
a validating/Secure DoH 172.18.0.55
pre-cutover H3 endpoint 172.18.0.61
post-cutover endpoint   172.18.0.12
b.service.test          172.18.0.12
c.service.test          172.18.0.13
```

The included files provide the relevant CoreDNS zone/config, Unbound configuration, H3 server, browser driver, TLS helper, key/discovery/bootstrap generators, and historical orchestration reference.

`historical-runner.sh` intentionally contains paths from the original DNS-Lab and is **not** a portable one-command runner. Treat it as an auditable record/topology reference when reconstructing the isolated environment.

## 7. Run the cutover

The behavior to reproduce is:

1. start authoritative DNS and validating DoH;
2. start the H3 server at the pre-cutover endpoint;
3. launch the patched Chromium against the lab;
4. admit DNSSEC-authenticated discovery;
5. receive and commit Snapshot Gen100;
6. on a later natural H3 request, receive and commit Delta Gen100 -> Gen101;
7. verify Gen101 points to the post-cutover endpoint **before** removing the old endpoint;
8. discard the normal resolver cache used for the test;
9. remove the old H3 endpoint and activate the replacement;
10. issue the next request from the same Chromium process;
11. verify HTTP 200 from the replacement;
12. inspect authoritative DNS capture and verify zero target-name queries during the cutover window.

Use the frozen files in `../../evidence/hard-cutover/` as the reference for expected logs, captures, vectors, and PASS markers.

## 8. Reproduction status boundary

Important distinction for v0.1.0:

- the **canonical hard-cutover evidence is validated and frozen**;
- the clean authority/discovery/DNSSEC/vector helpers were individually validated;
- the full clean reconstruction has **not** yet been independently executed end-to-end as one portable packaged runner.

That is deliberate disclosure, not a hidden success claim. External contributors are invited to complete, simplify, port, and attack the reconstruction.

## 9. Do not modify frozen evidence

Run experiments in a separate output directory. Do not regenerate files inside `../../evidence/` or `../../test-vectors/` if the goal is to compare against the published v0.1.0 evidence.
