# Falsification Plan

The highest-value next step is independent validation, not additional local happy-path gates.

## Reproduction targets

1. Apply a clean Chromium patch against a pinned revision and reproduce: DNSSEC bootstrap -> Snapshot -> Delta -> hard cutover.
2. Repeat the core mechanism on Firefox/Necko, WebKit/NetworkProcess, or another independent browser/resolver stack.
3. Exercise real CDN/edge topologies, reverse proxies, HTTP field normalization/stripping, WAFs, service meshes, and anycast.
4. Test QUIC migration, 0-RTT, connection coalescing, Alt-Svc changes, concurrent H2/H3 streams, and response reordering.
5. Measure large working sets, scope churn, history truncation, update storms, and bounded-resource behavior under adversarial inputs.
6. Quantify the **hard-discontinuity rate and overlap window**: how often every previously authorized path disappears before a signed transition can be learned, versus rolling/draining/partial-change cases where at least one path survives long enough to reconcile state.
7. Run direct end-to-end Classic DNS/TTL vs Freshness recovery experiments in a production-grade browser harness, including:
   - long-TTL stale mappings;
   - resolver prefetch behavior;
   - explicit 30 s and 60 s short-TTL baselines;
   - Alt-Svc + HTTPS/SVCB where applicable;
   - request latency and failure attempts;
   - population-wide DNS query volume over change windows and different client-activity ratios.
8. Measure CPU, memory, cryptographic verification cost, cursor compression/QPACK effects, and mobile battery impact.
9. Simulate clock skew, root/operational key compromise, replay windows, and emergency DNSSEC root resets.
10. Attempt to dominate the proposal with simpler existing mechanisms. If Alt-Svc, HTTPS/SVCB, short TTLs, resolver prefetch, or combinations of them provide comparable convergence/recovery with materially less state, trust machinery, implementation complexity, and no materially greater population-wide DNS work, narrow or reject the proposal.

## Kill criteria

Reject or redesign the approach if independent testing shows any of the following as a common rather than exceptional condition:

- Freshness itself adds a network RTT in the intended active-path operating point.
- Trust/view boundaries cannot be preserved through real intermediaries.
- Client, relay, or Authority state grows without a hard bound.
- Real services rarely retain an authorized overlap path long enough for useful pre-failure reconciliation.
- Recovery is triggered more often than stale-path or DNS work is avoided.
- A simpler existing mechanism delivers comparable convergence and failure recovery with materially lower implementation complexity.
- Short-TTL/prefetch or Alt-Svc + HTTPS/SVCB achieves comparable operational results without materially greater population-wide DNS work.
- CPU, memory, cryptographic, header-compression, or battery cost makes the mechanism unattractive in production clients.

## Evidence discipline

A local Gate PASS means only that the tested falsifiable condition survived the lab scenario. It does not establish Internet-scale superiority or production readiness.

If a narrative statement conflicts with the frozen evidence ledger, `evidence/evidence-freeze-v0.1-de.md` takes precedence until new evidence is added.
