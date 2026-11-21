# Research evidence status matrix (2026-11-16)

| Workstream | State | Evidence / blocker | Next code task |
| --- | --- | --- | --- |
| Hardware bridge authenticated TCP ingress | PARTIAL | This PR implements a simulation-only bounded HMAC admission gate; NOT integrated with hardware_bridge or persistent replay state | Trace actual receiver path, enforce authenticated framing and deadlines before any physical output |
| Bench arming / local emergency isolation | PARTIAL | Draft #138 descriptor revalidation unverified; draft #137 trace invariants unintegrated | Run full regression suite, wire local emergency priority and verify actuator output paths |
| Ledger crash consistency / finality | BLOCKED | No externally anchored finality or crash-recovery proof accepted | Inject process kill at each ledger write boundary; distinguish mock receipts from finality |
| Distinguishable evidence-gated admission hypothesis | PARTIAL | Protocol model only; HMAC is established technology, not novel cryptography | Specify evidence freshness, quorum, malicious enrolled-node and fail-safe properties |
| Authentic VeReMi NextGen / CAN ingest | BLOCKED | Independent source hashes, licensing, labels and provenance not verified | Acquire and hash authorized raw archives; construct recording-disjoint splits |
| Replay / spoof / enrolled-node / DoS experiments | UPCOMING | 9 simulation protocol regression cases; no independent incidents or measured attack rates | Implement controlled paired attack replay and record unsafe-admission counts |
| Multi-seed latency / throughput / CPU / RAM | UPCOMING | No runtime network measurements | Run reproducible matched baselines and clustered uncertainty intervals |
| Publication figures and numeric claims | BLOCKED | Fixture CSV, 3-peer sanity checks, 5-iteration microbenchmarks and formula-only communications are NOT publishable main evidence | Maintain numeric claim ledger after independent experiment validation |

Simulation constraints: HMAC authenticates possession of a shared key, not truthful sensor data. A malicious enrolled node remains an attacker. Volatile high-water marks allow restart replay; time windows require trusted clocks. This gate has no socket deadlines, no concurrent connection limits, no durable state and NO physical actuator authority. Local emergency control must remain outside network admission.
