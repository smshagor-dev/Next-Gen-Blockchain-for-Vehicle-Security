# Original research readiness matrix — 2026-11-23 (ingress clock fault controls)

| Workstream | State | Evidence / next gate |
|---|---|---|
| Authenticated hardware ingress | PARTIAL | Existing MAC/replay framing; drafts #207–#215 await integration and exact-checkout regression |
| Host receive/commit freshness | PARTIAL | New UTC arithmetic overflow guard and six deterministic fault controls in this branch; tests NOT executed |
| Local emergency precedence | PARTIAL | Remote actuator outputs disabled; physical emergency circuit not validated |
| Ledger crash consistency and mock finality | PARTIAL | Durable inbox prior work; end-to-end failure/recovery and real finality remain unverified |
| Evidence-gated admission novelty | UPCOMING | Formal safety properties, strong prior-work comparisons, testable hypotheses |
| Authentic VeReMi NextGen and CAN provenance | BLOCKED | No verified dataset ingest/split provenance |
| Independent multi-seed attacks and baselines | UPCOMING | Replay/spoof/DoS/fault campaigns on identical splits |
| Runtime and uncertainty/effect sizes | UPCOMING | Real latency/CPU/RAM/throughput and uncertainty intervals |
| Original research article | BLOCKED | No publication-grade validated effectiveness results |

This is a **software-clock fault control**, not a physically trusted timestamp, network benchmark, hardware experiment, or evidence of attack-detection effectiveness. Fixture CSVs, three-peer poisoning checks, five-iteration microbenchmarks, and offline communication formulas remain non-publishable main results.

Validation gate:
```sh
python -m unittest discover -s tests -p 'test_ingress_clock_fault_controls.py' -v
python -m unittest discover -s tests -v
```
