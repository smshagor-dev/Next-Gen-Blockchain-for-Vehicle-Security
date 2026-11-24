# OmniGuard V2X research status — 2026-11-22

## Evidence scope
This branch introduces a **loopback-only** bounded-TCP-admission saturation and recovery experiment. It tests real socketpair descriptors and worker threads; it does **not** authenticate packets, simulate a real V2X network, or measure a physical actuator.

| Workstream | State | Evidence / remaining gap |
|---|---|---|
| TCP worker saturation/recovery | Implemented, execution pending | `tests/test_tcp_admission_saturation_experiment.py`; exact checkout unavailable in this environment |
| Authenticated TCP ingress, replay and resource budgets | Partial | Main includes authenticated envelope, SQLite nonce and bounded admission; integration fault injection still needed |
| Serial durable replay and pre-verification budgets | Partial | Draft PRs #180, #190, #191; reconcile rather than duplicate |
| Local emergency control and physical interlocks | Blocked for physical validation | Network actuation disabled; no physical lab evidence |
| Ledger crash consistency / contract finality | Partial / blocked | SQLite crash PRs #181–183; mock finality not independent consensus |
| Evidence-gated admission + baselines | Partial | Draft PR #189; requires independent incident experiments |
| Authentic VeReMi NextGen and CAN provenance | Partial / blocked | Draft PRs #185–188; no verified labelled corpus in this run |
| Identical-split multi-seed statistical effectiveness | Pending | Paired evaluator #184; no publishable effectiveness numbers |
| Runtime CPU/RAM/latency scaling | Partial | This experiment measures admission dispatch time only; no CPU/RAM/network throughput |
| Publication-ready original scientific evidence | Not ready | Exclude fixture CSVs, 3-peer poisoning, five-iteration microbenchmarks and offline communication formulas |

## Protocol
Run `python -m unittest discover -s tests -p 'test_tcp_admission_saturation_experiment.py' -v` and `python tests/test_tcp_admission_saturation_experiment.py --capacity 4 --excess 16` on an exact checkout. Repeat across capacities and seeds on a pinned host and record OS/Python/CPU/RAM, median/p95 latency and uncertainty. A single dispatch timing is not a publishable benchmark.

## Next engineering task
Run exact-checkout integration tests; instrument authenticated loopback frames with nonce-store reopen and malformed/DoS loads while preserving disabled network actuation. Then integrate independent labelled incident-level data for matched baselines.
