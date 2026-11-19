# OmniGuard V2X research evidence status — 2026-11-19

This matrix records implementation separately from verified experimental results. It is not a publication results table.

| Workstream | State | Evidence / next gate |
| --- | --- | --- |
| Hardware bridge authenticated ingress, bounded framing, replay and safety interlocks | PARTIAL / BLOCKED | Re-audit production entrypoint; no physical emergency-stop/HIL validation |
| Durable inbox and SQLite surrogate recovery | PARTIAL | Draft PRs #150–153; no production blockchain finality proof |
| Cross-process write lock conflict and precommit SIGKILL | IMPLEMENTED / UNVERIFIED | `research_contracts/verified_lock_contention.py`; contender must receive actual SQLITE_BUSY while holder lives; regression test committed; exact branch execution pending |
| Independently authenticated event admission | PARTIAL | Need adversarial enrolled-node experiments and independent incident truth |
| VeReMi NextGen provenance and CAN datasets | PARTIAL | CAM attacker labels must never be treated as incident truth |
| Matched adversarial baselines, ablations and multi-seed statistics | UPCOMING | No publishable incident-level estimates yet |
| CPU, RAM, network and latency scaling | UPCOMING | Must measure runtime rather than offline formula |
| Defensible original research manuscript | BLOCKED | Require verified, independent experiments and comparison to prior work |

## Current experiment contract

`python -m unittest discover -s tests -p 'test_verified_lock_contention.py' -v`

`python -m research_contracts.verified_lock_contention --trials 10`

The experiment forces an independent contender to time out on SQLite `BEGIN IMMEDIATE` while the first process holds an uncommitted write transaction. Only after receiving the bounded SQLITE_BUSY result does the parent release the holder to die by SIGKILL. Restart must show zero precommit rows; a retry then writes exactly one row. The wait duration is instrumentation, not a statistically independent sample or a throughput benchmark.

Limitations: this is a SQLite WAL surrogate, not real ledger consensus, power-cut durability, distributed finality or physical actuator safety. No real automotive hardware was accessed. Existing fixture CSVs, 3-peer poisoning checks, 5-iteration microbenchmarks and communication formulas are non-publishable. Statistical significance must be assessed with justified experimental units, uncertainty, effects and an appropriate test; `n >= 30` alone is not significance.

Next: execute the exact branch tests, investigate failures, then integrate observed lock-wait controls with postcommit reconciliation and independently sourced event-admission truth.
