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

## 2026-11-19 — independent surviving-writer recovery timing control

- **Implemented (draft PR #153, not main):** `lock_release_latency.py` starts two separate spawned processes. The first holds an uncommitted SQLite write, then is SIGKILLed; the second waits to acquire a write transaction and must see no victim row before committing one surviving event. Every trial reports monotonic wait duration, exit codes and final row contents.
- **Regression:** `tests/test_lock_release_latency.py` asserts rollback, single surviving record, positive wait and parameter bounds. Commands: `python -m unittest discover -s tests -p 'test_lock_release_latency.py' -v`; `python -m research_contracts.lock_release_latency --trials 10 --hold-ms 100`.
- **Verification:** an independently authored local equivalent passed 3/3 unittest cases and 3/3 smoke trials (waits approximately 129 ms). **The exact committed GitHub source has NOT been executed**; these observations are engineering smoke evidence only, not independently validated branch results.
- **Limitations:** the contender signals immediately before calling SQLite; scheduling exposure is not an independent proof of entry into SQLite's busy handler. The earlier `verified_lock_contention.py` remains the explicit SQLITE_BUSY control. No real consensus, physical power loss, hardware, publishable latency estimate or incident-level effectiveness is claimed.
- **Next:** run exact branch regression/full suite, add deterministic busy-handler instrumentation or bounded busy timeout control, and return to authenticated hardware safety and production ledger inclusion verification.
