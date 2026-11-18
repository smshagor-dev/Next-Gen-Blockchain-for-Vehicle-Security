# Independent-process ledger race status — 2026-11-18

| Research workstream | Status | Evidence and limitations |
| --- | --- | --- |
| Authenticated bounded hardware ingress | PARTIAL | Draft #148; actual hardware safety and emergency interlocks not validated |
| Durable replay and rollback | PARTIAL | Draft #145–#146; valid SQLite snapshot rollback remains an observed design weakness |
| Crash recovery and idempotent inbox | PARTIAL | Draft #150–#151, surrogate only |
| Threaded concurrency | IMPLEMENTED, UNVERIFIED | Draft #152, separate connections but one process |
| Independent process contention | IMPLEMENTED, UNVERIFIED | This branch: spawn processes, separate SQLite connections, synchronized release, same-identity/conflicting-payload controls, exitcodes and persisted-state assertions |
| Production ledger verified inclusion/finality | BLOCKED | Surrogate is not a distributed ledger, no consensus or external monotonic anchor |
| Hardware emergency control | BLOCKED | No physical/HIL validation; never route remote commands to actuators |
| Authentic VeReMi NextGen/CAN | PARTIAL | Existing importer/baseline work elsewhere; no verified incident-level ground truth |
| Multi-seed matched adversarial experiments | PENDING | No publishable estimates, effect sizes or uncertainty |
| Resource scaling | PENDING | No independently measured network/CPU/RAM results |
| Scientific paper | BLOCKED | Need independent source provenance, baselines, threat model and numeric claim ledger |

## Reproducible commands

```bash
python -m unittest discover -s tests -p 'test_process_ledger_recovery.py' -v
python -m research_contracts.process_ledger_recovery --trials 10 --workers 4
python -m unittest discover -s tests -v
```

## Experimental integrity

The source code and assertions are committed, but the exact GitHub checkout was not executed locally: github.com DNS is unavailable to the execution container. **No passing outcomes or effectiveness measurements are claimed.** Process-level concurrency is a correctness probe, not an independent trial of real vehicles, power-cut durability, Byzantine consensus, or real ledger finality. A start event aligns worker attempts but does not guarantee overlapping SQLite transactions. SQLite connection setup may itself contend under concurrent PRAGMA initialization. Keep draft until verified execution, test review and resource bounds assessment.

## Follow-up implementation (2026-11-18)

Commit `ad9d90d` records child setup failure and readiness timeout as explicit failed observations rather than silently waiting at the startup barrier; `4b13a78` adds assertions for those fields. **Execution remains unverified**; these are instrumentation improvements, not successful experimental outcomes. Failure-injection of a child exiting before readiness and independent process SIGKILL during overlapping writes remain upcoming.

## Next

Run actual branch tests in CI or checkout; if PRAGMA initialization contends, isolate initialization from timed attempts and record failures rather than masking them. Add kill-at-commit-boundary while multiple independent writers race, then production ledger inclusion verification. Do not merge unverified changes.
