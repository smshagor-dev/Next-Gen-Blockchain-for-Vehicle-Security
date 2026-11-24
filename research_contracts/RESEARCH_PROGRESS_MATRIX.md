# OmniGuard V2X research evidence matrix (2026-11-18)

This matrix tracks **evidence**, not code completeness. None of the SQLite surrogate checks establish blockchain finality or real-vehicle safety.

| Workstream | State | Evidence / missing validation |
|---|---|---|
| Authenticated bounded hardware ingress and emergency isolation | Partial | Production changes in earlier draft PRs; no physical emergency-control validation |
| Per-frame replay handling | Partial | Draft regression tests; cross-store nonce claim remains non-atomic |
| Durable SQLite inbox / ledger reconciliation | Partial | Code and fault probes in draft PRs; actual production ledger inclusion/finality adapter absent |
| Independent process contention | Partial | Spawned-process harness; repository execution and overlap measurements pending |
| Exit-before-readiness fail-closed barrier | Implemented, **unverified** | Commit 2001831 and regression commit 94b71e3; expected zero ledger writes when one worker exits |
| SIGKILL before SQLite ledger COMMIT | Implemented, **unverified** | New spawned child inserts inside BEGIN IMMEDIATE then SIGKILL; parent asserts rollback and unique retry. This is a single-writer surrogate, not overlapping-writer proof |\n| SIGKILL during overlapping transactions | Upcoming | Need deterministic two-writer overlap, timeout controls and independent restart verification |
| VeReMi NextGen and CAN provenance | Blocked | Authentic downloads, licensing, checksums, split manifests and validation pending |
| Adversarial baselines and ablations | Upcoming | No publishable independent dataset experiments |
| Multi-seed statistical effects and runtime resource measurement | Upcoming | No publishable samples; n>=30 alone does not imply statistical significance |
| Research paper and numeric claim ledger | Blocked | Wait for validated real experiments, uncertainty, limitations and baseline comparisons |

## Reproduction
```bash
python -m unittest discover -s tests -p 'test_process_ledger_recovery.py' -v
python -m research_contracts.process_ledger_recovery --trials 10 --workers 4\npython -m unittest discover -s tests -p 'test_inflight_sqlite_sigkill.py' -v\npython -m research_contracts.inflight_sqlite_sigkill --trials 10
```

## Next
Run branch regression tests, fix failures, add bounded deterministic SIGKILL at transaction overlap, and reconcile after process restart. Preserve fail-closed non-actuating behavior. Existing fixture CSVs, three-peer sanity checks, five-iteration microbenchmarks and offline network formulas are not publishable main results.

## 2026-11-19 contention measurement isolation

- **Implemented, not yet branch-tested:** commit 9cad2f4 separates WAL journal-mode initialization from independent contender connections, so the measured `BEGIN IMMEDIATE` lock attempt cannot be confused with journal-mode configuration.
- **Regression strengthened:** commit e8969b5 requires at least 50 ms of SQLite busy waiting and POSIX SIGKILL exit `-9`, rather than accepting any positive wait. The timeout configured for the contender is 200 ms; elapsed duration is an assertion threshold, not a benchmark estimate.
- **Local diagnostic only:** an independent SQLite/WAL two-connection probe observed `BEGIN IMMEDIATE` returning `database is locked` while a writer held an uncommitted transaction. This is not execution of the committed branch or publication evidence.
- **Blocked:** exact branch regression execution (GitHub checkout DNS failure), external finality, hardware safety, real incident labels and statistically powered multi-seed experiments.
- **Next:** run `python -m unittest discover -s tests -p 'test_verified_lock_contention.py' -v` on the exact branch; verify wait and recovery traces, then pursue real ledger receipt integrity rather than expanding SQLite-only proxies.
