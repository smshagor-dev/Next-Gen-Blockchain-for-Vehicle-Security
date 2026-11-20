# Durable admission validation matrix — 2026-11-20

Scope: draft PR #158, stacked on #157. Non-actuating research prototype.

| Workstream | State | Evidence / limitation |
|---|---|---|
| Epoch replay and one-shot admission | Partial | Implementation and focused tests; exact branch suite not executed |
| Emergency stop across restart | Partial | Persisted latch and regression test; no physical interlock evidence |
| Cold-start SQLite initialization | Implemented, unverified | BEGIN IMMEDIATE now covers schema/seed/read; WAL mode configured only at initialization |
| Cold-start independent-process experiment | Implemented, unverified | Six spawned processes, synchronized cold start, one-positive invariant |
| Existing warm-start concurrency | Partial | Twelve-process test committed; exact checkout execution pending |
| Crash-before/after-commit | Partial | Subprocess tests committed; actual run pending |
| Hardware TCP authentication / local interlocks | Partial | Audit and hardware validation pending; never enable physical actuation |
| Trusted rollback detection and ledger finality | Blocked | No external trusted checkpoint or real consensus proof |
| Authentic VeReMi NextGen/CAN cohorts | Pending | Dataset licensing, provenance and independent labels needed |
| Matched baselines / effect sizes | Pending | No authentic independent experiment results |
| Publication claims | Blocked | Fixture CSVs, poisoning sanity checks, microbenchmarks and formulas excluded |

## Reproduction

```bash
python -m unittest discover -s tests -p 'test_durable_cold_start_integrity.py' -v
python -m unittest discover -s tests -p 'test_durable_multiprocess_admission.py' -v
python -m unittest discover -s tests -p 'test_durable_crash_boundaries.py' -v
python -m unittest discover -s tests -v
```

No tests were executed on an exact repository checkout in this run. Review cold-start WAL-mode contention under independent process launches before merging. SQLite crash consistency is not Byzantine consensus, power-loss durability or vehicle safety.

Next code task: execute exact checkout tests, fix any initialization lock errors, and collect independently measured cold/warm start latency and error distributions with multiple seeds and confidence intervals.
