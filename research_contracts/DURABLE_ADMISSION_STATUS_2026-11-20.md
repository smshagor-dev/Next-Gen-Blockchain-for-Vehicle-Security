# Durable admission research status — 2026-11-20

This is a non-actuating experiment ledger for draft PR #158 (stacked on #157).
Do not use these microbenchmarks as V2X attack-detection or vehicle safety results.

| Workstream | State | Evidence / next action |
|---|---|---|
| Authenticated bounded hardware ingress | Partial | Existing implementation reported; independent end-to-end receiver and local emergency-stop audit still needed |
| Epoch replay and one-shot admission | Partial | Candidate and regression code in #157; exact checkout suite unverified |
| Durable SQLite admission | Partial | Atomic transition adapter and crash/concurrency test scripts in #158; exact checkout execution outstanding |
| Randomized paired execution order | Implemented, unverified | Commit 7796a647; deterministic seeded block balance, order captured in each trial |
| Reverse-order and schedule regression tests | Implemented, unexecuted | Commit b99c9e5; run focused unittest on exact checkout |
| Network/CPU/RAM/throughput scaling | Upcoming | Independent-process networked workload and resource measurement |
| Trusted rollback protection and independent ledger finality | Blocked | Requires independent trusted checkpoint and actual consensus implementation |
| Authentic VeReMi NextGen/CAN data and provenance | Upcoming | Acquire, verify hashes/licensing, incident-level splits and non-leaking labels |
| Adversarial matched baselines, ablations and uncertainty | Upcoming | Same traces, independent truth, multiple scenario/seed clusters |
| Publishable effectiveness evidence | Blocked | No independently validated cohort or physical actuation evidence |

Run:
```bash
python -m unittest discover -s tests -p 'test_durable_admission_benchmark.py' -v
python -m research_contracts.benchmark_durable_admission --repeats 30 --seed 20261120 --output /tmp/omni-paired-30.json
python -m unittest discover -s tests -v
```

Known limitations: cold-start and sequential within-process timings; seeded order does not control OS scheduling, disk cache, thermal state, or independent-process contention. Thirty repetitions do not imply statistical significance. Fixture CSVs, 3-peer sanity checks, five-iteration microbenchmarks and offline formulas remain non-publishable.
