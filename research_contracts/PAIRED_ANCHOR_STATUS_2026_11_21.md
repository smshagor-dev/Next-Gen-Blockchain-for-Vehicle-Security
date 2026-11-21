# Research validation matrix — paired replay-anchor analysis (2026-11-21)

| Area | State | Evidence / limitation |
|---|---|---|
| Prior synthetic protocol-seed aggregate model | Partial | PR #165; exact-checkout tests not yet verified |
| Per-incident common-random-fault pairing | Implemented, unverified | `paired_anchor_analysis.py` uses identical seeded faults across all three protocols |
| Binary paired risk difference | Implemented, unverified | Counts discordant incident pairs, rejects missing/duplicate pairs |
| Edge-case and alignment regression tests | Implemented, unexecuted | `test_paired_anchor_analysis.py` |
| Seed-cluster uncertainty / effect sizes | Upcoming | Incident dependence prevents naive iid confidence intervals; use seed-cluster bootstrap and sensitivity |
| Actual receiver / external authenticated anchor | Blocked | Model uses in-memory anchor; no real authority, hardware, or actuator evidence |
| Real VeReMi NextGen / CAN data | Pending | No authentic dataset outcome in this branch |
| Ledger finality / physical emergency safety | Blocked | No distributed-finality or physical safety claim |
| Publishable evidence | Not ready | Synthetic deterministic mechanism checks are not main research results |

Reproduce after checking out this stacked branch:
```bash
python -m unittest discover -s tests -p 'test_paired_anchor_analysis.py' -v
python -m unittest discover -s tests -p 'test_anchor_failure_tradeoff.py' -v
python -m research_contracts.paired_anchor_analysis --seeds 30 --incidents 1000 --output /tmp/paired_anchor_incidents.csv
python -m unittest discover -s tests -v
```

**Hypotheses:** Relative to SQLite-only, reserve-first prevents replay after a locally restored valid historical snapshot if its independent reservation persists; it can reject legitimate retry after a failed local commit. These are falsifiable protocol-model predictions, not measured security effectiveness. No statistical significance follows from choosing 30 seeds.

**Next code task:** Execute exact-checkout tests and paired run, fix any integration failures, implement seed-cluster bootstrap uncertainty and independent subprocess crash/fault injection. Do not merge this stacked draft before ancestors #160–#165 pass review.
