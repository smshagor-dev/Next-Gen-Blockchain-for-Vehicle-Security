# Seed-cluster paired inference validation matrix (2026-11-21)

| Workstream | State | Evidence / limitation |
|---|---|---|
| Paired risk difference across incident rows | Completed in code | Parent draft PR #166; exact checkout not executed |
| Seed-cluster bootstrap percentile CI | Completed in code | `research_contracts/seed_cluster_inference.py`; resamples seeds, not incidents |
| Deterministic, unequal-size, degenerate and invalid-pair controls | Local verified | `python -m unittest discover -s tests -p 'test_seed_cluster_inference.py' -v`: 4 passed in isolated local copy |
| Full repository test integration | Partial | Exact stacked branch checkout not run; must run full suite |
| Statistical inference | Partial | Descriptive percentile CI; no automatic significance claim, few-cluster coverage not validated |
| Independent subprocess crash injection | Upcoming | No real fault-boundary data |
| Authenticated trusted external anchor | Blocked | In-memory oracle cannot guarantee rollback resistance |
| Production hardware safety / emergency stop | Blocked | No physical vehicle access or hardware evidence |
| Authentic VeReMi NextGen/CAN paired baselines | Upcoming | Synthetic protocol rows are not empirical V2X effectiveness |
| Runtime scaling, CPU/RAM/latency | Upcoming | No measured deployment data |
| Journal-ready scientific claims | Blocked | Require authentic datasets, uncertainty validation, independent baselines |

Reproduction: `python -m unittest discover -s tests -p 'test_seed_cluster_inference.py' -v`, then `python -m unittest discover -s tests -v`.

Design: cluster-resample the complete set of paired incident differences within each seed; retain unequal cluster sizes in each replicate. Interval bounds are nearest-rank percentile quantiles, not coverage-corrected CIs. n>=30 is not a significance rule. This is non-actuating simulation analysis; do not present as publishable effectiveness evidence.
