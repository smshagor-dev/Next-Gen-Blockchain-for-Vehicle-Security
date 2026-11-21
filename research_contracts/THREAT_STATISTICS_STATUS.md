# Threat statistics evidence status — 2026-11-18

| Workstream | Status | Evidence / next action |
|---|---|---|
| Paired synthetic incident generator | Partial | `bench_correlated_group_threats.py`; independent validation pending |
| Seed-cluster uncertainty estimator | Implemented, repository unverified | `paired_threat_statistics.py`; local equivalent 4/4 tests passed, repository suite pending |
| Paired truth and observation consistency | Implemented, repository unverified | `test_paired_threat_statistics.py`; test missing, duplicate, and mismatched pairs |
| Authentication-only, sender quorum, strict group and dissent-tolerant policies | Partial | Re-run all policies on identical seeds, splits and attack workloads |
| Physical interlocks / emergency stop | Blocked | No independent HIL or physical interlock verification; preserve local emergency control |
| Production authenticated TCP DoS and replay evaluation | Pending | Non-actuating loopback fault campaign and resource metrics |
| VeReMi NextGen and CAN dataset provenance | Blocked | Need independently verified source files, hashes, licenses and scenario mapping |
| Coordinated compromise, correlated faults and ablations | Partial | Synthetic scenario generator only; no validated effect estimates |
| Publication-grade comparisons | Blocked | Multiple independent runs, authentic datasets, latency/resource results, effect sizes and limitations |
| Ledger finality | Blocked | Mock contract cannot establish external consensus finality |

## Statistical interpretation

The estimator reports candidate-minus-baseline risk differences conditional on ground-truth incident class. It resamples whole simulation seeds, not individual incidents. Percentile bootstrap intervals are descriptive and may be unstable with few independent seeds. Neither `n >= 30` nor an interval excluding zero automatically establishes practical significance, causal generality, or field safety. Fixture CSVs, 3-peer poisoning checks, five-iteration microbenchmarks and offline communication formulas are **not publishable main results**.

## Validation

`python -m unittest discover -s tests -p 'test_paired_threat_statistics.py' -v`

`python research_contracts/paired_threat_statistics.py combined_seeded_incidents.csv --baseline authentication_only --candidate dissent_tolerant_groups`

No dataset or result CSV has been committed or claimed. Keep PR #141 draft until the full repository tests and independent review are complete.
