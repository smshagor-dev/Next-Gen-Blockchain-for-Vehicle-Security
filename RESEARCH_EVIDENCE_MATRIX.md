# Research evidence status (2026-11-14)

| Area | State | Evidence and next step |
|---|---|---|
| Authenticated hardware ingress and actuation isolation | Partial | Draft PR #101 contains hardening and regression harnesses; full production loopback, physical interlocks and emergency stop remain unverified |
| Ledger crash consistency and finality | Partial | Issues #91 and #95 remain distinct from proof of distributed finality; execute process-crash and restart recovery on actual save path |
| Evidence-gated V2X admission | Partial | Specify externally sourced incident universe, authorization invariants, matched baselines and formal counterexamples |
| Authentic VeReMi NextGen / CAN provenance | Blocked | No independently verified raw datasets and incident-ground-truth manifest recorded in this change |
| Independent attack experiments | Blocked | No publishable multi-seed replay, spoof, insider, DoS or fault experiment generated in this change |
| Paired statistical comparison | Partial | `experiments/v2x/paired_incident_analysis.py` computes confusion counts and exact two-sided McNemar on aligned incident IDs; 8 synthetic regression cases authored (including 2,000 discordances, balanced pairs, malformed CSV); new cases not executed in repository because GitHub DNS checkout failed; CI not verified |
| Runtime scaling / uncertainty | Upcoming | Add independent scenario seeds, clustered uncertainty intervals, effect sizes, throughput, CPU/RAM, latency and source digests |
| Paper and numeric claims | Blocked | Do not use fixture CSVs, 3-peer sanity checks, 5-iteration microbenchmarks or offline formulas as main results |

This matrix records engineering progress, **not scientific validation**. Exact McNemar assumes independent paired incident units. Repeated frames from one incident must be grouped, not treated as independent observations. A sample size of 30 does not itself imply significance. No physical hardware or external dataset access is claimed.

## 2026-11-14 follow-up

- Paired incident analyzer now validates exact four-column schema and rejects ragged CSV before scoring; exact McNemar tail uses integer binomial recurrence for large cohorts rather than floating-point combinatorial sums.
- Four additional synthetic regression cases committed; repository execution remains blocked by GitHub DNS resolution in the execution environment. These are **not experimental observations**.
- Upcoming: run repository tests, verify independent incident provenance and cluster independence, add cluster-aware effect-size confidence intervals, and only then run matched authentic baselines.

## 2026-11-14 cluster uncertainty extension

- Added `experiments/v2x/clustered_effect_analysis.py`: deterministic cluster-resampled paired accuracy difference in percentage points and percentile confidence interval, requiring explicit independent cluster IDs and exact binary incident schema. Cluster resampling preserves within-cluster dependence and unequal cluster sizes.
- Added `tests/test_clustered_effect_analysis.py` with six synthetic contract scenarios (determinism, uniform improvement, single-cluster rejection, duplicate incident rejection, invalid labels and schema rejection).
- Independently executed six equivalent local Python contract tests: **6/6 passed**; committed repository tests and CI are **not yet executed**, so this is implementation verification only, not experimental evidence.
- Remaining methodological limits: percentile bootstrap can under-cover with few clusters; define independent cluster unit a priori, obtain authentic source provenance, record scenario-level seeds and paired baseline outputs, and consider BCa or hierarchical sensitivity analysis.
- **Next code task:** independent incident provenance manifest and strict join against captured predictions, including missing detections as false negatives; then validate on authentic VeReMi NextGen/CAN data with matched splits.
