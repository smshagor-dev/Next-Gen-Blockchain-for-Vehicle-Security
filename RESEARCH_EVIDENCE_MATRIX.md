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

## 2026-11-14 — capture-interval receipt validation (issue #92)

- **Implemented (draft, not main):** `experiments/v2x/attested_interval_join.py` adds a strictly schema-validated authenticated *claim* of complete hub capture interval, separately bound to capture SHA-256 and experiment/scenario/seed/split. It refuses a mismatched operator-selected interval, timestamps outside `[start,end)`, malformed/naive timestamps and incomplete signed exports. It reuses the existing independent-world join to count authenticated zero-observation intervals as false negatives, without silently trimming late relays.
- **Synthetic test evidence:** `PYTHONPATH=experiments/v2x python -m unittest discover -s experiments/v2x -p 'test_attested_interval_join.py' -v` ran in isolated local Python with a locally reconstructed mirror of `join_world_incidents.py`: **15/15 passed**. Newly pushed GitHub file content hashes matched the locally tested files; the exact repository-wide test suite and CI have **not been executed**.
- **Critical limitation:** No capture-interval attestation producer has been implemented or physically verified. A signed `capture_complete` flag is a hub's self-report, not proof of uninterrupted sensing, independently trusted annotators or a pre-registered experiment. No authentic incident-level efficacy evidence was generated; this test suite is NON-PUBLISHABLE as a main result.
- **Next:** implement exporter-side canonical interval receipts, preserve an operator-pinned trial manifest before execution, validate producer/consumer interoperation and execute matched real incident trials under independent world truth; then independent cluster-aware comparisons.

## 2026-11-15 — independent-trial statistical analysis protocol

| Workstream | Status | Evidence and next step |
| --- | --- | --- |
| Hardware authentication, emergency isolation, physical actuation | PARTIAL / PHYSICAL LAB BLOCKED | Prior hardening is separate from a trusted, independently witnessed vehicle safety test. Do not infer emergency-stop reliability from software tests. |
| Ledger durability and distributed finality | PARTIAL / INDEPENDENT FAULT LAB BLOCKED | Crash consistency and mock-contract finality are not physical/distributed finality evidence. |
| Actual policy replay and source binding | DRAFT PRS #107/#108 | Keep pending changes isolated; source pins and offline replay are not independently authenticated observations. |
| Independent cluster-level comparisons | IMPLEMENTED, CI PENDING | `experiments/v2x/analyze_independent_trials.py` accepts strict held-out test JSONL, equal baseline/candidate denominators and truth counts, unique claimed cluster/source IDs; computes paired cluster-mean accuracy difference, deterministic cluster bootstrap percentile CI and explicitly exploratory sign-flip p-value. 17 synthetic contract tests authored; **not field results**. |
| Authentic multi-seed V2X/CAN study | BLOCKED | Requires external datasets, verified source hashes/licenses, independent label provenance, genuine session receipts, complete observation windows and independent trial collection. |
| Publication | BLOCKED | No real cluster outcomes were analyzed in this change. n>=30 is NOT statistical significance. No claim of novel cryptography or physical safety. |

Next implementation: adapt authenticated real receiver captures into immutable trial-level summaries with independent witness metadata and a predeclared trial split; execute separate baseline/candidate runs with real provenance. Validate this PR's workflow before merge.
