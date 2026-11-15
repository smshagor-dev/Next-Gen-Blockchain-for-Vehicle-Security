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

## 2026-11-15 — isolated deterministic incident replay (draft)

- **Implemented:** `experiments/v2x/replay_isolated_commands.py` accepts bounded JSONL incident claims, validates exact schema and boolean gates, rejects duplicate IDs, and emits deterministic input-hash-bound verdicts. No socket, CAN, serial or ECU interfaces are used. Network-originated brake/steer/throttle/reset never produce simulated alert admission. Local emergency overrides every remote request.
- **Tests authored:** `experiments/v2x/test_replay_isolated_commands.py` checks exhaustive 16 gate combinations x 4 forbidden commands, 16 alert gate combinations, duplicates, malformed schema, boolean coercion, reproducibility and empty evidence classification. **Not yet executed** against a checked-out repository because local GitHub DNS resolution is unavailable.
- **Status:** simulation-only safety isolation **partial**, no production bridge integration; independent incident experiments **blocked** pending authentic publisher data, independent truth and paired baseline/candidate outputs. This is not publishable effectiveness or physical safety evidence.
- **Next:** execute tests in GitHub Actions, connect independently attested world-incident truth and bounded receiver capture to this driver, compare preregistered baseline policies under identical splits and cluster-level seeds.

## 2026-11-15 — Independent truth join for isolated replay (draft)

- **Implemented:** `experiments/v2x/join_replay_truth.py` joins source-supplied incident IDs and independent binary annotations to the simulation-only replay decisions; requires a caller-pinned replay-input SHA-256, strict schema and unique IDs, and rejects unknown decisions, malformed counts and duplicate JSON keys. Missing replay decisions are explicitly treated as negative predictions (thus false negatives when ground truth is positive); independent cluster IDs are retained for later clustered comparisons.
- **Validation:** Ten synthetic adversarial unit cases authored and equivalent locally constructed Python module passed 10/10 with `python -m unittest -v test_join_replay_truth`. Exact GitHub repository execution and CI have not yet been verified. No authentic dataset was processed.
- **Status:** Evaluation adapter **partial**; real world-truth independence, capture completeness, authentic VeReMi NextGen/CAN ingest, matched baseline experiments and physical emergency-stop evidence **blocked**. This is not publishable efficacy evidence.
- **Next code task:** verify exact pushed tests in CI, bind replay decisions to independently authenticated capture-interval receipts and pre-registered scenario/seed manifests, then execute genuine matched incident-level baseline trials.
