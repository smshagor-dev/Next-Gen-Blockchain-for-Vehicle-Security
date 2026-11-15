# Research evidence status (2026-11-14)

| Area | State | Evidence and next step |
|---|---|---|
| Authenticated hardware ingress and actuation isolation | Partial | Merged PR #101 contains hardening and regression harnesses; full production loopback, physical interlocks and emergency stop remain unverified |
| Ledger crash consistency and finality | Partial | Issues #91 and #95 remain distinct from proof of distributed finality; execute process-crash and restart recovery on actual save path |
| Evidence-gated V2X admission | Partial | Specify externally sourced incident universe, authorization invariants, matched baselines and formal counterexamples |
| Authentic VeReMi NextGen / CAN provenance | Blocked | No independently verified raw datasets and incident-ground-truth manifest recorded in this change |
| Independent attack experiments | Blocked | No publishable multi-seed replay, spoof, insider, DoS or fault experiment generated in this change |
| Paired statistical comparison | Partial | `experiments/v2x/paired_incident_analysis.py` computes confusion counts and exact two-sided McNemar on aligned incident IDs; synthetic regression cases authored (including 2,000 discordances, balanced pairs, malformed CSV); new cases not executed in repository because GitHub DNS checkout failed; CI not verified |
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

## 2026-11-15 — pinned offline CAN recording normalization

| Area | Status | Evidence / next |
| --- | --- | --- |
| CAN frame normalization | Implemented; CI verification pending | New `experiments/v2x/normalize_can_recording.py` validates external SHA-256 pin, strict unlabeled timestamp_us/CAN ID/byte-length/data schema, 11/29-bit identifier range, monotonic microsecond timestamps, CAN/CAN-FD payload lengths, frame and byte bounds; outputs deterministic normalized frames and a SHA-256 manifest |
| CAN adversarial fixture regression | Authored; CI verification pending | 17 synthetic tests for zero-byte frames, payload mismatches, tamper, labels in source, invalid identifiers, timestamps, ragged CSV, frame bound, deterministic digest and empty captures. **Not actual CAN dataset observations** |
| Source archive authenticity | Blocked | External pin is operator supplied; no independently downloaded publisher archive, trusted checksum, dataset license or source metadata in this run. Previous PR #110 separately audits provenance and disjoint splits |
| Incident truth and authentic V2X/CAN attacks | Blocked | Adapter intentionally never infers attack labels from CAN IDs or frame content. Requires separately authenticated annotation source and recording-group-disjoint splits before scientific inference |
| Physical hardware safety | Blocked | Offline CSV only; no CAN interface, vehicle actuator or independent emergency-stop witness exercised |
| Next | Upcoming | Validate genuine licensed CAN source parser against publisher schema, link recording-level annotations and source provenance, then compare methods on identical disjoint recordings with cluster-aware uncertainty |

Test command: `PYTHONPATH=experiments/v2x python -m unittest discover -s experiments/v2x -p 'test_normalize_can_recording.py' -v`. Source pins prove byte integrity relative to operator supplied hash, **not publisher authenticity**. No synthetic fixture is a publishable main result.

## 2026-11-15 — strict replay parser hardening (draft)

- **Implemented:** replay JSONL now rejects duplicate fields (including authentication/evidence gates and incident IDs), non-finite JSON constants and invalid UTF-8 before any decision is produced. This closes parser ambiguity that could cause different replay tools to interpret different gates from identical bytes.
- **Regression coverage:** five adversarial/valid-input cases added to `test_replay_isolated_commands.py`; CI not yet confirmed. This is a synthetic parser-integrity check, **not** attack-detection effectiveness evidence.
- **Remaining:** independent truth join PR #117, pinned-trial PR #118 and policy-output cross-check PR #119 remain separate pending review. No authentic CAN/VeReMi dataset, physical safety or publication-ready comparison is established here.
- **Next code task:** integrate complete incident universe and capture receipts after validating pending PRs, then run identical held-out baseline/candidate cohorts.
