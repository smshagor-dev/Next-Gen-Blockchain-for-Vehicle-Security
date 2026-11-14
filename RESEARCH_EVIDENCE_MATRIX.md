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

## 2026-11-14 — pinned trial manifest + capture exporter (issue #92 follow-up)

- **IMPLEMENTED (DRAFT, NOT YET VALIDATED):** New experiments/v2x/capture_export_producer.py creates a canonical trial plan bound to experiment/scenario/seed/split, window, cluster identifier, matched baseline/candidate identifiers and independent world CSV digest. It uses exclusive file creation, file fsync and POSIX directory fsync. Printed SHA-256 requires external pre-run pinning; creating the file itself does not establish pre-registration.
- **IMPLEMENTED:** Seal requires a previously pinned manifest digest, two distinct HMAC secrets and validates source universe, scope, capture timestamp boundaries, unknown incidents, replayed nonces and unverified relays. Signed export and interval receipts interoperate with the existing conservative consumer. Explicit capture_complete is a hub self-assertion, never automatically inferred.
- **TESTS ADDED, EXECUTION PENDING:** experiments/v2x/test_capture_export_producer.py covers real subprocess CLI plan/seal, zero-capture false negatives, tamper, identity, time, replay, credentials and output overwrite. Dedicated Ubuntu Python 3.11 workflow compiles code and executes producer, interval and world-join suites. Command: PYTHONPATH=experiments/v2x python -m unittest discover -s experiments/v2x -p test_capture_export_producer.py -v. No test success claimed before actual CI verification.
- **PARTIAL:** Distinct receipt files are individually fsynced and exclusive, not one atomic two-file commit. An interrupted second write may leave an unmatched first receipt; consumers must require both. Signed completion proves only the hub assertion, not uninterrupted sensing, independent annotations, independent cluster identity or hardware safety.
- **BLOCKED:** Independent pre-registration/time witness; source-authenticated production receiver export and complete coverage witness; genuine VeReMi NextGen/CAN independent incident truth and matched baseline trials; physical emergency-stop and power-cut evidence. Synthetic fixtures remain NON-PUBLISHABLE main results.
- **UPCOMING:** Execute PR CI, fix regressions, anchor manifests and real capture evidence with independent provenance and run preregistered matched-split incident campaigns.
