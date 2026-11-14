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

## 2026-11-15 — label-isolated external V2X trace replay (issues #88, #92)

| Research workstream | Status | Actual implementation or blocker |
| --- | --- | --- |
| Live hardware ingress and independent emergency stop | PARTIAL / HARDWARE BLOCKED | Existing authentication, bounded ingress and simulation-only safety work remains; no physical local emergency-stop evidence in this run |
| Go-ledger durability and finality | PARTIAL / LAB BLOCKED | Prior crash consistency hardening is separate from distributed finality and power-cut experiments; no new HIL evidence |
| Matched admission-policy comparisons | IMPLEMENTED, VALIDATION PENDING | New `experiments/v2x/replay_external_incidents.py` reads an independently supplied world incident CSV and a **label-free** event trace, validates operator-pinned source hashes, fixed scenario/seed/split/window, then executes the **real** `EvidenceAdmissionGate` with quorum-2, quorum-3 and 10-km ablation on identical trace rows alongside authentication-only forwarding |
| Missing hazards and unavailable network | IMPLEMENTED, VALIDATION PENDING | Header-only event CSV is valid; positives absent from all received frames remain FN in all methods, negative opportunities remain TN |
| Replay, collusion, faulty sessions, and capacity exhaustion | IMPLEMENTED, VALIDATION PENDING | Duplicate authenticated sender/nonce frames are rejected before policy evaluation; two enrolled colluders may still fool quorum-2; a source/incident-memory limit is enforced in the real gate. 17 synthetic regression cases **executed successfully in GitHub Actions**, including a real CLI subprocess |
| Measurement | PARTIAL | Incident-level TP/FP/TN/FN, true-detection delay **from first valid received frame** (not hazard onset), local Python CPU/wall replay time, and bounded active incident state count. No live throughput or network latency claim |
| Authentic VeReMi NextGen/CAN and multi-seed independent trials | BLOCKED | No independently documented real incident truth and session authentication evidence or independently witnessed zero-observation capture interval. Synthetic test traces are NOT publication-quality main results |
| Inference, novel mechanism, paper | BLOCKED | Existing quorum logic is not a new cryptographic primitive. No independently replicated matched runs, trustworthy independent clusters, strong prior-art effects, physical safety or uncertainty/effect size. **n>=30 is not statistical significance** |

Test command: `PYTHONPATH=.:experiments/v2x python -m unittest discover -s experiments/v2x -p 'test_replay_external_incidents.py' -v`. **VERIFIED:** GitHub Actions [run #43644518930](https://github.com/smshagor-dev/Next-Gen-Blockchain-for-Vehicle-Security/actions/runs/43644518930), job #132599186356, compiled source and ran all 17 replay contract tests successfully. This proves synthetic software behavior only, not independent V2X safety or efficacy.

Next code task: integrate hub-authenticated sender/session receipt provenance into the label-free trace ingest, require independent coverage witnesses for empty intervals, then run frozen datasets and policies across genuinely independent seeds/scenarios to compare effect sizes and cluster-aware uncertainty. Never claim physical safety or research efficacy from unit fixtures.
