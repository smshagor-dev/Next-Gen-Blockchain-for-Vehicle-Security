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

## 2026-11-15 — safety-isolated remote command reference model (draft PR)

| Workstream | State | Verifiable evidence and limitations |
| --- | --- | --- |
| Remote command vs local safety separation | IMPLEMENTED, CI PENDING | `experiments/v2x/model_command_authority.py` enumerates 64 Boolean authority states and 256 remote requests; remote brake, steering and throttle are categorically denied. Only an authenticated, fresh, evidence-admitted network alert with network availability and no local emergency latch may relay. |
| Local emergency dominance | IMPLEMENTED, CI PENDING | Local emergency sets a latch independently of network state; only a separately authorized **local** reset can clear it. Remote requests never mutate the latch. 15 deterministic tests include state enumeration, partition, replay and reset transitions. |
| Formal safety interpretation | PARTIAL | Finite-state exhaustive reference model is an executable bounded invariant check, **not** a formal proof of production `hardware_bridge.py`, embedded firmware, CAN interlocks or external safety standards. Integration/refinement proof and hardware fault injection are missing. |
| Genuine experimental results | BLOCKED | No physical local emergency circuit or independent network capture, original VeReMi/CAN dataset labels, independently replicated multi-seed effect estimates. No publication claims from model enumeration. |

Next: wire the reference model's deny-by-default network-only authorization decision into a simulated adapter and verify no path to CAN/ECU actuation. Separately obtain hardware test access and independent data provenance before manuscript efficacy claims.

## 2026-11-15 — simulation-only command boundary (stacked draft)

- Completed in draft: memory-only alert adapter, strict evidence context, bounded messages, independent local emergency/reset and synthetic exhaustive action/context checks. No CAN, serial or vehicle actuator interface.
- Partial: four synthetic regression methods and dedicated CI workflow; CI and full repository regressions not yet verified. Depends on draft PR #113.
- Blocked: physical ECU safety and interlocks, publisher-authenticated VeReMi/CAN data, independent trial provenance, matched multi-seed outcomes, ledger finality.
- Upcoming: run CI, add network-free incident replay driver and authentic baseline experiments. Synthetic tests are NOT publishable efficacy evidence.
