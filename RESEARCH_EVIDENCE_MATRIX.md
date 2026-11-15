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


## 2026-11-15 — externally pinned held-out replay trial (draft PR)

| Workstream | State | Evidence and limitation |
| --- | --- | --- |
| Replay manifest binding | Implemented, validation pending | `verify_pinned_replay_trial.py` checks an out-of-band manifest SHA-256, exact trial identity and held-out split, UTC interval ordering, and byte-level digests of replay input, truth, capture and policy |
| Decision consistency | Implemented, validation pending | Rejects duplicate IDs/JSON keys, unknown verdicts, inconsistent counts and replay input digest mismatch |
| Synthetic regressions | Authored, CI pending | 12 isolated adversarial unit cases and dedicated GitHub Actions workflow; do not treat as scientific efficacy results |
| External preregistration | Blocked | An operator-supplied hash is not proof of independent timestamping or preregistration |
| Capture and ground truth authenticity | Blocked | No independent uptime proof, publisher-authenticated dataset or independent annotation attestation |
| Matched experimental cohorts | Upcoming | Integrate with independent truth join in PR #117 after review; verify incident coverage and baseline/candidate symmetry before statistical analysis |

**Next code task:** connect pinned trial verification to independent truth join and capture-interval receipt with consistent incident universes, then run verified publisher-sourced held-out multi-seed cohorts. No physical ECU tests or publishable efficacy claims are implied.

## 2026-11-15 — PR #118 Security Baseline regression follow-up

- **Confirmed failure:** Security Baseline run 43685231526 failed in `tests.test_hardware_bridge_security.BridgeSecurityTests.test_ecu_interlock_is_rechecked_before_output`; its expectation that ECU `_init_transport` is called contradicts the deliberately disabled CAN/serial output introduced by earlier safety hardening.
- **Implemented:** replaced obsolete test with explicit regression checks that the ECU transport is never initialized, forced legacy gateway flags do not forward to CAN/serial output, and private output helpers fail closed.
- **Validation:** original pinned replay workflow 43685231640 passed before this correction; changed Security Baseline regression is **not yet revalidated** as of this entry.
- **Scientific limitation:** these are mocked software safety checks, not tests on a physical ECU, emergency control circuit, or independent safety certification.

## 2026-11-15 — remote safe-stop command isolation (draft)

| Workstream | State | Evidence / limitation |
| --- | --- | --- |
| Remote actuator authorization | Implemented on draft; verification pending | `SafeModeActuatorDispatcher` no longer transmits signed `COMMAND` envelopes to Arduino/Pi merely because ledger safe mode is active and bench gate is armed. This closes the sender-only authorization gap; remote actuator transport is deliberately disabled |
| ECU output | Existing fail-closed boundary retained | `ECUCommandGateway` still refuses CAN/serial output |
| Regression coverage | Authored, unverified | Five mocked tests cover serial, TCP, environment opt-in, ECU direct helpers and emergency/sensor combinations. Run `PYTHONPATH=. python -m unittest discover -s tests -p 'test_network_actuation_isolation.py' -v` and full security suite before merge |
| Local physical emergency stop | Not verified | Software code does not test physical emergency circuit, persistence across power loss or actuator isolation |
| Formal-model conformance | Partial | Draft #130/#131 assume no network actuation; this change aligns production command *output* boundary, but does not prove full temporal conformance or independent receiver-side authorization |
| Scientific efficacy | Blocked | No authentic V2X/CAN held-out trials, independent attack truth, HIL or measured effect sizes added |

**Next:** run exact CI and investigate any legacy tests that expect unsafe network stop delivery; verify signed telemetry ingestion remains unaffected. Then add differential production/model traces and externally witnessed power-loss emergency tests before considering physical command output. Never use these mocked regressions as main scientific results.


## 2026-11-15 — fail-closed network actuator regression reconciliation (draft PR #132)

- **Implemented:** replaced the stale armed-bench regression that expected signed Pi commands and ECU forwarding with a two-state (armed/unarmed) check asserting no Pi `sendall`, Arduino `write`, or ECU dispatch even with both legacy environment flags enabled. This tests the actual safety-isolated production dispatcher rather than treating a MAC as receiver-side interlock proof.
- **Evidence:** updated test committed as `9cb99ae17a4ce6ee17a9aaeeeea695e2c59c5090`; source inspection confirmed the dispatcher returns false for both network send paths. Exact repository tests **not executed**: local `git ls-remote` failed DNS resolution for github.com. CI **not verified**.
- **Command once checkout is available:** `python -m unittest tests.test_hardware_bridge_security -v` followed by `python -m unittest discover -s tests -p 'test_*.py'`.
- **Limit:** no physical actuator, CAN, emergency circuit, authenticated runtime capture, or external dataset was tested. This is engineering regression coverage, **not publishable scientific evidence**.
- **Next:** verify CI and full integration regression on PR #132, implement differential trace conformance against the abstract emergency-state model, and independently witness physical emergency precedence before any hardware authorization claim.

## 2026-11-15 — stateful production dispatcher conformance (draft PR #132)

- **Implemented on draft branch:** `tests/test_stateful_network_isolation_conformance.py` exercises 1,024 deterministic two-step combinations (2,048 transitions), including emergency state, sensor failure, safe-mode alarm, bench arming and simulated dispatcher restart. It asserts production `SafeModeActuatorDispatcher` never writes to Pi/Arduino sockets or delegates to the ECU gateway. An additional test checks eight legacy ECU mode/arming/internal-init combinations.
- **Validation:** GitHub commit created; exact repository test execution and CI **not yet verified** because the execution container cannot resolve github.com. Run `python -m unittest tests.test_stateful_network_isolation_conformance -v` from the repository root (or `python -m unittest discover -s tests -p 'test_stateful_network_isolation_conformance.py' -v`).
- **Evidence classification:** deterministic mocked software trace regression only; **not** an independent safety proof, physical interlock test, real network latency measurement, or publishable V2X efficacy result.
- **Next:** validate the draft PR against current main, execute integration tests with real localhost authenticated ingress, then independent incident-ground-truth dataset trials and matched baseline comparisons. Keep draft until verified.
