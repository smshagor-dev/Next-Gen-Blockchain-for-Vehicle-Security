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


## 2026-11-15 — matched, signed held-out capture comparisons (draft PR; issue #92)

| Research item | Status | Evidence / limitation |
| --- | --- | --- |
| Baseline/candidate capture matching | Implemented, GitHub CI pending | \`compare_matched_capture_trials.py\` calls existing \`attested_interval_join.evaluate_interval\` for BOTH methods using the same independent-world incident universe and operator-pinned held-out test interval |
| Source integrity and receipt checking | Implemented | Requires four exact SHA-256 pins (world, both raw hub captures, expected window), two export HMAC receipts, two interval HMAC receipts, and claim of complete capture for the exact test window; never filters a method's missing incidents |
| Paired outcomes | Implemented | Produces deterministic \`paired_incidents.csv\` in \`incident_id,cluster_id,truth,baseline,candidate\` schema, TP/TN/FP/FN, unreceived incident counts and candidate-minus-baseline accuracy difference in percentage points |
| Cluster validity | Partial | One scenario/seed is **one cluster**, not an independent observation per incident. Estimating uncertainty needs multiple genuinely independent, source-verified clusters |
| Synthetic adversarial validation | Local contract checks complete; repository CI pending | 18/18 local Python tests passed with reconstructed upstream dependencies; pushed new source and test Git blob hashes match locally tested files. Validates empty-but-signed capture, missing positives, false positives, duplicate rows, nonce replay, forged HMAC, incomplete receipts, wrong trial/window, out-of-window timestamps, unverified relay, malformed truth and pins |
| Authentic VeReMi NextGen/CAN efficacy | Blocked | No independently publisher-verified raw archives, trusted annotation producer, physical capture proof or real multiple-cohort experiment in this PR |
| Statistical inference and manuscript claims | Blocked | Per-trial descriptive results are not a population estimate or significance test; fixture results are NON-PUBLISHABLE main research evidence |

**Next code task:** integrate reviewed per-trial paired exports across independently recorded scenario/seed cohorts, require external publisher source pins and group-disjoint split manifests, and only then run cluster-aware bootstrap/permutation sensitivity and measured runtime network/CPU/RAM. Do not infer physical safety, capture continuity, preregistration or finality from HMACs or SHA-256 alone.

## 2026-11-15 — independent V2X trial-cluster aggregation (draft)

| Item | State | Evidence / limitation |
| --- | --- | --- |
| Pinned multi-cohort comparison | Implemented, review pending | New `experiments/v2x/aggregate_pinned_cohorts.py` checks externally pinned manifest SHA-256 and every paired CSV digest; refuses duplicate trial IDs, reused cluster IDs or declared source groups |
| Descriptive effect and uncertainty | Implemented, synthetic only | Reconstructs paired confusion counts and candidate-minus-baseline accuracy, cluster-resampled 95% percentile interval with deterministic seed; never interprets n>=30 as significance |
| Tests | Local checks passed; GitHub CI pending | 12/12 synthetic contract tests passed in isolated Python, including tamper, duplicate source group, duplicate incident, nonbinary truth, missing trial and one-cluster rejection. Exact pushed repository suite not yet verified |
| Scientific provenance | Blocked | A source-group string and operator SHA-256 pin are assertions, not publisher authentication, independent ground truth or proof of preregistration |
| Independent efficacy trials | Blocked | No authentic VeReMi NextGen/CAN observations, independent multi-seed experiments, vehicle hardware or external lab evidence in this change |
| Upcoming | Next code task | Wire reviewed PR #121's paired capture outputs into cohort manifest creation; add independent publisher source checks, controlled attack cohorts and runtime measurements |

This is research infrastructure, **not a publishable efficacy result**. The percentile interval can under-cover with few independent clusters and cannot establish a causal effect. Source-group disjointness is checked only against declared identifiers.

## 2026-11-15 — duplicate-member hardware transport ambiguity (draft PR)

- **Implemented:** recursively reject repeated JSON object members in raw authenticated hardware envelopes before MAC verification, including repeated `mac`, `device_id` and nested telemetry measurements. This removes first/last-wins interpretation ambiguity between parser implementations without changing wire format or local emergency-stop control.
- **Regression cases:** four new in-memory adversarial tests cover valid-MAC duplication, nested payload duplication, device-identity override and rejection without replay-nonce consumption. Test command: `python -m unittest tests.test_hardware_bridge_security -v` (repository CI pending).
- **Evidence class:** protocol-parser hardening only. No independent live attack measurement, physical actuator tests, or publishable efficacy results. `AGENTS.md` not present at repository root.
- **Next:** measure authenticated socket ingest under bounded malicious framing/reconnect traffic with separate CPU/RAM/latency counters and pinned experiment artifacts; validate producer/consumer interoperation on independent held-out V2X captures.

## 2026-11-15 — real local socket admission saturation (draft, not scientific main results)

| Item | State | Evidence / limitation |
| --- | --- | --- |
| Saturated admission boundedness | Locally measured | `tests/test_admission_runtime.py` uses actual OS socket pairs, two occupied worker slots and 100 overload attempts; confirms 100 rejects, peak active 2, slot recovery after release |
| Worker exception recovery | Locally tested | Synthetic worker fault raises in daemon thread; admission slot is released, although Python emits an uncaught thread exception |
| Five-replicate runtime measurement | Locally measured | `experiments/v2x/bench_local_admission_saturation.py` with 4 blocked workers, 1,000 rejected socketpair attempts per replicate, 5 replicates. Median per-rejection dispatch times (microseconds): 1.498, 1.421, 1.416, 1.399, 1.392; per-replicate p99: 7.577, 4.062, 6.117, 11.472, 32.423. CPU process time per batch (ms): 9.924, 7.372, 8.020, 12.552, 16.386. Raw observation: `experiments/v2x/observations/local_socketpair_admission_2026-11-15.json` |
| Exact repository CI | Pending | New `bounded-hardware-ingress-runtime.yml` exercises the repository test against actual mainline module. Local tests used a reconstructed copy of the mainline module and passed 2/2; no CI pass claimed |
| Full network ingress / MAC / ledger / DoS | Upcoming | This benchmark measures only admission dispatcher under sequential overload, not real TCP, concurrent attacker connections, authentication, ledger throughput or end-to-end latency |
| Independent vehicle hardware safety | Blocked | No vehicle, CAN interface, physical emergency stop, hardware-in-the-loop, or independent laboratory access. Results are **NON-PUBLISHABLE main evidence** |

**Next implementation:** run end-to-end loopback TCP with authenticated and invalid hardware envelopes, verify global budgets and absolute deadlines, then perform isolated process CPU/RAM/latency measurements with several independent seeds and explicit threat scenarios. Never infer publication-level significance from n >= 30.

## 2026-11-15 — authenticated telemetry observation-time integrity (draft)

| Item | State | Evidence and limitation |
| --- | --- | --- |
| Observation timestamp admission | Implemented; CI pending | `hardware_bridge.to_telemetry` now requires an explicitly supplied canonical UTC ISO-8601 observation timestamp, rejecting absent, naive, non-UTC, malformed and oversized values instead of inventing current ingestion time |
| Regressions | Authored; execution pending | `tests/test_hardware_observation_timestamp.py` covers Z/UTC normalization, missing timestamp, invalid offsets and malformed dates; command: `python -m unittest discover -s tests -p 'test_hardware_observation_timestamp.py' -v` |
| Hardware safety | Unchanged, partial | No changes to independent physical emergency control or fail-closed CAN/serial gateway. Signed transport freshness is **not** sensor observation freshness |
| Dataset evidence | Blocked | No authentic independently sourced VeReMi/CAN data or independent timestamp attestation; device can still lie about observation time |
| Next code task | Upcoming | Enforce policy-defined maximum observation age relative to independently verified reception time, with bounded clock-skew tests and real TCP-loopback latency/DoS trials |

This is a provenance-integrity engineering correction, not a new cryptographic primitive or publishable research efficacy result. No actual hardware experiment was performed.

## 2026-11-15 — host-reception observation age policy (stacked on draft #125)

| Area | State | Evidence / next step |
| --- | --- | --- |
| Authenticated telemetry observation freshness | Implemented, unverified | `hardware_observation_freshness.py` rejects signed sensor timestamps older than 15 seconds or more than 2 seconds in the future by default, with bounded operator configuration; called before ledger writes for BOTH Arduino and Pi TCP paths |
| Local emergency / ECU isolation | Preserved in code | No new remote CAN/serial actuation capability; no physical hardwired interlock test |
| Synthetic contract tests | Authored, execution blocked | Twelve tests for stale/future boundary, malformed timestamps, naive/non-UTC host clock, invalid policy and fractional seconds; `PYTHONPATH=. python -m unittest discover -s tests -p 'test_hardware_observation_freshness.py' -v`. GitHub raw checkout from this execution environment failed due to DNS; CI pending. Do not claim tests passed |
| Device clock trust | Blocked | MAC authenticates a device's timestamp *claim*, not sensor uptime, synchronization, or true measurement time. Host UTC wall clock can jump; independent hardware time and physical event trace needed |
| Independent V2X/CAN efficacy | Blocked | No authentic publisher-verified incident dataset, multi-seed attack efficacy or matched-baseline observation in this change |

**Next code task:** capture host ingress UTC once at first complete signed-frame receipt and bind it to the exact verified envelope, rather than sampling the clock immediately before each ledger mutation; then execute real TCP loopback under delayed ledger operations, replay/future skew and wall-clock adjustments, and independently measure rejection rates/CPU/RAM/latency. This policy is a software safety guard, not publishable scientific efficacy evidence.

## 2026-11-15 — host ingress clock binding (stacked draft, issue #92)

| Research area | Status | Evidence / next step |
| --- | --- | --- |
| Authenticated telemetry freshness at receive boundary | Implemented, CI pending | New `hardware_ingress_clock.py` samples host UTC and monotonic time immediately after bounded TCP recv / Arduino read, before MAC verification; signed observation age checked at ingress and again before ledger mutation using monotonic elapsed time |
| Delayed queued frames / clock rollback | Synthetic regression authored, CI pending | 14 tests cover delayed processing, stale/future observations, invalid monotonic values, boundary conditions, and bounded policy. No vehicle or network timing result claimed |
| Physical interlocks and local emergency | Blocked physical validation | No ECU actuation change; fail-closed ECU output remains. Local hardwired emergency control has not been independently witnessed |
| Authentic independent V2X/CAN evidence | Blocked | No verified raw dataset, independent annotation, or matched multi-seed effectiveness result in this change |
| Runtime scaling and manuscript | Upcoming | Next: real localhost TCP with authenticated multi-frame bursts, queue-delay histograms, CPU/RAM and bounded-DoS scenarios; then independently sourced matched baselines |

**Limitations:** Host software receive UTC is not a trusted hardware timestamp; fragmented frames use the receive that completes the frame, and clock synchronization is not attested. The monotonic elapsed clock prevents *processing delays* from refreshing an old observation, but does not establish truth of a compromised device's signed clock. This is safety engineering evidence only, not publishable original efficacy research.

## 2026-11-15 — real localhost TCP saturation protocol (draft, issue #92)

| Area | State | Evidence / next action |
| --- | --- | --- |
| Bounded TCP admission | Implemented on main; real loopback experiment added in draft | `experiments/v2x/bench_tcp_loopback_admission.py` creates actual IPv4 localhost TCP connections, fills worker slots, rejects a bounded overload, waits for release and verifies admission recovery |
| TCP runtime measurements | Code implemented; CI pending | Measures rejection round-trip median/p95, wall/process CPU seconds, Python-traced peak allocations, and overload attempts per elapsed second; raw per-repetition JSON preserved as a CI artifact |
| Socket experiment regressions | Authored, execution pending | Three test methods cover one/four workers and invalid parameter limits; dedicated workflow runs actual TCP sockets on GitHub runners |
| Local execution | Blocked transiently | Exact GitHub checkout failed in local container: `Could not resolve host: github.com`. Do not claim local pass or numerical measurements |
| Authentic V2X/CAN and HIL safety | Blocked | TCP admission alone does not test MAC/replay validation, end-to-end authenticated telemetry, physical emergency interlock, publisher data or vehicle network behavior |
| Research inference | Blocked | Repeated microbenchmarks on one host are engineering diagnostics, NOT independent incident-level research trials or publishable V2X efficacy |

**Next:** integrate authenticated telemetry TCP loopback from reviewed PR #125–#127 once validated; record actual end-to-end reception-to-ledger timing, malformed/replay rejection and process RSS under matched attack loads, then independent publisher-verified incident experiments. Existing PR #124 measures socketpair admission and is not duplicated here: this run uses actual TCP connections and includes recovery.

## 2026-11-15 — numeric overflow and signed metadata boundary (draft)

| Area | Status | Evidence and next step |
| --- | --- | --- |
| Authenticated telemetry parser fail-closed behavior | Implemented in draft; CI pending | `hardware_transport_security.py` catches huge JSON integer-to-float overflow as `HardwareTransportError`, and rejects non-string event, source and observation timestamp rather than stringifying them |
| Synthetic adversarial regression | Authored, execution unverified | Seven tests in `tests/test_hardware_numeric_metadata_boundary.py`, including a valid authenticated envelope roundtrip. Dedicated CI workflow added. Exact local checkout blocked by GitHub DNS failure; do not claim test pass |
| Hardware control | Unchanged | No ECU/CAN actuation path enabled. Local emergency stop remains independent |
| Authentic experiments and scientific efficacy | Blocked | No genuine external VeReMi NextGen/CAN trial, physical interlock measurement, or independently validated attack outcomes generated |
| Next code task | Upcoming | Validate CI, integrate pending ingress freshness PRs and measure authenticated TCP loopback rejection latency, CPU/RAM, reconnect load and safe emergency isolation |

This is security engineering evidence, not publishable incident-level detection effectiveness. An enrolled malicious node can still send a syntactically valid but false reading; independently sourced truth and matched baselines are required.

## 2026-11-15 — abstract safety-invariant exploration (issue #92)

| Research dimension | Status | Evidence and limitation |
| --- | --- | --- |
| Evidence-gated remote alert admission | Implemented in **abstract** model | All authenticated, fresh, admitted-evidence gates and absence of local emergency are necessary for network alert relay |
| Local emergency dominance | Abstract model checked | Simultaneous local emergency set dominates local clear; remote reset cannot clear the emergency latch |
| Physical command isolation | Abstract model checked | Network brake, steer and throttle are blocked for every enumerated combination |
| Exhaustive finite-state exploration | Locally executed | 640 one-step input/state combinations for each of two policies; candidate: 0 violations; deliberately unsafe authenticated-command baseline: 100 violating combinations. Eight local Python tests passed |
| Production implementation refinement | Blocked | This abstract model is NOT linked to production code, does not prove temporal safety under concurrency or hardware/ECU isolation; physical emergency stop and watchdog are not independently measured |
| Original research evidence | Partial | Provides falsifiable abstract safety properties and an unsafe reference counterexample, NOT novel cryptography or publishable effectiveness metrics |
| Next | Upcoming | Extract a production adapter to the actual command-authorization decision path, check multi-step traces and crash/restart invariants, run physical interlock/HIL tests only when authorized lab access exists |

Local verification (on reconstructed standalone source identical in logic to the pushed model):
`python -m unittest -v test_check_command_authorization.py` (8/8 passed) and
`python check_command_authorization.py` (candidate 0/640; unsafe baseline 100/640).
Repository CI and production model conformance remain unverified. These are synthetic model results, NOT independent physical experiments.

## 2026-11-15 — bounded multi-step emergency/restart model (draft)

| Area | State | Evidence and next step |
| --- | --- | --- |
| Abstract emergency safety transitions | Implemented, repository CI pending | `experiments/v2x/check_emergency_state_machine.py` explores restart, sensor faults/recovery, physical emergency/reset, and gated remote commands through depth 7 |
| Bounded model verification | Local contract test passed | Isolated local Python exploration found 28 reachable state/depth pairs, 360 transitions and 0 invariant violations; 10/10 local tests passed on equivalent source. GitHub CI is not yet verified |
| Physical interlock and persistence | **Blocked** | The model **assumes** an external persistent emergency latch and trusted local reset; no physical ECU or process-crash test validates those assumptions |
| Production conformance | **Upcoming** | Build stateful differential tests against actual command dispatch path and prove reset cannot originate from network inputs |
| Scientific efficacy | **Blocked** | No independent incident dataset or matched multi-seed experiments; model checking is software specification evidence, not detection performance |

No novelty claim for cryptography, consensus finality, or physical safety follows from this abstract model. The model uses a reduced state space and no asynchronous timing or actuator dynamics. Do not cite 360 transitions as independent empirical trials.
