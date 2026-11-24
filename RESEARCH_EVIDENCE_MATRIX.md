## 2026-11-24 — #231 mainline reconciliation

Preserves the normalized JSON snapshot and strict top-level field types already on main. Adds bounded in-process traversal before canonical serialization, strict UTF-8 for raw strings, aggregate string-length budget, and exact string keys. Shared container identities are conservatively rejected; this is not a remote DoS guarantee or a guarantee against concurrent in-process mutation. Existing parser recursion/overflow handling remains unchanged. Historical entries below describe earlier branch work; exact-head CI is pending.

## 2026-11-24 — malformed Unicode hardware ingress negative controls (#231)

| Workstream | Status | Evidence and next gate |
| --- | --- | --- |
| UTF-8 boundary and canonical encoding | IMPLEMENTED ON DRAFT | Commit `83ed191`: reject lone surrogate in raw Python text as `HW_FRAME_UTF8_INVALID`; wrap canonical Unicode encoding failures as `HW_CANONICAL_ENCODING_INVALID` |
| Negative controls | AUTHORED, NOT EXECUTED | Commit `17a42df`; `python -m unittest discover -s tests -p 'test_hardware_unicode_boundary.py' -v` |
| Checkout / CI / integration | BLOCKED | Container DNS cannot resolve github.com; no repository test pass or CI success established, #231 remains draft; no merges |
| Original research efficacy | BLOCKED | No authentic incident comparisons, physical interlock evidence, or independent multi-seed results; fixture tests are non-publishable |

Next: run focused Unicode and ingress suites on exact checkout; reconcile #227/#229/#230 before merge. Preserve local emergency controls.

## 2026-11-23 — bounded hardware ingress fan-out (#231)

| Workstream | Status | Evidence / next gate |
| --- | --- | --- |
| Pre-expansion worklist bound | IMPLEMENTED ON DRAFT | Commit `ea7a188` rejects exact dict/list/tuple child fan-out before adding children to pending traversal, avoiding an oversized worklist allocation |
| Negative controls | AUTHORED, NOT EXECUTED | Commit `c827fe5`, `tests/test_hardware_ingress_fanout_budget.py`; run `python -m unittest discover -s tests -p 'test_hardware_ingress_fanout_budget.py' -v` |
| Execution and integration | BLOCKED | Container cannot resolve github.com; repository checkout and focused test execution unavailable; no CI pass or merge claimed |
| Research effectiveness | BLOCKED | This is synthetic ingress robustness, not independent V2X incident evidence; dataset provenance, paired baselines, and physical interlock tests still required |

Next: execute focused fan-out tests and existing ingress suites on a real checkout, reconcile #227/#229/#230, inspect required checks and reviews, then squash only validated changes. Preserve local emergency control.

## 2026-11-23 — executable Mapping ingress boundary (#231)

| Workstream | Status | Evidence / next gate |
| --- | --- | --- |
| Custom Mapping callback isolation | IMPLEMENTED ON DRAFT | Hardware parser now rejects non-exact dict Mapping before invoking custom iteration, length or item methods; commit 7b3c142 |
| Adversarial callback controls | AUTHORED, EXECUTION PENDING | Three tests in `tests/test_hardware_custom_mapping_rejection.py`; commit 014c2d1; run `python -m unittest discover -s tests -p 'test_hardware_custom_mapping_rejection.py' -v` |
| CI and merge | BLOCKED | GitHub checkout DNS unavailable in execution container; #231 remains draft, no focused suite or CI result established |
| Safety and experimental evidence | PARTIAL / BLOCKED | Built-in dict values may still include user-defined objects with encoder callbacks; local emergency controls and physical actuation unverified; authentic incident dataset and matched independent experiments absent |

This is a deliberately narrow in-process input-type restriction. It is not a claim of remote TCP DoS immunity, cryptographic novelty, or publishable attack-detection effectiveness. Next: reject executable nested subclasses or normalize to exact JSON primitives, execute focused regressions, then reconcile #227/#229/#230 and required CI before merge.

## 2026-11-23 — bounded pre-serialization Mapping traversal (draft PR #231)

| Workstream | Status | Evidence / gate |
| --- | --- | --- |
| In-memory mapping preflight | IMPLEMENTED ON DRAFT | Iterative depth <=32, traversal node <= configured frame bytes, cycle rejection, oversized string rejection before canonical serialization; commits a71a015, 62ad49c |
| Adversarial tests | AUTHORED, NOT EXECUTED | `python -m unittest discover -s tests -p 'test_hardware_mapping_traversal_budget.py' -v`; deep, cyclic, wide and ordinary invalid mapping |
| CI and integration | BLOCKED | Local GitHub DNS resolution failed; do not merge #231 or overlapping #227/#229/#230 until focused tests, CI and review succeed |
| Residual resource risks | PARTIAL | Untrusted custom Mapping methods, non-string scalar serialization, and JSON encoder CPU remain unbounded; no real network DoS claim |
| Original article efficacy | BLOCKED | Authentic incident provenance, matched baselines and multi-seed independent trials absent |

## 2026-11-23 — in-memory hardware frame budget (draft PR #231)

| Workstream | Status | Evidence / next gate |
| --- | --- | --- |
| In-process Mapping admission byte budget | IMPLEMENTED ON DRAFT BRANCH | `hardware_transport_security.py` canonical size check before schema/MAC; same configured max frame bytes as wire ingress |
| Oversized, small-invalid, and no-mutation negative controls | AUTHORED; NOT EXECUTED | `python -m unittest discover -s tests -p 'test_hardware_mapping_frame_budget.py' -v` |
| #227/#229/#230 overlap | INTEGRATION BLOCKED | Reconcile transport changes and run security regression suites, required CI and review before squash merge |
| Authentic incident-level original research | BLOCKED | No independently pinned VeReMi NextGen/CAN source or paired multi-seed evidence; no physical actuation claim |

**Threat boundary:** Mapping ingress is in-process, not a claim that arbitrary TCP clients can directly send Python mappings. The size check bounds accepted serialized content but still incurs serialization work; a deeply nested or enormous in-memory object can consume resources before rejection. Consider depth-limited traversal and bounded encoder next. Fixture tests are NON-PUBLISHABLE as effectiveness results. No CI or runtime success claimed.

## 2026-11-23 — nested in-memory ingress objects (draft PR #231)

| Workstream | Status | Evidence / next gate |
| --- | --- | --- |
| Executable nested Python objects | IMPLEMENTED ON DRAFT BRANCH | Reject unsupported object types and container subclasses before JSON serialization; commit `ab52374` |
| Adversarial negative controls | AUTHORED, NOT EXECUTED | `tests/test_nested_hardware_ingress_objects.py`; run `python -m unittest tests.test_nested_hardware_ingress_objects -v` |
| GitHub CI and main integration | UNVERIFIED | Do not merge before focused tests, security baseline and overlapping #227/#229/#230 reconciliation |
| Physical safety / authentic incident effectiveness | BLOCKED | No physical interlock proof, independent dataset provenance or publishable efficacy evidence |

**Limitation:** This guards Python in-process mapping admission, not raw socket framing or hostile process memory. The regression tests are synthetic, and no test execution is claimed. Next: execute focused tests and review serializer semantics for repeated shared immutable references, then reconcile transport PRs.


## 2026-11-19 — issuer lock-path substitution negative controls (draft PR #154)

| Workstream | Status | Evidence and next gate |
| --- | --- | --- |
| Lock-file symlink, FIFO, hardlink and unsafe mode rejection | IMPLEMENTED, EXACT BRANCH UNVERIFIED | `research_contracts/independent_checkpoint_issuer.py`; POSIX O_NOFOLLOW, descriptor metadata and inode identity checks |
| Lock replacement during acquisition | DETERMINISTIC NEGATIVE CONTROL AUTHORED | `tests/test_checkpoint_issuer_lock_path.py`; injected replacement after flock, not a concurrency stress test |
| Normal issue/restart and rewritten history | REGRESSION AUTHORED | Six tests total; run `python -m unittest discover -s tests -p 'test_checkpoint_issuer_lock_path.py' -v` |
| Trusted directory and lock ownership | PARTIAL | Rejects unsafe lock metadata, but directory must be owned/protected by an independent principal; hostile directory writers remain out of scope |
| Authenticated verified Go-chain ingestion | PENDING | Issuer still trusts caller-provided hashes |
| Authentic V2X/CAN incident comparisons | BLOCKED | No publishable original-effectiveness evidence; no hardware actuation |

**Execution limitation:** GitHub connector committed code, but container GitHub DNS resolution failed. The exact branch regression suite was not run. No pass, crash durability, independent finality or physical safety claim. Next: execute tests, validate POSIX race behavior and implement Go-chain verification at issuer ingress.

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

## 2026-11-15 — cluster influence sensitivity (draft)

- **Implemented:** `experiments/v2x/cluster_influence_analysis.py` computes paired candidate-minus-baseline accuracy effects with each independent cluster omitted in turn, reports effect range and possible sign reversal. This is an influence diagnostic, not inferential significance.
- **Regression contracts authored:** `tests/test_cluster_influence_analysis.py` covers cluster dominance, uniform improvement, duplicate IDs, insufficient clusters, nonbinary predictions and extra columns.
- **Validation:** repository checkout failed with `Could not resolve host: github.com`; exact tests and CI are **unverified**. Synthetic examples are **not publishable scientific observations**.
- **Blocked:** genuine independent incident/recording clusters, publisher-verified dataset hashes and labels, matched held-out candidate/baseline predictions, physical interlocks.
- **Next code task:** run `python -m unittest discover -s tests -p 'test_cluster_influence_analysis.py' -v` in the full checkout; link out-of-band pinned replay manifests to paired cluster IDs, fail closed on incomplete joins, then execute independent real cohorts.

## 2026-11-15 — cluster influence semantics correction (draft #133)

| Area | State | Evidence / next |
| --- | --- | --- |
| Leave-one-cluster-out direction | Implemented, exact CI pending | Strict sign reversal now requires opposite nonzero signs (`full * omitted < 0`); touching zero is separately reported as `reaches_null_under_omission` |
| Regression | Authored, unverified | Two synthetic cases distinguish positive-to-zero from negative-to-positive; run `PYTHONPATH=. python -m unittest discover -s tests -p 'test_cluster_influence_analysis.py' -v` |
| Authentic paired clusters | Blocked | No independently verified recording/scenario grouping, source truth or held-out candidate/baseline pairs; no publishable effect estimates |
| Next | Upcoming | Bind external trial manifests and independent cluster IDs to complete incident joins, then validate matched cohorts and uncertainty estimates |

This correction prevents reporting a loss of effect as a directional reversal. Neither outcome alone establishes statistical significance.

## 2026-11-16 — Paired incident universe coverage (draft)

| Workstream | Status | Evidence / limitation |
| --- | --- | --- |
| World-universe denominator | Implemented, synthetic contract only | `experiments/v2x/audit_trial_coverage.py` uses every independently supplied world incident; missing method predictions are scored as no-alert, including positive false negatives |
| Candidate/baseline symmetry | Implemented | Both methods use exactly the same world IDs; reject unknown IDs, duplicate IDs, invalid binary labels, ragged CSV and unexpected columns |
| Reproducibility | Partial | SHA-256 of three source CSV files, explicit incident/cluster counts, confusion counts; no external source authenticity attested |
| Regression evidence | Locally verified equivalent isolated script: 7/7 synthetic tests; repository CI pending | Run `python -m unittest tests.test_audit_trial_coverage -v` from repo root; GitHub checkout DNS unavailable locally |
| Authentic incident efficacy | Blocked | No independent incident truth provenance, source capture completeness proof, or authentic held-out candidate/baseline predictions |
| Next | Upcoming | Integrate pinned trial receipt and complete capture interval; fail on source identity mismatch, then execute matched multi-seed trials and cluster-level uncertainty |

These synthetic checks are not publication-ready attack detection results. Missing prediction means no alert only when the world-universe manifest and trial capture interval are independently complete; otherwise no scientific inference is warranted.


## 2026-11-16 — paired full-universe diagnostic extension (draft PR #134)

| Workstream | State | Evidence / limitation |
| --- | --- | --- |
| Full-universe paired correctness | Implemented, repository CI unverified | Audit v2 adds both-correct, candidate-only-correct, baseline-only-correct, and both-wrong counts on every world incident, treating absent predictions as no-alert |
| Asymmetric observation audit | Implemented, repository CI unverified | Separately counts both-observed, candidate-only-observed, baseline-only-observed and neither-observed to expose differential capture without conditioning paired comparisons on observed rows |
| Synthetic validation | Partial | Two equivalent isolated Python regression cases executed locally and passed; committed repository tests and complete CI not executed |
| Scientific efficacy | Blocked | No independent capture-completeness witness, source-authenticated incident universe, matched publisher dataset, physical ECU test or independently clustered multi-seed trials |
| Next engineering task | Upcoming | Bind both prediction streams to pinned capture receipts and preregistered incident/cluster manifests, then reject mismatched trial identity before computing effect sizes |

Do not interpret missing prediction as proof of no physical observation: it is a prespecified **no-alert scoring convention**, and incomplete capture remains a separately reported threat to validity. No p-value or publishable attack detection claim is derived from these synthetic tests.


## 2026-11-16 — paired-world trial input pinning (draft PR #134)

| Workstream | State | Evidence / limitation |
| --- | --- | --- |
| Input integrity | Implemented, tests pending | `experiments/v2x/verify_pinned_coverage.py` requires an out-of-band SHA-256 pin for a strict held-out trial manifest, and checks exact SHA-256 of world/candidate/baseline input bytes before scoring; rechecks digests after scoring |
| Trial identity and split | Implemented, tests pending | Rejects absent/extra manifest fields, duplicate JSON keys, non-held-out split, invalid seed, nonfinite constants and wrong protocol |
| Regression verification | Authored, unverified | Six synthetic tests in `tests/test_verify_pinned_coverage.py`; run `PYTHONPATH=. python -m unittest tests.test_verify_pinned_coverage -v` |
| Independent source authenticity | Blocked | Manifest and pins can be operator generated; no trusted external timestamp, independent ground truth or publisher archive authentication |
| Experimental evidence | Blocked | No authentic multi-seed paired V2X/CAN trial, independent capture uptime proof or physical hardware validation |
| Next | Upcoming | Run exact tests/CI; connect pinned capture receipts and externally verified world annotations; execute independent held-out attack trials |

This is a **measurement integrity guard**, not proof of preregistration or publishable efficacy. Local checkout remains blocked by GitHub DNS; no test pass is claimed.


## 2026-11-16 — recording/source-disjoint cohort audit (draft)

| Area | State | Evidence and next step |
| --- | --- | --- |
| Held-out recording leakage | Implemented, tests pending | `experiments/v2x/audit_recording_split_leakage.py` fails closed on recording-group and source-digest overlap across train/validation/test, malformed schema, duplicate incident/trial IDs, duplicate JSON keys and incorrect external manifest SHA-256 |
| Synthetic contracts | Authored, not yet executed | 10 adversarial unit tests in `tests/test_recording_split_leakage.py`; run `python -m unittest tests.test_recording_split_leakage -v` |
| Publisher dataset provenance | Blocked | A SHA-256 supplied by an operator establishes byte identity only, not publisher authenticity, annotation reliability or license |
| Attack efficacy and independent cluster statistics | Blocked | No authentic held-out observations, independent labels, strong-baseline comparisons or physical interlock evidence from this work |
| Next | Upcoming | Execute exact tests/CI, verify publisher-sourced recording manifests, preregister disjoint cohorts, then run identical candidate/baseline trials with independent cluster-level uncertainty |

This is a methodological guardrail, **not a scientific detection result**. Group IDs are operator-supplied and must be independently validated; conservative source-level disjointness may exclude legitimate splits within one archive. Existing fixture CSVs, microbenchmarks and offline formulas remain non-publishable main evidence.


## 2026-11-16 — offline CAN replay intervention protocol (draft)

| Workstream | Status | Evidence / limitations |
| --- | --- | --- |
| Deterministic CAN replay intervention | Implemented in draft; validation pending | `experiments/v2x/generate_can_replay_scenario.py` takes pinned normalized CAN frames, replays a selected contiguous window after the original recording, and writes byte-hashed scenario output and provenance manifest |
| Synthetic protocol contracts | Authored, not executed | `tests/test_can_replay_scenario.py` checks determinism, tamper, out-of-range windows, nonpositive offset, malformed indices, mixed recording identities and ragged CSV |
| Repository execution | Blocked transiently | Fresh GitHub clone failed with DNS `Could not resolve host: github.com`; no claim that tests or CI passed |
| Scientific inference | Blocked | Injected replay flags are **simulation interventions**, not independently annotated attack truth. No authentic publisher archive, physical CAN device, or comparative efficacy evidence is claimed |
| Next code task | Upcoming | Execute exact regression tests and cross-check with existing CAN normalization, then add matched no-attack controls and randomized multi-seed replay positions on publisher-verified recording-disjoint data |

This protocol never opens a CAN socket, sends physical actuator commands, or infers ground-truth labels. Existing fixture/microbenchmark observations remain NON-PUBLISHABLE main results.

## 2026-11-16 — paired offline CAN replay control (draft PR #136)

| Workstream | Status | Evidence / limitation |
| --- | --- | --- |
| Matched recording input | Implemented, unverified | `generate_paired_can_replay_control.py` derives injected and no-injection control traces from the exact same SHA-256-pinned normalized source, recording ID and scenario parameters; hashes both outputs |
| Synthetic regression contracts | Authored, not executed | Five tests in `tests/test_paired_can_replay_control.py` cover counts, deterministic output, tampering, invalid windows and scenario IDs. Command: `PYTHONPATH=experiments/v2x python -m unittest tests.test_paired_can_replay_control -v` |
| Scientific comparability | Partial | No-injection control has fewer frames and lacks post-recording exposure. It is NOT an equal-load/equal-duration matched control; no valid latency/throughput causal comparison until explicit horizon and matched benign traffic are added |
| Authentic datasets and physical safety | Blocked | No publisher-authenticated CAN recording, independent annotation, hardware loopback or physical emergency witness in this change |
| Next | Upcoming | Execute tests in repository CI, add fixed-horizon benign traffic matched-load control, then run recording-disjoint independent trials and candidate/baseline comparisons |

No accuracy, safety efficacy, statistical significance or publishable primary research result is claimed. Existing fixture CSVs, three-peer poisoning checks, five-iteration microbenchmarks and offline network formulas remain non-publishable primary evidence.


## 2026-11-16 — equal-timestamp, equal-frame-count offline CAN sham (draft PR #136)

| Area | State | Evidence / limitation |
| --- | --- | --- |
| Matched exposure control | Implemented; test execution pending | `generate_matched_can_sham_control.py` appends frames from a separately pinned donor at exactly the replay timestamps, preserving frame count and horizon, with independent source/donor recording IDs and byte digests |
| Adversarial contracts | Authored; execution pending | `tests/test_matched_can_sham_control.py`: seven synthetic tests covering timestamp/count parity, determinism, tamper, donor identity, bounds and type validation |
| Donor ground truth | Blocked | This tool **cannot verify** that the donor is benign; the operator must provide independently verified provenance and source-disjoint labels. A different recording ID and hash do not prove independent collection |
| Scientific comparability | Partial | Timing and frame-count parity do **not** imply equal CAN ID distributions, payload distributions, ECU dynamics, capture quality or causal exchangeability. Donor frames are explicitly simulated, not physical CAN events |
| Publishable evidence | Blocked | No real publisher-authenticated CAN source, independently annotated incidents, multi-seed matched baselines, physical safety witness or validated effect estimates |
| Next code task | Upcoming | Run exact tests and CI; pin independently verified benign donor provenance; add matching/stratification for CAN ID and DLC distributions; execute disjoint-recording trials with incident-level truth and cluster-aware uncertainty |

Test: `python -m unittest tests.test_matched_can_sham_control -v`. Existing fixture CSVs and short microbenchmarks remain NON-PUBLISHABLE main results.

### 2026-11-23 — Durable admission corruption negative controls (draft #228)

| Area | Status | Evidence and limitation | Next gate |
| --- | --- | --- | --- |
| Durable epoch admission snapshot integrity | PARTIAL | Added four synthetic persisted-row corruption negative controls: forged positive without quorum, positive without evidence bucket, duplicate nonce, and future-epoch nonce. They assert fail-closed reopen and state transition. Commit 4ad316b24c4fc04dc986b420cd746321f769c587; execution/CI not yet verified. | Run focused unittest and full security suite; inspect CI before merge. |
| Hardware actuation | BLOCKED | No physical receiver or independent interlock validation; remote ECU actuation intentionally disabled. | Independent hardware safety review; never infer physical safety from mocked tests. |
| Crash durability and rollback | PARTIAL | SQLite WAL/FULL is not tamper-proof or rollback-resistant and not blockchain finality. | Fault-injected independent-process crash/restart tests and external trusted anchor. |
| Publishable original research evidence | BLOCKED | Snapshot mutation fixtures are negative-control tests, not authentic datasets or independent incident-level evidence. | Pinned authentic V2X/CAN data, held-out baselines, paired multi-seed experiments and uncertainty. |
| PR reconciliation | PARTIAL | #225 merged as b572cb3fd1c85ec9929edc986aa609f67a63cf67; #226/#227 remain draft, #158/#160 closed unmerged. | Reconcile unique changes and validate checks without bypassing safety gates. |
