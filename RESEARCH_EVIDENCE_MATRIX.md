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
- **TESTS VERIFIED IN GITHUB ACTIONS:** Ubuntu Python 3.11 run 43613905380 completed SUCCESS on the PR commit; experiments/v2x/test_capture_export_producer.py covers real subprocess CLI plan/seal, zero-capture false negatives, tamper, identity, time, replay, credentials and output overwrite. Dedicated Ubuntu Python 3.11 workflow compiles code and executes producer, interval and world-join suites. Command: PYTHONPATH=experiments/v2x python -m unittest discover -s experiments/v2x -p test_capture_export_producer.py -v. CI workflow passed, but no independent physical or field experiments occurred; additional repository-wide and cross-platform checks remain separate.
- **PARTIAL:** Distinct receipt files are individually fsynced and exclusive, not one atomic two-file commit. An interrupted second write may leave an unmatched first receipt; consumers must require both. Signed completion proves only the hub assertion, not uninterrupted sensing, independent annotations, independent cluster identity or hardware safety.
- **BLOCKED:** Independent pre-registration/time witness; source-authenticated production receiver export and complete coverage witness; genuine VeReMi NextGen/CAN independent incident truth and matched baseline trials; physical emergency-stop and power-cut evidence. Synthetic fixtures remain NON-PUBLISHABLE main results.
- **UPCOMING:** Execute PR CI, fix regressions, anchor manifests and real capture evidence with independent provenance and run preregistered matched-split incident campaigns.

### Evidence file publication hardening (2026-11-14 follow-up)

- Replaced direct O_EXCL target writes with same-directory temporary staging, full file fsync and exclusive hard-link publication, followed by POSIX directory fsync. This prevents observers from seeing partially written **individual** manifests or receipts and prevents silent replacement of preexisting outputs.
- Added regression cases checking that the final path does not exist until the fully written staging file is published and that a simulated hard-link failure leaves no published target or temporary file.
- **Validation pending on latest commit:** new GitHub Actions checks must pass before merge; earlier passing CI on a prior commit does not validate this change.
- **Residual limitation:** the two separately published receipt files still do not form one atomic transaction; independently verify the pair and digest bindings. External pre-run pinning and physical capture coverage remain unproven.

## 2026-11-14 — receipt pair fail-closed verification

- **IMPLEMENTED IN DRAFT PR #107:** `experiments/v2x/verify_capture_receipt_pair.py` verifies BOTH signed receipt files, operator-pinned canonical manifest, matching capture SHA-256, independent HMAC keys, matching trial window, and explicit complete-interval assertion before scoring. Missing, malformed, duplicate-key, extra-field, mismatched or tampered receipts fail closed. A partial two-file publication cannot be mistaken for a completed observation by this verifier.
- **TESTS AUTHORED:** `experiments/v2x/test_verify_capture_receipt_pair.py` exercises valid pair, missing halves, duplicate JSON keys, forged hashes, tampered HMACs, mismatched external pin and signed incomplete interval. CI workflow now includes this test module. Actual new-commit CI outcome must be checked before claiming success.
- **STILL PARTIAL:** This is logical pair verification, not an atomic two-file filesystem transaction, independent timestamp, authenticated real sensor uptime or physical actuation safety. A hub can sign a false completeness assertion. Real field experiments and independent provenance remain blocked.
- **NEXT:** Run CI and fix regressions; independently anchor manifest timestamp and signed coverage witness, then validate actual receiver captures and matched replay/DoS trials.

## 2026-11-14 — paired signed-capture campaign adapter (issue #92; scientific comparison follow-up to #79/#88)

| Gate | State | Evidence / remaining gate |
| --- | --- | --- |
| Same source and matching splits | IMPLEMENTED IN DRAFT #107 | One operator-pinned manifest and one independently supplied world-incident universe drive both arms; missing incidents are scored as absence, not discarded |
| Method identity integrity | PARTIAL | Detached, independently keyed assignment HMACs bind each capture to baseline/candidate arm and planned method name. **Hub self-claims cannot prove which algorithm actually executed** |
| Adversarial integrity tests | ADDED, CI OUTCOME PENDING | 17 synthetic tests cover mismatched arm, signed wrong method, tampered role HMAC, duplicate keys, swapped captures, replay, unverified relay, wrong world pin, zero-observation intervals and a real CLI round-trip |
| Direct paired estimates | IMPLEMENTED, **DESCRIPTIVE ONLY** | Both arm confusion counts, accuracy difference in percentage points, exact McNemar descriptive p-value, full per-incident rows and cryptographic source digests |
| Independent inference | BLOCKED | The tool accepts one seed/cluster at a time. Repeated correlated incidents cannot be treated as independent units; no confidence interval or significance claim is appropriate from this output |
| Authentic physical/field observations | BLOCKED | No source-authenticated receiver exports, independently witnessed continuous capture, independently curated world truth, or HIL safety evidence |
| Next code task | UPCOMING | Integrate actual instrumented policy-run identifiers and independent witness/attestation; execute frozen policies on identically scheduled authentic multi-seed scenarios and aggregate by genuinely independent clusters |

These deterministic protocol tests are **non-publishable main evidence**. This adapter is not a claim of original cryptography, sensor validity, or real comparative superiority. Never claim p-values demonstrate significance merely because n>=30.

### Verified paired-capture contract evidence (2026-11-14)

- **TESTED:** GitHub Actions `V2X Trial Manifest and Capture Receipts` run [43624931667](https://github.com/smshagor-dev/Next-Gen-Blockchain-for-Vehicle-Security/actions/runs/43624931667) completed **SUCCESS** on source commit `072a9662758f3892f163dbf63c143a9903063efa`. Job [132538551757](https://github.com/smshagor-dev/Next-Gen-Blockchain-for-Vehicle-Security/actions/runs/43624931667/job/132538551757) executed 17/17 new matched-cohort tests, including the actual CLI subprocess round-trip, 21 producer tests, 31 receipt-pair tests, 15 interval tests and 10 world-join tests. All passed (94 passing cases in the workflow, not 94 independent experiments).
- **PARTIAL:** Both signed policy-assignment receipts are hub claims, not cryptographic proof of which executable policy actually ran. No authentic multi-seed experiments or independent observation-coverage measurements were performed. Exact McNemar p-value is **descriptive only** at a single claimed cluster and cannot establish significance for correlated incidents.
- **BLOCKED:** Independently observed algorithm execution and sensor uptime; trustworthy incident annotations, authentic Veremi/CAN trials, physical local emergency-stop evidence; source-audited prior-art comparisons.
- **NEXT:** Pin executable/configuration digests in a separately observed harness, run matched split trial traces under independent clocks and clusters, and report bootstrap uncertainty/effect sizes only after true independent replications.

## 2026-11-14 — executable/configuration pre-run pin integrity (follow-up)

- **IMPLEMENTED IN DRAFT PR #107:** `experiments/v2x/pin_policy_artifacts.py` hashes the exact baseline and candidate executable bytes and configuration bytes, binds them to the existing planned method names and trial manifest SHA-256, and emits an exclusive immutable-on-create pin. Verification requires the independently retained pin digest and byte-for-byte original artifacts.
- **TESTS AUTHORED:** `experiments/v2x/test_pin_policy_artifacts.py` has 12 synthetic adversarial cases for binary tampering, configuration changes, swapped artifacts, forged pin digest, duplicate keys, wrong method, invalid version and missing binary. Dedicated CI test step added; no CI success is claimed for the latest code until it completes.
- **LIMITATION:** This is pre-run *artifact integrity*, NOT proof that a particular executable ran, proof of external preregistration timestamp, trustworthy sensor coverage or physical emergency actuation. The hash must be pinned externally before the trial. No authentic field experiment or scientific efficacy measurement was performed.
- **NEXT CODE TASK:** Independently observed launcher with measured executable/config digests, OS process identity and run/capture receipt binding; verify actual execution under controlled simulated incident trials. Preserve local emergency control outside all network policy gates.

- **CI VERIFIED (2026-11-14):** [V2X receipt workflow run 43625928701](https://github.com/smshagor-dev/Next-Gen-Blockchain-for-Vehicle-Security/actions/runs/43625928701), job 132541598180 completed SUCCESS at commit `962858c83bedeac1f4792b775ca7be7ebcd238e3`: 12/12 new policy-pin tests passed, together with 21 producer, 31 receipt pair, 17 matched-cohort, 15 interval and 10 independent-world tests (106 contract tests total). These are synthetic validation cases, **not 106 research observations**.
