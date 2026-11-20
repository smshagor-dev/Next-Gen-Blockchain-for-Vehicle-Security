# Research validation matrix (2026-11-20)

This file records the scope of this branch's paired-overhead analysis. It does not supersede other repository research tracking.

| Workstream | Status | Evidence / limitation |
|---|---|---|
| Authenticated hardware ingress and bounded receives | Partial | Independent exact-checkout audit and physical interlock validation outstanding |
| Durable replay/one-shot admission | Partial | Implementation and crash/concurrency tests on draft PR; full checkout execution outstanding |
| Paired runtime timing collection | Partial | Balanced seeded benchmark implemented; no independently validated raw run in this update |
| Trial-cluster uncertainty analysis | Implemented, unverified | `research_contracts/analyze_paired_admission.py`; no fabricated numeric results |
| Analysis negative controls | Implemented, unexecuted | `tests/test_paired_admission_analysis.py` |
| Mock ledger finality and rollback | Blocked | No independently trusted finality or rollback-resistant checkpoint |
| Authentic VeReMi NextGen and CAN ingestion | Pending | No verified dataset provenance or real labelled experimental splits |
| Adversarial matched baselines and ablations | Pending | No publishable effectiveness evidence |
| Network/CPU/RAM scaling | Pending | No instrumented independent process runs |
| Defensible scientific manuscript | Blocked | Requires authentic datasets, baselines, multi-seed uncertainty and limitations |

## Reproduction commands

```sh
python -m unittest discover -s tests -p 'test_paired_admission_analysis.py' -v
python -m research_contracts.benchmark_durable_admission --repeats 30 --seed 20261120 --output /tmp/omni-paired-30.json
python -m research_contracts.analyze_paired_admission /tmp/omni-paired-30.json --output /tmp/omni-paired-summary.json
```

The bootstrap resamples complete trials rather than treating three operations within a trial as independent. The 95% interval is exploratory and cannot establish attack resistance or statistical significance from a sample-count rule. Tests above are prescribed, not claimed passed.

## Next engineering task

Execute exact checkout tests, repair failures, record immutable environment metadata, and implement paired CPU/RAM/process-isolated network experiments; then move to verified labelled dataset ingest and identical-split adversarial baselines.

## 2026-11-20 — Authority type-confusion negative controls

| Workstream | State | Evidence / limitation |
|---|---|---|
| Evidence verification strictness | Implemented, unverified | Only literal boolean True is accepted; truthy strings, integers, lists and mappings cannot satisfy quorum |
| Local emergency reset authority | Implemented, unverified | Only literal boolean True clears stop; no physical operator identity authentication is implemented here |
| Admission configuration validation | Implemented, unverified | Boolean values rejected as integer bounds to prevent Python bool/int confusion |
| Restart negative-control tests | Committed, unexecuted | tests/test_strict_admission_authority_types.py exercises durable stop latch and rejected reset after reopening |
| Hardware ingress and actual local interlocks | Partial / blocked | Must verify source of verified/operator_confirmed assertions and local physical stop independently |
| Publishable adversarial effectiveness | Blocked | Type-confusion regression is a safety invariant test, not a dataset effectiveness outcome |

Reproduce: `python -m unittest discover -s tests -p 'test_strict_admission_authority_types.py' -v`, then `python -m unittest discover -s tests -v`. No exact checkout test execution is claimed. Next: audit all call sites setting `Evidence.verified` and `operator_confirmed`, especially TCP/JSON adapters; ensure cryptographic verification and operator presence are performed outside the admission state machine. Do not merge until exact checkout regression and review.

## 2026-11-20 — Stratified bootstrap correction

| Workstream | State | Evidence / limitation |
|---|---|---|
| Execution-order confounding in paired analysis | Implemented, unverified | Bootstrap now resamples complete trials within the assigned first-execution strata, preserving the observed order mix |
| Statistical regression controls | Committed, unexecuted | tests/test_order_stratified_admission_analysis.py checks missing strata, deterministic seed, stratum counts and invalid durations |
| Exact repository validation | Blocked transiently | Container cannot resolve github.com; connector commits do not establish test pass |
| Hardware ingress and local emergency control | Partial / unverified | No physical actuation or hardware validation in this change |
| Genuine V2X attack-effectiveness evidence | Blocked | No authentic VeReMi/CAN dataset, matched adversarial baseline, or independently executed multi-seed trial |
| Paper and numeric claim ledger | Upcoming | Do not promote microbenchmark timings into paper effectiveness claims |

Reproduce: `python -m unittest discover -s tests -p 'test_order_stratified_admission_analysis.py' -v` and `python -m unittest discover -s tests -v`. Next: run exact checkout tests and execute the paired benchmark, then prioritize production TCP ingress audit and verified real-dataset pipeline. Stratification reduces one known order-mix confound but does not remove time drift, disk-cache dependence or pseudoreplication across repeated process operations.

## 2026-11-20 — Numeric evidence integrity in paired analysis

| Workstream | State | Evidence / limitation |
|---|---|---|
| Extreme-duration ratio overflow and underflow | Implemented, unverified | Uses difference of logarithms of integer sums rather than unsafe float division; rejects non-reportable extreme ratios |
| JSON schema and trial-count type confusion | Implemented, unverified | Rejects boolean schema and repetition counts instead of accepting Python bool-as-int |
| Negative-control regression | Committed, unexecuted | tests/test_paired_numeric_evidence_integrity.py covers ordinary ratio, extreme integer duration, excessive ratio and malformed type metadata |
| Exact checkout tests | Pending | GitHub connector commit confirmation is not a test execution |
| Hardware TCP ingress and safety | Partial | Existing signed ingress and fail-closed actuation code observed in main; independent runtime and physical verification pending |
| Scientific V2X effectiveness | Blocked | No authenticated real-dataset, matched-baseline adversarial trial or physical hardware evidence established |

Reproduce: `python -m unittest discover -s tests -p 'test_paired_numeric_evidence_integrity.py' -v`; then `python -m unittest discover -s tests -v`. Next: execute these tests on the exact PR checkout, audit TCP envelope verifier and replay cache across restarts, then implement authenticated dataset provenance and attack-matched baselines. This is input-integrity engineering and not a publishable scientific effectiveness result.

## 2026-11-20 — TCP receive preallocation bound

| Workstream | State | Evidence / limitation |
|---|---|---|
| Bounded hardware ingress allocation | Implemented, unverified | `hardware_transport_security.AuthenticatedLineFramer.feed` rejects oversized recv chunks before bytearray.extend; clears pending partial state on overflow |
| Oversized receive negative controls | Committed, unexecuted | `tests/test_hardware_framer_preallocation.py`: oversized single recv, fragmented overflow, valid fragmentation, batched flood |
| Runtime receiver and resource DoS | Partial | Receiver recv size, per-peer timeouts, concurrency limits and CPU under slowloris/flood still require independent audit |
| Hardware emergency-stop independence | Blocked physical validation | No hardware or real vehicle access; no actuation in these tests |
| Publishable effectiveness | Blocked | Framing regression is not attack-detection performance or an independently validated dataset experiment |

Reproduce: `python -m unittest discover -s tests -p 'test_hardware_framer_preallocation.py' -v` and `python -m unittest discover -s tests -v`. Exact checkout tests not executed. The conservative chunk bound rejects oversized batches of otherwise valid small frames; assess receiver chunk sizing before deployment. Next: independently inspect socket receive loop and impose per-connection deadline/concurrency quotas while retaining local emergency-stop priority.
