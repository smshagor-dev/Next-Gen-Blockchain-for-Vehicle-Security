# Signed event admission checkpoint — 2026-11-17

| Workstream | Status | Evidence or blocker |
| --- | --- | --- |
| Signed event type/size/control validation | Implemented, unverified | hardware_bridge.py uses _signed_event_label before both ledger push paths; commit d2044c8 |
| Regression suite | Committed, not executed | tests/test_signed_event_label.py; commit a78c6e2 |
| Authenticated production ingress | Partial | Durable replay gate not wired into production; current verifier uses process-local replay cache |
| Emergency control isolation | Partial | Remote actuator dispatch disabled; independent local physical stop not verified |
| Ledger crash consistency / mock finality | Partial / blocked | SQLite gate is not distributed consensus; privileged snapshot rollback remains possible |
| Authentic V2X/CAN dataset provenance | Pending | No independently verified dataset ingest or license evidence |
| Independent adversarial baselines and multi-seed statistics | Pending | No publishable incident-level results |
| Manuscript | Blocked | Fixtures, 3-peer sanity check, 5-iteration microbenchmarks and offline formulas are non-publishable primary evidence |

Run: `python -m unittest discover -s tests -p 'test_signed_event_label.py' -v`
Then run full repository suite and authenticated real loopback tests before merging.

Next substantive task: integrate durable replay with explicit provisioning/recovery into production Pi ingress, preserving the network-actuation default deny and independent local emergency controls. Measure authenticated replay/slow-peer behavior against matched baselines. No hardware access or research effectiveness is claimed.

## Follow-up: UTF-8 budget alignment

Implemented: hardware_bridge._signed_event_label now enforces the transport's 160-byte UTF-8 event limit, rather than an inconsistent 128-codepoint limit. This preserves acceptance of valid 129–160 byte ASCII labels and rejects multibyte labels exceeding the wire budget. Regression cases now cover 161 ASCII bytes and 162 UTF-8 bytes. Commits: 844517a, 2d408b0.

Validation: GitHub DNS resolution failed in the execution container; committed tests were not run. Run `python -m unittest discover -s tests -p 'test_signed_event_label.py' -v` and the full suite before merging. Independent safety and publishable adversarial results remain blocked. Next: durable production replay recovery and actual authenticated loopback experiments.

## 2026-11-17 persistent nonce admission checkpoint

| Workstream | Status | Evidence / limitation |
| --- | --- | --- |
| SQLite authenticated nonce claims | Implemented, repository tests pending | hardware_nonce_store.py; unique device/nonce PK, WAL/FULL, explicit provisioning, fail-closed recovery |
| Production Pi TCP startup and verifier | Implemented, repository tests pending | SMARTCAR_HW_NONCE_STORE_PATH required; no volatile replay fallback; verified envelope released after committed claim |
| Regression tests | Committed, not executed | tests/test_hardware_nonce_store.py covers restart, unrelated SQLite DB, clock rollback |
| Isolated SQLite behavior | Verified locally | WAL accepted, expected PK schema observed, inserted claim survived close/reopen; NOT full module execution |
| Database capacity/retention | BLOCKED | Current persistent nonce table grows without bound. Do not merge until bounded retention and safe clock-rollback strategy are implemented |
| End-to-end Pi loopback / full CI | BLOCKED | github.com DNS unavailable for checkout; no repository test pass claim |
| Physical local emergency | Unverified | No actuator enabled; independent local emergency-stop not physically tested |
| Original paper evidence | Not ready | Authentic datasets, matched independent adversarial baselines and multi-seed uncertainty missing |

Commands:
`python -m unittest discover -s tests -p 'test_hardware_nonce_store.py' -v`
`python -m unittest discover -s tests -p 'test_authenticated_socket_session.py' -v`

Next code task: bound persistent nonce table safely (without reopening expired replay during clock rollback), then run full checkout and real authenticated loopback restart/replay experiments. The current database is vulnerable to unbounded storage growth; keep PR draft and do not merge.

## 2026-11-17 bounded nonce capacity checkpoint

| Workstream | Status | Evidence / blocker |
| --- | --- | --- |
| Durable nonce capacity | Implemented, tests unexecuted | DEFAULT_MAX_NONCE_CLAIMS=100000, configurable max_claims 1..1000000; no eviction or expiration-based replay reopening |
| Capacity/clock tests | Committed, unexecuted | tests/test_hardware_nonce_store.py checks fail-closed capacity and non-finite clock |
| Storage/availability | Partial | SQLite pages and WAL file can grow; exhaustion intentionally denies legitimate traffic; no safe retention protocol or disk-quota enforcement |
| Runtime performance | Blocked | COUNT(*) in every claim needs measured throughput and latency; no performance result |
| Safety/actuation | Blocked | Independent local emergency stop not physically verified |
| Research datasets/baselines | Upcoming | Independent attack labels and matched splits required |

Validation command: `python -m unittest discover -s tests -p 'test_hardware_nonce_store.py' -v`
Next: test committed code on full checkout, measure capacity and disk-growth behavior, design epoch-bound replay expiration with authenticated time and rollback resistance before enabling eviction. Do not merge this draft.

## 2026-11-17 nonce capacity experiment harness

Implemented `research_contracts/bench_nonce_capacity.py` (commits d345a64, 12d6d3a). The harness creates a real temporary SQLite database, performs measured admission attempts, records per-attempt monotonic latency, SQLite main/WAL bytes and platform-dependent process max RSS, and asserts replay rejection after reopening. It exports raw CSV and prints descriptive summary; no results are precomputed or claimed. Windows RSS is omitted rather than fabricated.

Execute:
`python research_contracts/bench_nonce_capacity.py --capacity 200 --samples 300 --output results/nonce_capacity_raw.csv`

**Not yet run against repository checkout:** git remote DNS lookup failed in execution environment. No measured runtime or significance claim. This is a capacity/fault microbenchmark, NOT publication-quality independent attack evidence. Next: run on checkout, independently validate raw CSV against actual SQLite records, then add matched concurrent honest/adversarial ingress experiments and independent incident-level dataset ground truth. Keep PR draft.

## 2026-11-17 reprovisioning and authenticated fault tests

| Workstream | Status | Evidence / limitation |
| --- | --- | --- |
| Crash/recovery provisioning | Implemented, tests pending | fcb62dd: explicit provisioning refuses any existing path, preventing silent loss of replay history |
| Recovery regression | Committed, not executed | b82783e: existing nonce and unrelated database preservation |
| Real signed-envelope adversarial tests | Committed, not executed | 6c38351: production envelope builder/verifier with SQLite, replay after restart, payload tamper, capacity fail closed |
| Hardware ingress / emergency control | Partial / blocked | no physical device or independent interlock verification |
| Research evidence | Not publishable | tests are deterministic safety checks, not independent multi-seed comparative experiments |
| Main merge | Blocked | repository checkout unavailable; run full CI and inspect main drift before merge |

Commands:
`python -m unittest discover -s tests -p 'test_hardware_nonce_store.py' -v`
`python -m unittest discover -s tests -p 'test_authenticated_durable_replay.py' -v`

Next: run full repository tests, add reproducible authenticated multi-client socket attack harness with matched honest and malicious workloads, record raw latency/resource outcomes and independent trial seeds. Preserve default-deny remote actuation.

## Concurrent nonce contention checkpoint

Implemented `research_contracts/bench_concurrent_nonce.py` (commit 4e048fe) and `tests/test_concurrent_nonce_experiment.py` (commit 6da8f31). Real SQLite shared-store transactions are exercised by concurrent threads, with paired fresh/replay nonces, per-attempt monotonic latency, explicit outcomes and seed-tagged raw CSV. The assertion prevents accepting the same nonce twice regardless of scheduling order. Capacity saturation is tested independently.

Run:
`python -m unittest discover -s tests -p 'test_concurrent_nonce_experiment.py' -v`
`python research_contracts/bench_concurrent_nonce.py --seed 20261117 --workers 8 --attempts 400 --capacity 200 --output results/concurrent_nonce_seed_20261117.csv`

Status: IMPLEMENTED / UNEXECUTED. This is a **component-level concurrency benchmark**, not TCP ingress, malicious enrolled-node, CAN dataset or physical safety evidence. No raw results or statistical conclusions yet. Next code task: authenticated multi-client loopback harness against production Pi TCP and independent repeated-seed experiments with raw results; do not merge draft without verified tests.

## Paired concurrency experiment validity correction — 2026-11-17

Completed (code, unexecuted): `research_contracts/bench_concurrent_nonce.py` now uses seeded shuffled submission and neutral `first_copy`/`second_copy` labels. Previous `fresh`/`replay` labels were scientifically invalid: a scheduler can admit the nominal replay copy first, and neither copy is independently known malicious. The experiment checks exactly two copies per pair and no more than one accepted claim before writing CSV. Regression tests cover seeded ordering, pair completeness and odd-count rejection.

Status: implementation complete; repository tests not run; no raw measured results or independent samples. The shuffled paired SQLite component workload is not an authenticated TCP attack, CAN/V2X dataset, or publication-quality effect estimate. Upcoming: run `python -m unittest discover -s tests -p 'test_concurrent_nonce_experiment.py' -v`, verify actual outputs, then implement authenticated TCP paired workload with explicit sender-role ground truth, synchronized network baseline, and per-seed independent runs. Main remains unchanged.

## 2026-11-17 authenticated attack benchmark checkpoint

Implemented `research_contracts/bench_authenticated_envelope_attacks.py` (7785c80, 08c4391) and `tests/test_authenticated_attack_benchmark.py` (68ecffd). Production HMAC envelope builder and verifier plus real SQLite nonce gate are used. Each seeded run primes legitimate nonces, then randomly orders independently labeled fresh honest, exact replay, and MAC-tampered envelopes; records raw per-trial outcome and monotonic latency. Security assertions block CSV export if any mismatch. This is a component-level bench, **not** a TCP/network or physical V2X result. Seeds represent separate experiment runs; trials within a seed are dependent.

Run `python -m unittest discover -s tests -p 'test_authenticated_attack_benchmark.py' -v` and `python research_contracts/bench_authenticated_envelope_attacks.py --seed 17 --pairs 100 --output results/authenticated_attacks_seed17.csv`. Commands not executed this run: git checkout failed with DNS error resolving github.com. No measured results or passing tests claimed.

Status: authenticated replay/tamper experiment code implemented, unverified; production TCP multi-client attack experiment pending; malicious enrolled-node false data, dataset provenance, independent baseline and hardware interlock blocked. Next implement actual loopback listener harness with matched workload and non-actuating receiver, validate on full checkout, and measure independent seed-level effect sizes. PR remains draft.

## 2026-11-18 signed-control boundary and enrolled false-data negative control

| Workstream | Status | Artifact |
| --- | --- | --- |
| Signed event DEL (U+007F) admission | Implemented; test pending | hardware_transport_security.py; signed builder and verifier share telemetry validator |
| Event regression | Committed, not executed | tests/test_authenticated_event_control_boundary.py |
| Malicious enrolled sender negative control | Implemented, not executed | research_contracts/bench_enrolled_false_data_negative_control.py; independently assigned false-data labels, signed schema-valid values, raw trial CSV |
| Scientific inference | Blocked | A MAC is authentication, not truth. Negative control intentionally has no external physical ground truth or realistic dataset; cannot be used as effectiveness evidence |
| Safety | Blocked | Remote actuation remains disabled; physical independent emergency control unverified |
| Network evaluation | Upcoming | Paired TCP workload under safe loopback; measure false positives, availability, latency and resource use |

Commands:
`python -m unittest discover -s tests -p 'test_authenticated_event_control_boundary.py' -v`
`python research_contracts/bench_enrolled_false_data_negative_control.py --seed 17 --trials 100 --output results/enrolled_false_data_17.csv`

No new runtime measurements or test-pass assertions. PR remains draft. Next: independent sensor corroboration/evidence-gated admission with explicit safety isolation and matched baselines; collect authentic VeReMi NextGen/CAN provenance before publication claims.

## 2026-11-18 evidence-gated event admission prototype

| Workstream | Status | Evidence / limitations |
| --- | --- | --- |
| Independent-group event admission | Implemented as isolated prototype, unverified | `v2x_evidence_gate.py`; requires target plus distinct trust-group witness, authenticated freshness, incident agreement, bounded witness set |
| Command isolation | Prototype property only | `AdmissionDecision.command_authorized` always false; production actuator not wired to gate |
| Deterministic safety properties | Committed, tests not executed | `tests/test_v2x_evidence_gate.py` covers group collusion, stale/future/unauthenticated, conflicting, duplicate and capacity cases |
| Trust-group enrollment | BLOCKED | Group labels supplied by caller; no authenticated independent enrollment or Sybil-resistant trust-group authority |
| False-data robustness | BLOCKED | Multiple colluding independent groups can jointly fabricate; no physical sensor corroboration |
| Production integration | Upcoming | Verify against real signed event/ledger pipeline; preserve emergency-stop isolation |
| Scientific evidence | Not ready | No independent dataset, measured baselines or statistical evidence |

Research hypothesis (unproven): independently enrolled, freshness-bounded group corroboration lowers false hazard-event admission under a single compromised group relative to authentication-only admission, with a measurable honest-event availability and latency cost. Compare authentication-only, sender-count quorum, and independent-group quorum using the SAME independently labeled incident scenarios. Avoid assuming trust-group independence when groups share infrastructure or credentials. Neither a new cryptographic primitive nor a physical safety certification is claimed.

Run: `python -m unittest discover -s tests -p 'test_v2x_evidence_gate.py' -v`.
No tests executed in this run; no result or effect size claimed. PR remains draft.

## 2026-11-18 paired evidence baseline checkpoint

| Workstream | Status | Evidence / limitation |
| --- | --- | --- |
| Paired synthetic baselines | Implemented, repository tests pending | research_contracts/bench_evidence_baselines.py; authentication-only, sender-count quorum, independent-group gate share each incident's truth and observations |
| Methodology regression | Committed, tests pending | tests/test_evidence_baselines.py; paired truth, deterministic seeds, invalid parameters |
| Local exploratory execution | Partial, NON-PUBLISHABLE | Isolated local copy of gate logic with seed=17, 1000 incidents, 4 devices, 1 malicious device: auth-only 108 false admissions/124 misses; sender-count 0/0; independent-group 0/494. This was NOT a repository checkout run; do not cite as scientific effectiveness evidence |
| Threat realism | Blocked | Synthetic perfectly honest noncompromised devices and fixed independent groups; malicious enrolled nodes can coordinate across groups; no VeReMi NextGen or CAN provenance |
| Network latency and resource measurement | Pending | No real TCP experiments or hardware claims |
| Physical actuation | Unverified | No hardware or independent emergency stop verification |
| Publication | Blocked | No authentic datasets, repeated independent seeds, uncertainty, or matched realistic attack workload |

Execute `python -m unittest discover -s tests -p 'test_evidence_baselines.py' -v` and `python research_contracts/bench_evidence_baselines.py --seed 17 --trials 1000 --output results/evidence_baselines_seed17.csv`. Synthetic outcomes demonstrate a potential **availability cost**, not superiority. Next code task: add coordinated multi-group attacker models, honest sensor error, incident-level split provenance and matched seed experiments; then production non-actuating TCP testing. Keep PR draft; do not merge.

## 2026-11-18 dissent-tolerant evidence quorum comparator

| Workstream | State | Evidence / limitation |
| --- | --- | --- |
| Independent-group corroboration ablation | Implemented | `research_contracts/robust_group_policy.py` counts only unconflicted groups; negative groups do not automatically veto positive quorum |
| Safety/limitation regression | Implemented; isolated local equivalent passed | `tests/test_robust_group_policy.py`: five cases covering dissent, same-group duplicate, conflict, stale and coordinated compromised groups |
| Repository regression validation | Pending | Full repository checkout and integrated test suite not executed in this run |
| Research originality | Hypothesis only | Compare strict-unanimity, dissent-tolerant quorum, sender-count quorum and authentication-only under identical incident splits |
| Critical threat assumption | Unverified | Trust-group assignments and sender identity must be authenticated externally; two compromised independent groups can still fabricate hazard admission |
| Physical actuation | Isolated by design | Comparator only returns event admission, never actuator permission; independent emergency-stop hardware remains untested |
| Dataset and statistical evidence | Blocked | Authentic VeReMi NextGen/CAN provenance and multi-seed matched results not yet collected |

Isolated Python equivalent of the comparator passed 5/5 deterministic tests on 2026-11-18. This verifies basic logic only, not repository CI or publication-grade empirical performance. Re-run on checkout:
`python -m unittest discover -s tests -p 'test_robust_group_policy.py' -v`

Next: paired seeded scenarios with independent group compromises, honest dissent, correlated errors, abstention, and timestamp faults. Measure false admissions, missed hazards and admission delay; compare with strict-unanimity and other baselines, then validate against authentic datasets. Do not merge draft without full CI.

## 2026-11-18 paired correlated-group stress protocol

**Completed (code committed, not executed):** `research_contracts/bench_correlated_group_threats.py` and `tests/test_correlated_group_threats.py` (a83ac65, 8206ae4, 9aea6fe). Four admission policies receive identical incident observations: authentication-only, sender-count quorum, strict independent-group unanimity, and dissent-tolerant group quorum. Controlled scenarios vary honest group-level sensor error, common-mode correlated error and enrolled group compromise. Raw per-incident labels and decisions export to CSV. Tests cover deterministic pairing, zero-error boundary, and coordinated compromise limitation.

**Partial:** Synthetic common-mode error is an explicit assumed generator, not a calibrated V2X model. Three trust groups and four devices are a limited toy topology. This experiment cannot establish real-world security or novelty. In particular a malicious enrolled group has authentic credentials; independence is assumed, not attested. No hardware/actuator authorization occurs.

**Blocked:** Repository execution and full tests, authentic VeReMi NextGen/CAN provenance, real incident labels, physical local stop verification, network DoS/latency and independent multi-seed inference. No results or p-values claimed. Statistical significance cannot be inferred from n>=30.

**Upcoming:** Run `python -m unittest discover -s tests -p 'test_correlated_group_threats.py' -v`; then `python research_contracts/bench_correlated_group_threats.py --seed 17 --trials 1000 --compromised-groups 1 --honest-error .05 --correlated-error .05 --output results/correlated_group_seed17.csv`. Review paired raw labels, expand compromise levels 0..3 and independent seeds, then integrate non-actuating authenticated TCP workload and authentic dataset ingest. Keep PR #141 draft pending actual validation.

## 2026-11-18 paired baseline primary-selection bias correction

| Workstream | State | Evidence / limitation |
| --- | --- | --- |
| Authentication-only comparator primary selection | Implemented, unverified | Previously hard-coded device-0 from group A; now per-incident seeded uniform draw over four devices, recorded in auth_primary_sender |
| Paired policy ground truth | Preserved by construction, tests pending | All four policies receive identical observed_bits, truth, compromised-group assignment and selected primary metadata |
| Regression tests | Committed, not executed | Verify primary index maps to selected observed bit, all four device indices occur for seeded 200 incidents, and primary is not always device-0 |
| Measured baseline comparison | Blocked | No repository test execution or raw independently sourced incident results; historical baseline CSVs are not comparable without regeneration |
| Authenticated TCP / emergency stop | Partial / blocked | Component simulation cannot demonstrate physical interlock or stop reliability |
| Authentic dataset provenance | Upcoming | VeReMi NextGen and CAN license/source/checksum validation needed |
| Publication readiness | Blocked | No independent held-out real dataset, multi-seed effects or physical safety evidence |

Methodological note: a fixed first witness in group A artificially privileged one failure domain in the authentication-only comparator. Randomized primary selection removes that fixed-position selection artifact, but does not create a fair all-evidence authentication baseline or establish independent group enrollment. Keep the primary choice and its sampling model explicit in the manuscript. Do not compare newly generated CSV against older runs without regenerating all paired policies with identical seeds and parameters.

Commands:
`python -m unittest discover -s tests -p 'test_correlated_group_threats.py' -v`
`python research_contracts/bench_correlated_group_threats.py --seed 17 --trials 1000 --compromised-groups 1 --honest-error .05 --correlated-error .05 --output results/correlated_group_seed17.csv`

Next engineering task: design a pre-registered multi-seed factorial threat grid with independent incident-level truth, explicit primary selection, clustered confidence intervals and a no-actuation TCP loopback experiment. All changes remain unverified; do not merge.
