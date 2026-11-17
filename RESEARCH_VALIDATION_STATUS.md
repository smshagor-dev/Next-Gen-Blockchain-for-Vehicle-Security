# Research validation status — bounded TCP admission branch

Updated 2026-11-14. No publication or hardware safety certification is implied.

| Workstream | Status | Evidence / gap |
| --- | --- | --- |
| TCP admission capacity primitive | Implemented, unverified | BoundedSemaphore prevents unbounded handler threads; immediate socket close on saturation |
| Loopback saturation regression | Locally validated (isolated copy) | Two additional real loopback tests: partial-frame slow peer does not block independent admitted worker; saturated peer rejected without queue. Both passed locally 2026-11-13. Full repository CI pending |
| Integration with hardware_bridge.run_pi_mode | Implemented, unverified | Production accept loop now dispatches to bounded worker pool, with shared verifier and ledger/actuator locks; no full checkout tests or live fault injection yet |
| Shared verifier / token-bucket / ledger thread safety | Partial | Shared replay verification and chain/dispatcher serialized with locks, token bucket locked; full stress validation and lock-order review pending |
| Authenticated ingress / interlocks | Partial | Existing draft branch and main differ; no physical emergency stop evidence |
| Durable nonce and crash consistency | Partial | Simulation-only tests; no physical power-loss or rollback guarantee |
| Contract finality | Blocked | Mock finality is not consensus finality |
| Novel mechanism / formal properties | Upcoming | Independent prior-art comparison and falsifiable safety hypotheses |
| Authentic VeReMi NextGen and CAN datasets | Upcoming | Provenance and license verification required |
| Independent multi-seed adversarial evaluation | Blocked | Existing synthetic world experiments are not independent incident truth |
| Runtime scaling / statistical analysis | Blocked | No credible multi-seed system benchmark or effect-size report |
| Manuscript | Blocked | Fixture CSVs, three-peer sanity checks, five-iteration microbenchmarks and formulas are not publishable primary results |

## Validation commands
`python -m unittest discover -s tests -p 'test_bounded_tcp_admission.py' -v`
`python -m py_compile bounded_tcp_admission.py tests/test_bounded_tcp_admission.py`

Two new tests in tests/test_slow_peer_admission.py passed (2/2) in a local isolated copy of the fetched admission implementation; this does not validate the full GitHub checkout or production Pi server. Original branch tests were not run. Do not merge as a production DoS fix until integration and live fault-injection validation.

Additional command: `python -m unittest discover -s tests -p 'test_slow_peer_admission.py' -v`\n\nNew validation: `python -m unittest discover -s tests -p 'test_shared_tcp_budget.py' -v`. Not yet executed against full checkout; no passing claim.\n\n## Next coding task
Refactor the existing authenticated Pi per-connection loop into a worker function, wire this bounded admission, protect shared verifier replay state and global token buckets with locks, serialize ledger mutations, then test slow-client starvation and concurrent authenticated sessions on real loopback sockets.

## 2026-11-14 integration checkpoint
Production Pi accept loop refactored to bounded per-connection workers (max clients 1–64). Admission budget is charged before worker dispatch; saturated sockets are closed immediately. Shared verifier replay check-and-claim and ledger/dispatcher mutation now use separate locks. New AST integration guards added. Commits: 46d6f8f, e673cd6, 59dae5f. GitHub checkout DNS failed in this environment; **no repository tests executed**. These changes are not proof of resistance to distributed DoS, and physical emergency control is unchanged and unverified.

Next: execute `python -m unittest discover -s tests -p 'test_pi_worker_integration.py' -v` and existing socket tests on an actual checkout; perform simultaneous authenticated replay and Slowloris tests, review lock contention and remote actuator blocking, and do not merge until verified.

## 2026-11-14 byte-budget checkpoint
Pi TCP handler now counts all received bytes (including incomplete and invalid frames) and rejects sessions over SMARTCAR_HW_MAX_SESSION_BYTES before cryptographic verification. Default 262144 bytes; configuration clamped to 4096–8388608 bytes. Added tests/test_pi_session_byte_budget.py with two source-structure regression guards. Commits: 4e07d5b, 5075943. Tests not executed against a full checkout because GitHub DNS was unavailable locally. **Status: implemented, unverified.** These tests do not replace live socket experiments.

Next: run `python -m unittest discover -s tests -p 'test_pi_session_byte_budget.py' -v`, then authenticated loopback replay-race and trickle-byte tests against the production handler. Measure CPU, RAM, rejection latency and honest-client throughput with matched baselines; do not use fixture-only outcomes as primary paper results.

## 2026-11-14 byte-budget syntax repair checkpoint

**Implemented (unverified):** Repaired literal escaped newline sequences accidentally inserted into `hardware_bridge.py` Pi handler, which prevented Python parsing; initialized `received_bytes = 0` for each accepted connection before its receive loop. Added `tests/test_pi_byte_budget_compile_regression.py` to check source compilation and counter/guard AST ordering without importing hardware dependencies. Commits: `0a293793`, `4506a11b`. This is a correctness repair, **not** a demonstrated DoS mitigation.

**Validation blocked:** `git ls-remote https://github.com/smshagor-dev/Next-Gen-Blockchain-for-Vehicle-Security.git HEAD` failed with `Could not resolve host: github.com` in the local execution environment. No full-checkout tests executed. GitHub connector commits succeeded.

Run next: `python -m unittest discover -s tests -p 'test_pi_byte_budget_compile_regression.py' -v`, then `python -m unittest discover -s tests -p 'test_pi_session_byte_budget.py' -v` and authenticated real-loopback concurrency/replay tests. Do not merge until runtime and full regression validation; local hardwired emergency stop remains independent and unverified.


## 2026-11-14 counter initialization verification checkpoint

**Code repair:** Inspected the actual branch file through the GitHub connector and found the prior claimed initialization absent: `handle_client` incremented `received_bytes` before assignment. Added `received_bytes = 0` immediately before the receive loop (commit `1449102`). The existing `test_pi_byte_budget_compile_regression.py` specifically asserts one zero initialization preceding increment and limit guard; the previous branch would fail this assertion. This is a code correction, not evidence that the full test suite passes.

**Status:** Pi byte budget implemented, **execution unverified**. Physical actuation and emergency-stop behavior unverified. Next: run source guard and real authenticated loopback concurrent replay/trickle tests on a complete checkout; then review ledger and actuator lock contention. No main-branch merge or publishable experiment claimed.


## 2026-11-14 signed telemetry semantic validation checkpoint

**Implemented, not yet runtime verified:** Production hardware_bridge.to_telemetry now rejects NaN/Infinity, invalid numeric types and ambiguous safety boolean coercion before blockchain mutation; Pi handler catches malformed authenticated telemetry and closes that session. New executable AST-isolated regression tests in tests/test_signed_telemetry_type_safety.py cover non-finite values, safety booleans, valid finite telemetry and numeric bool rejection. Commits: a3602fb, 4765209. Scope is semantic admission hardening, not cryptographic novelty or physical actuator certification.

**Validation:** GitHub connector writes succeeded; local git ls-remote failed with DNS resolution of github.com, so full checkout and tests were not run. Run: `python -m unittest discover -s tests -p 'test_signed_telemetry_type_safety.py' -v`; then full suite and authenticated real-loopback race/Slowloris tests. Existing fixture data, microbenchmarks and communication formulas remain non-publishable primary evidence.

**Next code task:** exercise the production Pi TCP server with authenticated concurrent loopback sessions and malformed-but-valid-MAC telemetry, then evaluate ledger crash consistency and safe actuation isolation. Do not merge without verification.


## 2026-11-14 strict JSON numeric admission checkpoint

**Code change:** Authenticated telemetry numeric fields now accept only JSON numeric types (Python int/float, excluding bool), not numeric-looking strings or containers. Finite-value checks remain in force. This prevents MAC-valid but schema-ambiguous strings such as `"0"` and `"12.5"` from being silently converted before ledger admission. Added regression cases for string/container rejection and valid integer/float preservation. Commits `f709b87`, `55c9af0`.

**Verification:** GitHub writes succeeded. Local `git ls-remote` failed with `Could not resolve host: github.com`, so full-checkout tests were not executed; **implemented, unverified**. Run `python -m unittest discover -s tests -p 'test_signed_telemetry_type_safety.py' -v` on the branch. Review upstream sensor producers for any legacy string-encoded measurements before merging.

**Next code task:** Add real authenticated concurrent loopback socket tests for production Pi ingress, including malformed-but-valid-MAC numeric strings, replay races, trickle-frame exhaustion, and worker recovery. Keep physical safety and publishability claims blocked.

## 2026-11-14 outbound network lock-isolation checkpoint

**Implemented, not runtime-validated:** Pi handler now releases the global ledger mutation lock before calling the potentially blocking socket-based `actuator.maybe_send_pi`. A separate `actuator_lock` serializes shared dispatcher cooldown and command state. Added `tests/test_pi_lock_isolation.py` with AST assertions that the ledger lock contains `push_telemetry` but not remote actuation. Commits: `8eccf3c`, `4994bf5`. This reduces cross-client head-of-line blocking from outbound sends but does not establish real-time guarantees or safe physical actuation.

**Validation:** GitHub connector writes succeeded; local checkout could not be cloned due to DNS failure. Neither full-suite nor new regression tests were executed in the repository. Command: `python -m unittest discover -s tests -p 'test_pi_lock_isolation.py' -v`.

**Next:** Test concurrent signed telemetry on real loopback sockets while a remote command receiver intentionally stalls; measure ledger progress and worker recovery. Review actuator lock hold time and use of blockchain state outside ledger lock; run full suite before merging. Local emergency-stop remains independent and physical safety is unverified.


## 2026-11-14 monotonic bench stop cooldown checkpoint

**Implemented:** SafeModeActuatorDispatcher now uses time.monotonic() for its cooldown check and successful Arduino/Pi send timestamps, with an explicit None sentinel for the first eligible stop. Wall-clock adjustments can no longer extend or bypass this local rate-control interval. The independent local emergency control is untouched. Commit: 7db3270. Added executable isolated dispatcher tests (commit c382ab5), including first-command eligibility, cooldown expiry, disarmed gate and inactive safe-mode rejection.

**Evidence:** Four assertions on an independently recreated cooldown logic snippet passed in local Python; this is NOT execution of the checked-in regression test or full hardware_bridge module. GitHub checkout DNS resolution remains unavailable. Run `python -m unittest discover -s tests -p 'test_actuator_monotonic_cooldown.py' -v` on a checkout, then complete full suite and authenticated loopback faults before merging. No physical actuation or independent emergency-stop evidence; not a publishable experimental result.

**Next task:** Exercise production Pi ingress with concurrent authenticated loopback sessions, replay races, slow receivers and measured rejection latency. Verify dispatcher command serialization does not starve honest sessions; then address durable ledger crash consistency.


## 2026-11-14 required signed safety-state checkpoint

**Implemented, not runtime verified:** Authenticated telemetry conversion now requires explicit `emergency_brake_active` and `driver_unwell` fields. Previously absent fields silently defaulted to false, making an omitted safety condition indistinguishable from an authenticated safe reading. No hardware actuation or independent emergency-stop path changed. Commit `07585114`.

**Regression coverage:** `tests/test_required_signed_safety_fields.py` uses AST-isolated executable tests for explicit safe values, missing brake state, missing driver state, ambiguous boolean and non-finite numeric rejection (commit `f9f23ef`). No test execution against full checkout in this run. Command: `python -m unittest discover -s tests -p 'test_required_signed_safety_fields.py' -v`. Existing signed producers must be checked for compatibility before merging.

**Status matrix:** Signed schema admission = partial, pending producer compatibility and authenticated loopback validation. Hardware actuation = blocked pending independent interlock verification. Ledger crash consistency = partial. Dataset provenance, independent multi-seed adversarial baselines and publishable statistical evidence = blocked. **Next code task:** production authenticated concurrent loopback replay and slow-receiver tests; verify fail-closed missing-field rejection before ledger writes. No publishable primary result or hardware safety certification claimed.


## 2026-11-14 concurrent signed-envelope executable regression checkpoint

**Implemented (commit ee22673):** Added `tests/test_concurrent_signed_envelope_security.py` with a real 32-thread barrier race against the shared enrolled-device verifier, requiring exactly one accepted nonce and 31 replay rejections. Added a tampered-payload/MAC rejection test ensuring a failed forgery cannot consume the legitimate nonce, plus a cross-session identity-binding rejection test ensuring the legitimate nonce remains usable. These use production cryptographic transport primitives rather than source-only AST checks. No hardware or real network is exercised.

**Validation:** Reviewed verifier implementation: MAC is checked before identity/payload checks; nonce claim occurs under its internal RLock. GitHub file write succeeded. Tests have **not** been executed against a full checkout, so results and branch compatibility remain unverified. Run `python -m unittest discover -s tests -p 'test_concurrent_signed_envelope_security.py' -v`, followed by full suite. No statistical or publication claim.

**Matrix update:** Concurrent replay/tamper regression = implemented, execution pending. Authenticated production loopback and independent emergency control = blocked/unverified. Durable ledger crash consistency = partial. Authentic datasets, independent baselines, multi-seed statistics = upcoming/blocked.

**Next code task:** Build real production `run_pi_mode` loopback integration harness with ephemeral port, concurrent signed clients and a stalled peer, asserting accepted chain mutations and worker recovery; collect measured timings without treating these regressions as independent scientific experiments.


## 2026-11-14 authenticated socket-session regression checkpoint

**Implemented:** Added `tests/test_authenticated_socket_session.py` (commit `d020e108`) exercising real local socketpair delivery with fragmented signed envelopes, a replay across distinct connection-session objects sharing one verifier, MAC tamper followed by valid nonce acceptance, and missing signed safety-state rejection. This exercises production `AuthenticatedPiTelemetrySession`, verifier and telemetry conversion, but **not** the full `run_pi_mode` accept loop, ledger mutation, hardware, or actuator dispatch.

**Evidence:** File created on draft PR #101 branch. Local `git ls-remote` failed because github.com DNS resolution was unavailable; no full-checkout test execution, passing assertion, timing or paper-level outcome is claimed. Execute `python -m unittest discover -s tests -p 'test_authenticated_socket_session.py' -v` on a complete checkout, followed by the full suite. Any failing assumptions about envelope schema or frame delivery must be corrected before review.

**Status matrix:** Signed TCP session framing/replay = implemented regression, unverified execution; production accept-loop fault injection = blocked; local emergency-stop = untouched, physically unverified; ledger durability = partial; original mechanism and real datasets = upcoming; independent adversarial baselines/statistics = blocked; manuscript evidence = blocked. Existing fixture CSVs, 3-peer sanity checks, 5-iteration microbenchmarks and offline formulas remain NON-PUBLISHABLE primary evidence.

**Next substantive task:** Make the production `run_pi_mode` accept loop testable with injected socket/stop controls; execute concurrent authenticated loopback clients, stalled receiver and byte-budget exhaustion, collecting bounded runtime metrics and verifying that no rejected input mutates the ledger. Review crash-consistent ledger writes next. Do not merge unverified work.


## 2026-11-14 concurrent admission budget test checkpoint

Added `tests/test_global_admission_budget_concurrency.py` (commit `84b93a9`) to exercise the **actual production** `GlobalTelemetryBudget` imported from `hardware_bridge`: 32 simultaneous claimants against burst 7 must yield exactly seven admissions; long clock advances must not refill beyond burst; backward clock movement must not manufacture tokens. This is an executable regression suite, **not yet executed** in a full checkout. No claim of runtime throughput or distributed DoS protection. Run `python -m unittest discover -s tests -p 'test_global_admission_budget_concurrency.py' -v`. Next: production Pi TCP integration with simultaneous authenticated peers, then compare lock contention and legitimate-client admission latency against a controlled baseline. Physical HIL and external incident ground truth remain blocked; existing fixture/microbenchmark results are non-publishable.


## 2026-11-14 production handler loopback regression checkpoint

Added `tests/test_production_pi_handler_loopback.py` (commit `f639b838`) to compile the actual nested `run_pi_mode.handle_client` function from production source and exercise it using OS socket pairs, the real envelope verifier, shared replay cache, and a recording ledger. Cases: fragmented signed frame, concurrent replay across twelve connections, partial-frame byte exhaustion, and recovery after malformed input. Hardware actuation is replaced by a no-op, so this cannot validate physical interlocks. **Not executed against the full repository** because local GitHub DNS resolution failed; these are test implementations, not passing experimental findings. Run `python -m unittest discover -s tests -p 'test_production_pi_handler_loopback.py' -v` and fix any failures before merging. Next: add controlled stalled-receiver latency measurements and ledger crash/restart durability checks. Existing fixture and microbenchmark results remain non-publishable.


## 2026-11-16 receiver session invalidation checkpoint

- **Implemented (unverified):** `research_contracts/test_receiver_fault_model.py` now poisons the simulated receiver session after an invalid frame header, oversized transport chunk, authentication/replay rejection, or excessively nested JSON parsing. Subsequent frames on the same receiver are rejected; a new receiver instance represents a fresh transport connection. Three regression tests added for tamper reuse, invalid-header reuse, and deeply nested JSON. Prior oversized-chunk regression updated to expect connection termination.
- **Scope:** isolated model only. Production `hardware_bridge` transport teardown, persistent replay storage, local emergency control, and power-loss behavior remain unverified. This does not establish DoS resistance or hardware safety.
- **Validation:** GitHub connector commit succeeded, but checkout/testing unavailable because `git ls-remote` failed with `Could not resolve host: github.com`. No test pass is claimed. Run `python -m unittest discover -s research_contracts -p 'test_receiver_fault_model.py' -v` and `python -m unittest discover -s research_contracts -p 'test_*.py' -v` before review.
- **Next:** enforce production socket teardown on rejected frames and run live loopback fragmentation/slow-peer/concurrent-client fault injection, preserving local emergency-stop precedence. Keep draft and do not merge without tests.

## 2026-11-16 durable replay storage fault session teardown

**Implemented, unverified (commit e7dd0836):** The isolated bounded receiver now poisons its transport session on unexpected exceptions from the durable replay gate, including injected OSError during SQLite/storage admission. Previously such exceptions escaped without setting `poisoned`, allowing a subsequent frame on the same session. Added two regression cases for storage exceptions and explicit durable-gate rejection. This is simulation-only and does not prove production receiver behavior or disk durability.

**Test commands (not executed in full checkout):** `python -m unittest discover -s research_contracts -p 'test_receiver_fault_model.py' -v` and `python -m unittest discover -s research_contracts -p 'test_*.py' -v`.

**Matrix:** Receiver storage-fault fail-closed = implemented/unverified; production bridge teardown = partial; physical emergency independence = unverified; ledger crash/power-loss = partial/blocked; authentic independent incident truth = blocked; multi-seed matched experiments and paper = blocked. Existing fixture CSVs, 3-peer sanity check, five-iteration microbenchmarks and communication formulas remain non-publishable primary evidence.

**Next code task:** Integrate equivalent storage-error teardown in production Pi ingress, exercise actual loopback sockets under concurrent replay and slow-peer faults, and record measured latency/CPU/RAM under identical baselines. Keep draft PR pending executable validation.

## 2026-11-16 cumulative receiver byte-budget checkpoint

**Implemented, execution unverified:** Isolated authenticated receiver now charges all input bytes across repeated `feed()` calls, including incomplete frames, before parsing or MAC verification. A per-connection default 262144-byte ceiling (configurable between 4096 and 262144 bytes) poisons the session and clears partial framing on exceed. Three regression cases cover one-byte fragmented authenticated frames, valid traffic consuming the budget, and invalid budget configuration. Commits `8429892c`, `bd499990`; existing Draft PR #141. This is a bounded-resource *simulation*, not evidence of production DoS resistance.

**Validation:** GitHub connector writes succeeded; local `git ls-remote` failed DNS resolution of github.com. Committed suite not executed. Run `python -m unittest discover -s research_contracts -p 'test_receiver_fault_model.py' -v` and full tests. Existing production Pi bridge has separate byte-budget logic but has not been jointly exercised with this model.

**Matrix:** Cumulative simulation ingress budget = implemented/unverified; production socket fault experiments = partial/unverified; local emergency hardware control = unverified; ledger finality = blocked; authentic incident ground truth = blocked; matched multi-seed independent experiments = upcoming; manuscript = blocked. Fixture CSVs, 3-peer poisoning sanity, 5-iteration microbenchmarks and offline formulas remain non-publishable primary evidence.

**Next code task:** Run real loopback socket fault-injection on production Pi handler with fragmented signed frames and stalled peers, measure rejection latency, CPU, RAM, and honest-client throughput against a matched baseline. Audit storage crash/restart replay persistence before any merge.


## 2026-11-16 receiver frame-budget preflight checkpoint

**Implemented, execution unverified:** Commit `b065f9d` preflights the number of complete length-prefixed frames in each input chunk before mutating the durable replay gate. A fully present over-budget batch now fails closed without consuming its first replay sequence. Updated prior regression expectations and added a recording durable-gate regression. This closes only the *known frame-count overflow partial-commit case*; malformed or rejected later frames can still leave earlier authenticated commits, and neither general batch atomicity nor crash consistency is established.

**Validation command:** `python -m unittest discover -s research_contracts -p 'test_receiver_fault_model.py' -v`. Not executed against the committed branch; no pass claim. The parser preflight copies bounded chunk data and should be benchmarked against trickle/fragmented input before production use.

**Status:** complete-frame count preflight = implemented/unverified; production hardware ingress and independent emergency-stop = partial/unverified; general multi-frame transaction semantics = blocked pending design; authentic V2X/CAN dataset provenance, independent attack baselines, effect-size statistics = blocked; publishable research = not ready.

**Next code task:** design explicit per-frame admission delivery or transactional replay-store batch API, and validate the production Pi handler using real authenticated loopback sessions with injected malformed second frames, replay races, slow clients and resource measurements. Keep PR draft; no hardware or scientific efficacy claim.


## 2026-11-16 receiver fragmented-body preflight repair

**Implemented (unverified):** Commit df9b3646 fixes the receiver's frame-count preflight to retain partial frame-body bytes across successive feed() calls. Previously, when expected was set, preflight discarded self.buffer, potentially parsing a legitimate continuation as an invalid frame and poisoning the session. Added two regressions: fragmented body plus next frame succeeds; fragmented body plus an over-budget second frame rejects before consuming the first replay sequence. This is a simulation-only correctness/security regression, not publishable experimental evidence.

**Validation pending:** Execute `python -m unittest discover -s research_contracts -p 'test_receiver_fault_model.py' -v` and the full repository suite on a checkout. No passing tests or real hardware/network metrics are claimed in this run.

**Matrix:** receiver fragmented-body preflight = implemented/unverified; general batch atomicity = partial; production hardware bridge and emergency control = unverified; ledger crash consistency = partial; authentic dataset experiments and independent statistical baselines = blocked; paper = not ready.

**Next code task:** implement explicit per-frame delivery semantics or a transactional replay batch API; test malformed second-frame behavior and crash rollback with real loopback sockets before merge.


## 2026-11-17 malformed-later-frame preflight checkpoint

**Implemented, execution unverified:** Receiver fault model now parses JSON syntax (including nested duplicate-key rejection and non-finite constants) for every complete frame in a feed batch before any durable replay admission. This prevents a syntactically malformed second frame from silently consuming the first valid frame's nonce when no events are returned. Two executable regression cases cover malformed trailing JSON and duplicate keys in the second frame. Commit `82eb47d7`.

**Limitations:** This is isolated simulation, not production Pi integration. It is NOT general batch atomicity: a later frame with valid JSON but invalid MAC, replay sequence or failed storage can still follow an earlier durable commit. A true transactional batch gate or explicit per-frame delivery contract remains necessary. Local emergency controls were not modified. No physical safety or scientific performance result claimed.

**Validation:** `git ls-remote https://github.com/smshagor-dev/Next-Gen-Blockchain-for-Vehicle-Security.git HEAD` failed with `Could not resolve host: github.com` on 2026-11-17. Connector commit succeeded, but checked-in tests could not run in the local container. Execute `python -m unittest discover -s research_contracts -p 'test_receiver_fault_model.py' -v` and full suite before merging.

**Matrix:** complete-frame JSON syntax preflight = implemented/unverified; general replay batch atomicity = partial; production ingress = partial; emergency-stop physical independence = unverified; ledger crash consistency = partial; real dataset provenance and independent adversarial comparisons = blocked; publication-ready evidence = blocked.

**Next code task:** Add a transactional multi-frame durable replay admission API or explicit one-frame-at-a-time delivery, then real production loopback socket fault injection with measured matched-baseline resource costs.


## 2026-11-17 complete-frame MAC preflight checkpoint

**Implemented, execution pending:** Isolated receiver `research_contracts/test_receiver_fault_model.py` now checks schema, node enrollment, signed sequence range and HMAC on *every fully buffered frame* before any per-frame durable replay-store admission. This prevents a valid first frame's durable nonce from being consumed when a later complete frame in the same `feed()` call has a bad MAC. Two new executable regressions cover coalesced and fragmented-first-frame cases. Commit `6c866b4` on draft PR #141.

**Important scope limit:** This is not transactional multi-frame admission. A later replay rejection or injected storage failure can still occur after an earlier commit. A complete frame received in an earlier `feed()` call is separately admitted; this change does not roll back prior calls. A transactional batch API or explicit per-frame delivery contract remains necessary. MAC preflight performs additional verification work and needs bounded latency measurements.

**Validation:** GitHub connector write succeeded; no checkout-based execution was performed in this run. Run `python -m unittest discover -s research_contracts -p 'test_receiver_fault_model.py' -v`, then full regression suite and real production loopback experiments. No empirical effectiveness, hardware safety, or publication-ready result is claimed.

**Matrix:** complete-frame syntax + MAC preflight = implemented/unverified; batch atomicity = partial; production ingress/independent local emergency control = partial/unverified; crash consistency and mock finality = partial; authentic VeReMi NextGen/CAN provenance = blocked; independent matched multi-seed attacks, ablations, latency/CPU/RAM/throughput = upcoming; original research manuscript = blocked until validated evidence. Existing fixtures, 3-peer poisoning sanity checks, 5-iteration microbenchmarks and offline formulas are NON-PUBLISHABLE primary evidence.

**Next code task:** Design explicit per-frame delivery semantics or SQLite transactional batch admission and test later-frame replay/storage rejection without invisible nonce consumption. Then execute production authenticated loopback concurrent replay/slow-peer fault campaign and collect independent baseline metrics.


## 2026-11-17 coalesced replay-order preflight checkpoint

**Implemented, not yet executed:** Commit efafb27 adds a preflight monotonic sequence check for complete frames in one feed batch before any replay-store mutation. Duplicate and decreasing authenticated sequences within the same coalesced batch now reject and poison the session before the first replay-gate call. Added two executable regression tests, including a recording gate that must remain untouched. This only covers within-batch ordering, **not** durable-gate rejection against preexisting stored high-water marks or transactional multi-frame storage failure. No physical actuation changes.

**Validation pending:** `python -m unittest discover -s research_contracts -p 'test_receiver_fault_model.py' -v`; then full `research_contracts` suite and production loopback socket tests. No test pass, measured performance, or publication-level evidence is claimed for this change.

**Matrix:** coalesced replay-order preflight = implemented/unverified; general atomic replay batch = partial; production authenticated Pi integration and emergency interlock = partial/unverified; crash consistency = partial; authentic incident datasets and matched adversarial experiments = blocked; statistical manuscript evidence = blocked.

**Next code task:** add an atomic `admit_authenticated_batch` SQLite transaction with rollback-on-replay/storage-fault and test against restart; preserve per-frame delivery semantics or ensure all-or-nothing caller visibility. Then execute production loopback slow-peer/concurrent replay fault injections with honest-client latency and resource measurements. Fixture-only and microbenchmark outcomes remain non-publishable.


## 2026-11-17 atomic SQLite replay batch primitive

**Implemented, not yet integrated:** Added `research_contracts/sqlite_atomic_replay.py` with SQLite `BEGIN IMMEDIATE` multi-node replay high-water admission, rollback on stale/duplicate later entries and exception, strict authenticated caller flag, and persisted high-water after normal close/reopen. Added `research_contracts/test_sqlite_atomic_replay.py` covering later stale entry rollback, duplicate-in-batch rollback, restart, unauthenticated rejection and invalid input. Commits bc67dba, b8f12a9.

**Verification:** GitHub writes succeeded; checked-in tests not executed in this run. Run `python -m unittest discover -s research_contracts -p 'test_sqlite_atomic_replay.py' -v` followed by receiver tests. No crash/power-loss durability or concurrency guarantee has been experimentally established. SQLite local atomic commit is NOT distributed blockchain finality.

**Status matrix:** SQLite atomic batch gate = implemented/unverified; receiver integration = upcoming; production TCP ingress = partial; emergency hardware interlocks = blocked; independent multi-seed adversarial experiments and authentic datasets = blocked; paper = not ready. Existing fixture CSVs, 3-peer poisoning sanity check, five-iteration microbenchmarks and offline formulas are NON-PUBLISHABLE primary evidence.

**Next code task:** Wire `BoundedReceiver.feed` to `admit_authenticated_batch` only after full frame/MAC preflight, return events only after successful commit; test second-frame replay and injected SQL failures with no earlier sequence consumption. Then execute real production Pi loopback tests.


## 2026-11-17 atomic receiver integration checkpoint

**Implemented, execution pending:** BoundedReceiver now calls SQLiteAtomicReplayGate.admit_authenticated_batch for every complete authenticated frame in one feed() call before returning events. A rejected batch poisons the session; the SQLite gate rolls back all high-water updates on a later stale sequence. Added test_receiver_atomic_batch_integration.py covering cross-node later-frame disk replay rejection, rejected-batch state, normal reopen persistence, and injected SQLite error. Commits: 0f714734, d784f8d4, 6eabfe3b.

**Important limits:** Atomicity is scoped to complete frames within a single feed() call, not across different socket reads or across ledger/actuator side effects. Legacy replay gates exposing only admit_authenticated still use non-atomic per-frame admission; production should require the batch API for coalesced frames. SQLite normal reopen is not power-loss evidence. No hardware actuation or independent emergency-stop verification was performed.

**Validation:** GitHub connector changes succeeded; local git ls-remote failed with 'Could not resolve host: github.com'. No checked-in tests executed, no performance results claimed.

**Matrix:** simulation batch integration = implemented/unverified; legacy-gate fallback = partial/risk; production hardware ingress and interlocks = partial/unverified; ledger crash durability = partial; authentic datasets = blocked; independent matched multi-seed adversarial experiments = pending; paper = blocked. Fixture CSVs, three-peer sanity checks, five-iteration microbenchmarks, and offline formulas remain non-publishable primary evidence.

**Next:** run python -m unittest discover -s research_contracts -p 'test_receiver_atomic_batch_integration.py' -v and full research_contracts suite on a complete checkout. Then eliminate unsafe legacy batch fallback, test SQLite concurrent sessions and injected transaction failures, and wire production Pi loopback to the verified gate without compromising local emergency control.


## 2026-11-17 concurrent SQLite replay checkpoint

**Implemented, execution pending:** Shared SQLiteAtomicReplayGate now serializes the full BEGIN IMMEDIATE/validate/write/COMMIT transaction with an RLock, uses check_same_thread=False for concurrent Pi-style workers, and applies the configured timeout to SQLite busy_timeout rather than silently hardcoding 5 seconds. Commits: be4b539, 9b70c6d. Three new regression tests cover 16-worker same-nonce contention, independent SQLite connections racing on a shared database, and timeout validation. These tests have **not** been executed on the checked-out branch; no performance, durability, or physical safety claim follows.

**Validation command:** `python -m unittest discover -s research_contracts -p 'test_sqlite_concurrent_replay.py' -v`; then run the existing SQLite and receiver integration suites. **Status matrix:** concurrent replay transaction serialization = implemented/unverified; production bridge integration = partial; emergency interlock = unverified; crash durability = partial; authentic dataset provenance and independent multi-seed baseline experiments = blocked; paper primary evidence = not ready.

**Next code task:** integrate the shared gate into the production Pi handler (not just research receiver simulation), run actual authenticated loopback concurrent replay/slow-peer/storage-failure tests, and record rejection latency and honest throughput under matched baselines. Review multi-process SQLite locking, crash injection, and actuator isolation before any merge.


## 2026-11-17 SQLite injected-failure regression checkpoint

**Implemented:** Two executable regression tests in `research_contracts/test_sqlite_atomic_replay.py` (commit `020ec69`) inject a real SQLite `RAISE(ABORT)` trigger on the second insert. They assert that an earlier new high-water entry is rolled back, the transaction is closed and the connection remains usable; a second test checks that an existing high-water value is not advanced by a failed batch. These are fault-injection correctness tests, not publishable independent V2X experiments.

**Execution:** Full repository checkout unavailable (`github.com` DNS resolution failed); committed tests have **not** been run, so behavior remains unverified. Execute `python -m unittest discover -s research_contracts -p 'test_sqlite_atomic_replay.py' -v` on a complete checkout and then the full suite. No merge.

**Matrix:** SQLite SQL-error rollback = regression implemented / execution pending; production authenticated Pi ingress = partial; local emergency stop = physically unverified; ledger crash/power-loss = blocked; authentic VeReMi/CAN provenance = upcoming; independent multi-seed adversarial baselines and effect sizes = blocked; paper = blocked. Next: run these failure tests and integrate durable replay admission with production Pi socket handler, followed by real loopback fault injection.


## 2026-11-17 process-termination replay regression checkpoint

**Implemented:** `research_contracts/test_replay_process_termination.py` (commit `c21e5dd`) adds three executable subprocess tests: committed multi-node high-water survives abrupt `os._exit(0)` without connection close; an uncommitted high-water update rolls back after process exit; and corrupted SQLite input fails closed instead of silently initializing fresh replay state. Tests run actual SQLite file operations in independent Python processes, not mocks. **Execution pending**; neither SIGKILL/power-loss durability nor hardware safety is proven. This is a correctness prerequisite, not publishable primary scientific evidence.

| Item | Status | Evidence / blocker |
| --- | --- | --- |
| Replay process-exit persistence and rollback | Implemented; unverified | Three subprocess tests committed, execution pending |
| Actual power-loss/fsync durability | Blocked | No power-cut rig, crash harness or filesystem durability evidence |
| Production Pi authenticated ingress and interlocks | Partial | Independent local emergency stop unverified |
| Mock contract finality | Blocked | No distributed consensus finality demonstrated |
| Original mechanism and external adversarial evaluation | Upcoming | Threat model, real datasets, matched baselines and multi-seed experiments missing |
| Manuscript numerical claims | Blocked | Existing fixtures/microbenchmarks are non-publishable primary results |

**Run:** `python -m unittest discover -s research_contracts -p 'test_replay_process_termination.py' -v`. Next code task: integrate fail-closed recovery into production hardware bridge, then run real authenticated loopback faults and collect baseline-matched latency/CPU/RAM/throughput. Do not merge without executing the branch test suite.


## 2026-11-17 replay durability configuration hardening

- **Implemented, branch PR #141:** SQLite replay gate now requires `journal_mode=WAL` and `synchronous=FULL`, checking both pragmas before accepting events. Initialization fails closed and closes the connection if these guarantees cannot be configured. Non-finite busy timeouts are rejected. Commits `f5ae887`, `f6a6e0e`.
- **New executable tests:** `python -m unittest discover -s research_contracts -p 'test_replay_durability_configuration.py' -v`. These check file-backed WAL/FULL, restart replay rejection, unsupported in-memory journal and NaN/infinite timeouts. Full committed suite **not executed**.
- **Locally verified independent SQLite configuration probe:** file-backed SQLite returned `wal` and synchronous `2` (FULL); in-memory WAL request returned `memory`, confirming a fail-closed condition. This is an environment probe, not a full branch test or a crash/power-loss experiment.
- **Matrix:** file-backed replay durability configuration = implemented/branch tests pending; SQLite batch atomicity = implemented/full tests pending; production hardware ingress = partial; emergency-stop independence = unverified; physical power-loss durability = blocked; mock consensus finality = blocked; authentic V2X/CAN datasets = upcoming; matched adversarial multi-seed evaluation = blocked; paper = not ready.
- **Next:** run committed tests, audit production hardware bridge for replay-store path and restart behavior, then conduct real authenticated loopback slow-client and concurrent-replay experiments with matched baselines. No publishable scientific effect or physical safety claim.


## 2026-11-17 authenticated replay identity canonicalization checkpoint

| Workstream | Status | Evidence / limitation |
| --- | --- | --- |
| Replay principal encoding and NFC admission | Implemented, unverified | Rejects ill-formed UTF-8 surrogates, non-NFC aliases, malformed batch entry shapes before SQLite transaction |
| Replay identity compatibility | Partial | Enrollment/device registry must use the same canonical NFC policy; legacy non-NFC IDs will be rejected |
| Regression suite | Added, execution blocked | Four cases in research_contracts/test_replay_identity_canonicalization.py; no full-checkout execution |
| Real authenticated socket and physical interlocks | Blocked | No Pi/hardware or full repository checkout; independent local emergency control must remain available |
| Independent adversarial evidence | Pending | No authentic incident dataset, independent multi-seed baselines, measured effect sizes |
| Publication readiness | Blocked | This is security hardening, not publishable V2X effectiveness evidence |

Commits: a8d2d8394db6d6e9092aeb930ce038f06f1e9508, 56f67e7b7c52229c24456055a4f94d7f5e925ef0.
Validation command: `python -m unittest discover -s research_contracts -p 'test_replay_identity_canonicalization.py' -v`.
Local `git ls-remote` failed with `Could not resolve host: github.com`; do not claim tests passed. PR #141 remains draft and must not merge without validation.
Next: reconcile enrolled-node identifier canonicalization in hardware_bridge and device registry; run focused/full suites, then authenticated loopback replay/slow-peer faults and matched performance baselines.


### 2026-11-17: persisted principal canonicalization on recovery (draft PR #141)
- **Completed (code):** recovery now checks each persisted replay principal against the same strict UTF-8, NFC, byte-length and ASCII-control exclusion policy as authenticated admission. This closes the gap where a valid SQLite TEXT row could be noncanonical despite passing SQLite typeof/length checks. Commit 7050d419.
- **Completed (test implementation):** four independent SQLite file/reopen regression cases for decomposed Unicode, newline, DEL and valid precomposed Unicode; commit 159830f.
- **Partial / unverified:** committed tests have not been executed in the repository runtime. Run `python -m unittest discover -s research_contracts -p 'test_replay_persisted_identity_canonicalization.py' -v` and then `python -m unittest discover -s research_contracts -p 'test_*.py' -v`.
- **Blocked:** privileged database snapshot rollback remains possible without an independent trusted monotonic anchor; no physical safety or power-loss evidence.
- **Upcoming highest-priority code:** integrate fail-closed persistent replay recovery into production hardware_bridge ingress, keeping physical emergency stop independent; then authenticated socket fault injection and matched performance baselines.
- **Publication gate:** fixture CSVs, microbenchmarks, 3-peer sanity checks and offline formulas are not primary experimental results. No effectiveness claim or statistical significance claim from n>=30 alone.


## 2026-11-17 authenticated framer preallocation boundary

| Workstream | State | Evidence and remaining limitation |
| --- | --- | --- |
| Oversized single-chunk preallocation | Implemented; repository tests pending | `AuthenticatedLineFramer.feed` now rejects chunks exceeding configured frame budget before extending its buffer, and clears pending partial bytes |
| Framer chunk-boundary regression | Added; not yet executed in full checkout | `tests/test_hardware_framer_chunk_budget.py` covers over-budget input, recovery after partial input, and exact-budget multiple frames |
| Production TCP replay durability | Partial | Live `HardwareEnvelopeVerifier` uses an in-memory nonce cache; durable research replay-store is not wired to Pi/serial production ingestion |
| Independent local emergency stop | Software path isolated; physical behavior unverified | Remote CAN/serial command dispatch remains disabled; no physical bench/hardware evidence |
| Authentic V2X/CAN paired adversarial study | Pending | No publishable incident-level matched baseline, multi-seed runtime or uncertainty measurements from this change |

Run `python -m unittest discover -s tests -p 'test_hardware_framer_chunk_budget.py' -v` and the complete transport suite before merging. This resource-limit change does not prove end-to-end DoS resilience, physical safety or scientific detection performance. Next: integrate fail-closed durable replay provisioning/recovery into production Pi ingestion, then measure real authenticated loopback fault-injection behavior.
