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
