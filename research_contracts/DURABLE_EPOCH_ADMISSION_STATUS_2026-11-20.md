# Durable epoch-admission research checkpoint — 2026-11-20

| Workstream | Status | Evidence / limitation |
|---|---|---|
| Non-actuating epoch replay and one-shot admission persistence | Implemented; exact checkout unverified | SQLite transaction reload/commit across independent instances; no production actuator integration |
| Emergency-stop latch across restart | Implemented; unverified | Persisted stop bit; local confirmed reset; physical interlock not demonstrated |
| Crash-consistent transition publication | Partial | SQLite WAL, FULL synchronous and commit-before-positive-return; no power-cut campaign or trusted storage |
| Replay resistance against database rollback or compromise | Blocked | No external monotonic trusted counter or signed checkpoint |
| Hardware TCP ingress and physical safety | Partial/unverified | Existing hardware bridge work must be independently audited and tested |
| Go ledger finality | Blocked | SQLite persistence is not distributed consensus or ledger finality |
| Authentic VeReMi NextGen / CAN provenance | Pending | No authentic cohort evaluated here |
| Matched-trace adversarial experiments and cluster uncertainty | Pending | Synthetic regression cases are not publishable effectiveness results |
| Research paper and numeric claim ledger | Blocked | Requires independently verified experiments and defensible baselines |

## New scope
The durability adapter stores bounded epoch buckets, replay pins, one-shot decisions, and local stop latch in one SQLite record. Each transition locks and reloads current state under BEGIN IMMEDIATE, commits before returning, and rejects corrupted or configuration-mismatched state. It does **not** cryptographically authenticate callers or defend against a writable/rolled-back DB, forged epoch authority, malicious enrolled collusion, or hardware actuation.

## Validation required
```bash
python -m unittest discover -s tests -p 'test_durable_epoch_admission.py' -v
python -m unittest discover -s tests -p 'test_epoch*py' -v
python -m unittest discover -s tests -v
```
No exact checkout test passes claimed. Next: execute branch suite, fault-inject SQLite commit failures, add process-level concurrency campaign and fail-closed authenticated storage rollback negative control; review hardware bridge ingress before any integration.

## 2026-11-20: corrupt durable-state negative controls

- **Completed (code, unverified):** Reject non-string/oversized/unhashable state keys, boolean epochs, duplicate nonce/admission entries, and stale admitted keys on SQLite recovery. Six negative-control tests committed in `tests/test_durable_state_negative_controls.py`.
- **Partial:** The new tests are not yet executed against the exact GitHub branch; full repository suite and subprocess kill/commit fault injection remain pending.
- **Blocked:** No trusted external checkpoint or hardware test bench; SQLite does not detect an attacker rolling back the entire database.
- **Upcoming:** Run exact checkout tests, add subprocess crash-before/after-commit test with independent oracle, compare durable-vs-memory admission overhead on identical simulated traces.
- **Evidence classification:** Input-validation regressions only; not publishable effectiveness or physical safety evidence.


## 2026-11-20: persisted positive-admission quorum integrity

- **Completed (code, unverified):** Recovery now rejects an admitted incident whose stored distinct corroborator count is below the configured quorum. Previously the decoder checked bucket existence but not the positive-decision quorum invariant. This is a malformed-state fail-closed defense, not malicious database rollback protection.
- **Completed (tests committed, unexecuted):** `tests/test_durable_quorum_integrity.py` exercises forged one-of-two and two-of-three positive decisions, legitimate two-of-two restart, and recovery of a partial evidence bucket.
- **Partial:** No exact checkout test execution: container cannot resolve github.com; GitHub connector source writes and reads work. The complete suite and process-kill crash consistency experiments remain outstanding.
- **Blocked:** Trusted checkpoint, authentic ground truth, physical interlocks and distributed finality are not established.
- **Next code task:** Run tests on exact branch, add subprocess kill-before/after-commit fault injection with independent SQLite-state oracle, then matched-trace simulation benchmarks with identical seeds and baselines.
- **Evidence classification:** Protocol-state integrity regression, not a publishable V2X detection-effectiveness claim.

## 2026-11-20: subprocess crash-boundary experiment

- **Completed (code committed, unexecuted):** `tests/test_durable_crash_boundaries.py` injects abrupt subprocess termination immediately before SQLite COMMIT (exit 73), immediately after committed admission (exit 74), and after a committed local emergency-stop latch (exit 77). Parent process independently reopens the SQLite store and tests whether the quorum is newly attainable, whether positive admission is one-shot, and whether the emergency latch survives.
- **Partial:** Exact checkout execution and failure reproduction remain pending. SQLite trace-callback termination models process death at a software boundary, **not** power failure, filesystem loss, hostile DB rollback, or hardware actuation.
- **Validation command:** `python -m unittest discover -s tests -p 'test_durable_crash_boundaries.py' -v`; then `python -m unittest discover -s tests -v`.
- **Blocked:** No trustworthy rollback-resistant storage, independent hardware bench, or authentic labelled V2X/CAN cohort.
- **Next code task:** Execute exact branch tests, resolve any failures, add identical-trace durable/in-memory throughput and latency measurements with multiple seeds and explicit host specifications; independently audit the bridge's emergency control boundary.
- **Evidence classification:** Crash-boundary protocol regression only; not scientific effectiveness, power-loss durability, or finality evidence.


## 2026-11-20: cross-process one-shot concurrency experiment
- **Completed (code committed, unexecuted):** `tests/test_durable_multiprocess_admission.py` launches 12 independent spawned processes against one SQLite database, synchronizes their start, asserts exactly one positive quorum decision, and checks restart cannot reissue the decision. This tests a real interprocess race rather than a single-process mock.
- **Partial:** Exact branch execution, platform-specific spawn/SQLite lock timing, full test suite, and CPU/RAM/latency measurements are not verified. Do not report test success or numerical scientific results.
- **Blocked:** No trusted external rollback counter, physical vehicle interlock bench, authentic VeReMi NextGen/CAN cohorts, or independent consensus finality.
- **Upcoming:** Execute `python -m unittest discover -s tests -p 'test_durable_multiprocess_admission.py' -v` and full suite; investigate any concurrent lock failures; instrument matched-trace durable versus in-memory latency with multi-seed uncertainty. Independently audit `hardware_bridge` before actuation.
- **Evidence classification:** Unexecuted concurrency regression design; not publishable effectiveness evidence.
