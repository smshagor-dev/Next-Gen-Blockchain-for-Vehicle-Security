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
