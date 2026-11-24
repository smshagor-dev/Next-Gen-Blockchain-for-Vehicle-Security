# OmniGuard V2X research status — 2026-11-21

| Workstream | State | Evidence / limitation |
|---|---|---|
| Arduino serial persistent nonce store | Implemented, unverified | hardware_bridge.py requires dedicated configured SQLite store before opening port; no volatile fallback |
| Arduino restart replay contract | Implemented, unexecuted | tests/test_serial_durable_replay_admission.py; no actual serial hardware |
| Pi TCP authenticated bounded receive | Partial | Existing production code; separate open PRs must be reconciled |
| Arduino generator quarantine | Partial | Existing main catches generator creation rather than iteration; overlapping PR #176/#178 |
| Emergency stop independence | Software fail-closed | No physical/HIL validation; remote actuator output disabled |
| Ledger crash consistency and finality | Partial / blocked | Local SQLite durability is not independent finality or rollback resistance |
| Authentic VeReMi NextGen and CAN datasets | Partial | Dataset authenticity and incident labels must be independently verified |
| Matched multi-seed V2X incident experiments | Upcoming | Synthetic fixtures and microbenchmarks are not publication-ready |
| Scientific manuscript | Blocked | Await independently validated attack/availability and overhead evidence |

## Reproduction

```bash
python -m compileall -q hardware_bridge.py hardware_nonce_store.py tests/test_serial_durable_replay_admission.py
python -m unittest tests.test_serial_durable_replay_admission -v
python -m unittest discover -s tests -p 'test_serial_durable_replay_admission.py' -v
```

Configuration: set SMARTCAR_HW_SERIAL_NONCE_STORE_PATH to a private, persistent filesystem path. For **first initialization only**, set SMARTCAR_HW_SERIAL_NONCE_STORE_PROVISION=true; restart with it false. Protect the file and WAL/SHM sidecars from modification. Do not delete or reinitialize after a crash. Keep the Pi store separate unless cross-transport identity/nonce coordination is explicitly designed.

## Limits and follow-up

The existing nonce store is capacity-bounded and retains claims; capacity exhaustion fails closed and requires an explicit safe operational retention/rotation policy. A privileged host can restore old database snapshots. There is no hardware root of trust, physical emergency-stop evidence, external finality, or real attack-detection measurement. Next: execute exact-checkout tests, integrate generator quarantine, and fault-inject SIGKILL/restart plus serial partial-frame floods with resource metrics.
