# Hardware ingress research validation matrix — 2026-11-21

| Workstream | Status | Evidence / limitation |
|---|---|---|
| TCP and serial authenticated envelope checks | Partial | Existing MAC and framing implementation; integrated execution pending |
| Durable nonce claims | Partial | Draft PR #160; SQLite WAL/clock checks; full suite not independently executed |
| Bridge durable replay enforcement | Implemented, unverified | This branch requires explicit existing SQLite replay DB for both ingress modes |
| Missing/empty/symlink replay DB negative controls | Implemented, unverified | `tests/test_bridge_durable_replay_provisioning.py` |
| Replay after restart | Implemented, unverified | Test claims nonce, closes DB, reopens and checks duplicate rejection |
| Trusted rollback-resistant provisioning | Blocked | Historical DB snapshot replacement and privileged host attacks remain possible |
| Receiver-side command authorization | Blocked | Remote CAN/serial actuation intentionally disabled; local emergency control independent |
| Ledger crash consistency and finality | Partial | Mock finality is not consensus finality |
| Authentic VeReMi NextGen/CAN provenance | Upcoming | Dataset licensing, hashes, and disjoint split manifests needed |
| Independent multi-seed adversarial evaluation | Upcoming | No publishable effectiveness claim |

## Reproduction

```sh
python -m unittest discover -s tests -p 'test_bridge_durable_replay_provisioning.py' -v
python -m unittest discover -s tests -p 'test_durable_hardware_replay.py' -v
python -m unittest discover -s tests -v
```

Provisioning is **offline**: an operator creates a new database with `DurableNonceStore(path, max_entries_per_device=2048)`, closes it, then sets `SMARTCAR_HW_REPLAY_DB_PATH` before starting the bridge. Never provision automatically on restart. A deleted file is a security incident, not a fresh deployment. Tests are committed but not yet run against the exact GitHub branch; this is not publishable evidence.
