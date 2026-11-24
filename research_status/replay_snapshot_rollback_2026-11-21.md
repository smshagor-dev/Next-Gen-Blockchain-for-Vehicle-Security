# Replay snapshot rollback negative-control status (2026-11-21)

| Workstream | Status | Evidence / limitation |
| --- | --- | --- |
| Authenticated hardware ingress | Partial | Draft #161; exact checkout tests still unexecuted |
| Durable nonce claims | Implemented, unverified | Draft #160; SQLite WAL/FULL does not protect historical snapshots |
| Historical snapshot rollback control | Implemented, unverified | `tests/test_replay_snapshot_rollback_negative_control.py`; expected vulnerability: later nonce reaccepted after valid database rollback |
| Hardware interlocks and local emergency precedence | Blocked | No physical receiver/ECU evidence; network actuation must remain disabled |
| Ledger crash consistency and finality | Partial | Mock finality not consensus evidence |
| Authentic VeReMi NextGen and CAN provenance | Pending | No authentic cohort outcome established |
| Matched attack baselines, multi-seed uncertainty | Pending | Fixture CSVs and microbenchmarks are non-publishable |
| Publication-ready research claim ledger | Blocked | Requires independent, validated experiments |

## Threat model and interpretation

An attacker with permission to replace the replay database with a valid historical snapshot can restore the nonce history to an earlier state. SQLite `quick_check`, a monotonic clock value *inside the same database*, WAL and `synchronous=FULL` cannot detect this replacement. This negative control deliberately demonstrates the limitation, without opening sockets or actuators. It is not a novel security mechanism.

## Reproduction

```bash
python -m unittest discover -s tests -p 'test_replay_snapshot_rollback_negative_control.py' -v
python -m unittest discover -s tests -p 'test_bridge_durable_replay_provisioning.py' -v
python -m unittest discover -s tests -v
```

The exact repository checkout was blocked by GitHub DNS resolution in the execution environment on 2026-11-21. Do not claim the regression passed. Next: introduce a trusted external generation/epoch anchor and test rollback against it; separately validate receiver-side interlocks and authentic dataset protocols. No unverified PR should be merged.
