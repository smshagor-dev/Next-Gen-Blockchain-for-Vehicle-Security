# Durable hardware replay: research validation checkpoint (2026-11-20)

Scope: draft PR #160; code on branch `research/durable-hardware-nonce-claims`. This is a protocol-engineering checkpoint, **not** publishable effectiveness evidence.

| Workstream | State | Evidence / missing work |
|---|---|---|
| Atomic SQLite nonce claim and high-water clock | Implemented, unverified | `durable_hardware_replay.py`; exact checkout suite not yet executed |
| Cross-process same-nonce race | Test committed, execution pending | `tests/test_durable_nonce_process_faults.py::test_simultaneous_processes_admit_nonce_exactly_once`; expected 1 acceptance, 5 rejections |
| Abrupt process exit after commit | Test committed, execution pending | Same test module; validates restart persistence after `os._exit`, **not** crash during commit or power loss |
| SQLite initialization contention | Unverified / potential blocker | Concurrent first-open `PRAGMA journal_mode=WAL` may report database locked; reproduce before claiming robustness |
| MAC-authenticated bridge deployment | Partial | Durable replay is opt-in; inspect receiver config and enforce fail-closed before deployment |
| Host database rollback and trusted clock | Blocked | No independent monotonic hardware anchor; restore of old DB can re-admit prior nonce |
| Physical emergency stop | Blocked | No actuator/vehicle access; must remain locally authoritative |
| Authentic VeReMi NextGen and CAN ingest | Pending | Dataset provenance, license, splits and trace integrity not validated |
| Matched adversarial baselines and ablations | Pending | No independent incident-level result |
| Latency, CPU/RAM, throughput and uncertainty | Pending | No measured process-level comparison |
| Scientific paper claims | Blocked | Fixture CSVs, 3-peer sanity checks, microbenchmarks and offline formulas excluded from main results |

Validation commands (not executed in this environment):
```sh
python -m unittest discover -s tests -p 'test_durable_nonce_process_faults.py' -v
python -m unittest discover -s tests -p 'test_durable_hardware_replay.py' -v
python -m unittest discover -s tests -v
```

Next: run tests on exact checkout; if concurrent initialization fails, serialize schema/bootstrap safely without bypassing replay claims. Add fault injection at pre-commit, commit, post-commit and corrupted DB boundaries, then integrate durable replay in production receiver and evaluate bounded ingress.
