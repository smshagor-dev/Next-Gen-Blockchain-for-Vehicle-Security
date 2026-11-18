# Replay persistence experiment status — 2026-11-18

| Workstream | Status | Evidence / limitation |
|---|---|---|
| SQLite commit-before-admission high-water gate | Implemented; unverified | Single-process/connection transactional state, FULL sync, DELETE journal; no rollback-resistant anchor |
| Duplicate after receiver object restart | Test committed; not executed | SQLite file reopened after first committed acceptance |
| Subprocess exit/restart | Test committed; not executed | Clean subprocess exit, NOT SIGKILL, sudden power loss or filesystem rollback |
| Database failure | Test committed; not executed | Missing replay table returns storage_error rather than accept |
| Authentication | Partial | Caller supplies authenticated flag; NOT wired to HMAC verifier; must never trust user-controlled flag |
| Production hardware_bridge | Blocked | No production integration or hardware verification; local emergency stop must remain independent |
| Multi-process concurrency | Partial | BEGIN IMMEDIATE serializes SQLite writers; no measured stress test |
| Dataset and paper evidence | Blocked | No real VeReMi NextGen/CAN evaluation or publishable measurements |
| CI / checkout test evidence | Pending | Run commands below on actual branch |

Run:
```bash
python -m unittest discover -s tests -p 'test_durable_replay_gate.py' -v
python -m unittest discover -s tests -v
```

This is a negative-control mitigation prototype, not an actuator authorization service. A database copied from an older snapshot can admit previously observed higher sequences. SQLite FULL sync does not establish physical power-loss durability on all storage systems, Byzantine resistance, or trusted external finality. Do not publish synthetic/fixture evidence as a main scientific result.

Next: connect only after verified HMAC and freshness on a non-actuating production ingress path; test SIGKILL, disk-full, corrupt/rolled-back database, concurrent clients, deadlines and resource bounds before considering integration.
