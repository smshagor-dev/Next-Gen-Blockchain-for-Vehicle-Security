# Nonce-store snapshot rollback negative control — 2026-11-22

## Evidence classification
Engineering negative-control experiment, **not publishable attack-detection evidence**.
No real hardware, remote attacker, independent ledger finality or physical power-loss testing.

## Status matrix
| Workstream | State | Evidence / blocker |
| --- | --- | --- |
| TCP/serial authentication and local emergency isolation | Partial | Existing production work; no hardware proof |
| Restart replay persistence | Partial | Existing SQLiteNonceStore; this experiment checks ordinary restart |
| Privileged disk snapshot rollback resistance | **Known limitation / negative control** | Valid old SQLite snapshot can forget accepted nonce; test encodes expected failure |
| Corrupt snapshot fail-closed | Test added, execution pending | SQLite open/integrity failure |
| Nonce-to-ledger atomic inbox | Partial | Separate draft prototype; production integration pending |
| Independent finality / trusted monotonic anchor | Blocked | No independent trusted anchor or real consensus verification |
| Authentic incident-level V2X evaluation | Blocked | Independent world truth and sensor provenance absent |
| Multi-seed paired baseline comparisons | Upcoming | Must freeze split/protocol before running |
| Publication-ready original scientific paper | Not ready | No validated independent incident-level evidence |

## Reproduction
`python -m unittest discover -s tests -p 'test_nonce_snapshot_rollback.py' -v`

The snapshot is created through SQLite's backup API and restored only after all
connections close, removing WAL/SHM sidecars. This isolates rollback from
ordinary crash recovery and deliberately demonstrates a **negative** result.
Do not treat this as a practical remote exploit or as a security fix.

## Next implementation
Bind accepted nonce/event IDs to a trusted monotonic external anchor with
authenticated checkpoint verification and a defined fail-closed recovery policy.
Test rollback, stale-anchor availability and crash boundaries against identical
fault schedules; keep local emergency controls independent of the anchor.
