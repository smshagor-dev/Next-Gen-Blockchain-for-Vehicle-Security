# Replay crash-boundary research status — 2026-11-21

| Workstream | Status | Evidence / limitation |
|---|---|---|
| Real child-process abrupt termination at first/second store commit | Implemented, unverified | `research_contracts/subprocess_replay_crash.py` uses SQLite WAL, subprocess and `os._exit(73)` |
| POSIX SIGKILL + WAL TRUNCATE checkpoint recovery | Locally verified, exact checkout pending | 3 isolated unittest methods passed; four crash-order cases observed; both stores are same-host SQLite |\n| Restart retry negative control | Implemented, unverified | Duplicate first-store nonce must be rejected even after worker restart |
| Four matched protocol/boundary scenarios | Implemented, unverified | Reserve-first/local-first × after-first/after-second commit; not statistical inference |
| Regression tests | Implemented, unexecuted | `tests/test_subprocess_replay_crash.py` |
| Authenticated independent trusted anchor | Blocked | Second SQLite file is NOT a trusted anchor |
| Hardware interlocks and local emergency control | Blocked | No hardware or actuator access; experiment never actuates |
| Production bridge durable replay integration | Partial | Separate stacked draft PRs #160–#167 require exact checkout verification |
| Authentic VeReMi NextGen / CAN provenance and matched baselines | Upcoming | No authentic dataset or measured effectiveness |
| Publishable scientific claims | Blocked | No external validity, network measurements, hardware or multi-seed attack evaluation |

Reproduce from repository root:

```bash
python -m unittest discover -s tests -p 'test_subprocess_replay_crash.py' -v
python -m research_contracts.subprocess_replay_crash --output /tmp/replay_crash_boundaries.csv
python -m unittest discover -s tests -v
```

The two SQLite files are both on the same host and are vulnerable to common-mode failure and privileged rollback. A child exiting after its first successful commit leaves a partial cross-store state; retry is expected to reject because the first store already contains the nonce. This is an availability negative control, not a demonstration of V2X attack prevention. The four scenarios are deterministic controls and must not be reported as a sample size or statistical significance.

SIGKILL local isolated evidence (2026-11-21): 3 tests passed; reserve-first/first=(local 0, anchor 1), local-first/first=(local 1, anchor 0), both second-boundary cases=(1,1). All four retries rejected and checkpoint preserved committed state. These are deterministic fault controls, not independent incident replicates or publishable V2X effectiveness. Exact GitHub checkout full suite remains unverified.\n\nAdditional reproduction: `python -m unittest discover -s tests -p 'test_sigkill_recovery.py' -v` and `python -m research_contracts.sigkill_recovery --output /tmp/sigkill_recovery.csv` (POSIX).\n\nNext: execute exact branch full suite, investigate first-store retry preventing repair of the second store, then authenticated remote authority and matched dataset-based attack evaluation.
