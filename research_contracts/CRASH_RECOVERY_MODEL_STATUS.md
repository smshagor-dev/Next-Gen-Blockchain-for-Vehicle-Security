# Crash recovery state-model research matrix (2026-11-21)

| Item | Status | Evidence / limitation |
|---|---|---|
| Non-actuating monotonic two-claim authorization model | Implemented | `research_contracts/crash_recovery_state_model.py` |
| Exhaustive bounded-state safety exploration | Implemented, execution pending | `python -m research_contracts.crash_recovery_state_model --depth 7` |
| Four regression tests | Implemented, execution pending | `python -m unittest discover -s tests -p 'test_crash_recovery_state_model.py' -v` |
| Crash/retry repair liveness | Known limitation | Partial states persist unless explicit authenticated repair exists |
| Independent trusted anchor | Blocked | No trusted hardware/service evidence |
| Receiver hardware safety | Blocked | No physical actuator tests |
| Authentic VeReMi NextGen/CAN paired study | Pending | No authentic dataset results |
| Publication readiness | Not ready | This abstract model is not empirical effectiveness evidence |

Safety invariant: authorized implies local AND anchor claims. The model does not
establish real-world atomicity or durability. A fail-closed authorization rule
alone cannot guarantee recovery liveness after partial commits. No `n >= 30`
significance shortcut is valid.


## 2026-11-21 follow-up: concrete SQLite recovery experiment

| Workstream | Status | Evidence / limitation |
|---|---|---|
| Durable local pending intent + independent reservation | Implemented, unexecuted | `research_contracts/sqlite_recovery_experiment.py`; separate SQLite WAL files, not external trust |
| Restart reconciliation, outage and digest-equivocation controls | Six tests committed, unexecuted | `tests/test_sqlite_recovery_experiment.py` |
| Command authorization and physical actuation | Explicitly excluded | Reconciliation only returns state, never authorizes motion |
| Real SIGKILL crash-boundary and cross-process contention | Upcoming | Existing draft #168 covers different process fault scenarios |
| Rollback-resistant anchor and physical E-stop | Blocked | Requires external trust root and controlled hardware validation |
| Authentic datasets, baselines, uncertainty and paper | Pending | No publication-ready measurements |

Reproduce: `python -m unittest discover -s tests -p 'test_sqlite_recovery_experiment.py' -v`.
The code is an experimental recovery mechanism, not a production fix. In particular,
same-host SQLite files share a failure domain, rollback can restore both, and a
local process with database write access can forge either claim. The local-intent
then anchor-then complete protocol may leave pending entries during crashes.
No numerical effectiveness or significance claim is justified.
