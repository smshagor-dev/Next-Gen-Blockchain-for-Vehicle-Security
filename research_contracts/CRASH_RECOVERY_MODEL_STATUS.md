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
