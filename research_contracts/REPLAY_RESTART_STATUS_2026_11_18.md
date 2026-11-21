# Replay durability research status — 2026-11-18

| Workstream | Status | Evidence / next requirement |
|---|---|---|
| Volatile replay state negative control | Implemented; repository execution unverified | Socketpair exercise of actual experimental Receiver before and after object replacement; deterministic trace; EXPECTED replay bypass |
| Replay in running receiver | Implemented; repository execution unverified | Same packet must be rejected on same Receiver instance |
| Replay after process crash | Blocked | Object recreation is NOT a process crash; add subprocess kill/restart and persisted state |
| Crash-durable nonce/high-water store | Upcoming | Atomic persistence, fsync, rollback threat, restart test and bounded retention |
| Production hardware_bridge integration | Partial / unverified | Isolated experiment does not secure production TCP or actuators |
| Local emergency control | Blocked for physical verification | Must remain independent of network admission and ledger |
| Real VeReMi NextGen/CAN source evidence | Partial elsewhere; not evaluated here | No independently validated incident ground truth |
| Research effectiveness claims | Blocked | Negative-control demonstration is not publishable field efficacy |
| Test commands | Pending execution | `python -m unittest discover -s tests -p 'test_replay_restart_negative_control.py' -v`; `python -m research_contracts.replay_restart_negative_control --seed 17 --trials 100 --output results/replay_restart_17.csv` |

## Safety and interpretation
No physical hardware is connected or actuated. An accepted duplicate after resetting the in-memory Receiver is a **security failure** intentionally demonstrated as a negative control. The script neither proves durable replay security nor measures process-crash survival. All rows share deterministic construction and must not be counted as independent real-world trials. Never infer statistical significance from trial count.
