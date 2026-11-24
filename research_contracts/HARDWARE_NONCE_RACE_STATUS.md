# OmniGuard V2X — Hardware ingress nonce race research matrix (2026-11-21)

## Experiment protocol
- Production component under test: `hardware_nonce_store.SQLiteNonceStore`.
- Independent Python processes start from a shared barrier; each attempts the same device/nonce claim against the same WAL SQLite file.
- Expected safety property: **at most one successful reservation** for a device/nonce, including after a fresh database connection is opened.
- Explicit fail-closed rule: lock timeouts, abnormal exits, or missing outcomes are failures of the experimental run, not successes.
- No ECU/actuator command is generated. This is a concurrency/replay mechanism check, not a real V2X effectiveness experiment.

## Reproduce from repository root
```bash
python -m unittest discover -s tests -p 'test_hardware_nonce_race_experiment.py' -v
python -m research_contracts.hardware_nonce_race_experiment --workers 16 --rounds 5 --output /tmp/hardware_nonce_race.jsonl
```

## Status matrix
| Workstream | State | Evidence / blocker |
|---|---|---|
| Authenticated ingress, frame size limits, nonces | Partial | Existing bridge code reviewed; integrated threat evaluation outstanding |
| Independent process nonce-race harness | Implemented, unverified | GitHub commit exists; exact checkout execution pending |
| Restart replay rejection | Implemented, unverified | Asserted by harness, not yet observed |
| SIGKILL/restart cross-store repair | Partial | Existing draft PR work; independent external anchor absent |
| Physical emergency-stop safety | Blocked | No authorized lab/hardware access; local physical E-stop must remain independent |
| Authentic VeReMi NextGen/CAN provenance | Upcoming | Source license, hashes and original split protocol needed |
| Matched attack baselines and multi-seed uncertainty | Upcoming | No publication-ready measurements |
| Journal paper | Blocked | No authentic validated effectiveness evidence |

## Interpretation
Do not infer significance from 30 repetitions. The experiment checks a narrow safety invariant under a shared SQLite host; it cannot establish resistance to disk rollback, privileged compromise, distributed consensus faults, colluding enrolled devices, or physical safety. Existing fixture CSVs and microbenchmarks are not main-paper results.
