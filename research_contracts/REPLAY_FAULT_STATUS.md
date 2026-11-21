# Replay-fault evidence matrix (2026-11-18)

| Workstream | State | Evidence / limitation |
| --- | --- | --- |
| SQLite commit-before-admission high-water | Partial | Prototype from stacked PR #145; not production hardware ingress |
| Post-COMMIT SIGKILL restart | Completed (isolated local equivalent) | Worker SIGKILL after durable COMMIT; same sequence rejected in local campaign |
| Pre-COMMIT SIGKILL restart | Completed (isolated local equivalent) | Worker SIGKILL before COMMIT; uncommitted sequence can subsequently be admitted |
| Snapshot rollback negative control | Completed (isolated local equivalent) | Restoring older SQLite database permits previously admitted sequence; explicit known vulnerability |
| Corrupt database startup | Completed (isolated local equivalent) | Invalid SQLite header raises startup exception; receiver must fail closed |
| Repository checkout execution | Blocked | Container cannot resolve github.com; connector-written source not executed from checkout |
| Production hardware_bridge HMAC, bounded receive, interlocks | Partial / unverified | No actuator interface is exercised by this campaign |
| Real power-loss / fsync fault injection | Blocked | No controlled power-fault hardware |
| Multi-client DoS and latency | Upcoming | Non-actuating bounded loopback with CPU/RAM measurements |
| VeReMi NextGen and CAN provenance | Upcoming | No authenticated dataset imported here |
| Research paper numeric claims | Blocked | No real-dataset or independent replication evidence |

Local reconstruction command: `python -m unittest discover -s tests -p 'test_replay_fault_campaign.py' -v` (5/5 passed); `python -m research_contracts.replay_fault_campaign --trials 3 --output results/replay_faults.jsonl` (12/12 expected fault outcomes). The local copy was reconstructed from fetched gate source; the connector-pushed checkout remains unverified.

Threat boundary: these tests use authenticated=True as a **test precondition**, not an HMAC verification. SQLite high-water cannot detect adversarial restoration of a valid older database. SIGKILL after COMMIT is not evidence of physical power-loss durability. All output is exploratory engineering evidence, not publication-ready effectiveness.
