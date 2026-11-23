# Concurrent crash-recovery research status (2026-11-21)

| Workstream | Status | Evidence / limitation |
|---|---|---|
| Concurrent recovery reservation control | Implemented, unverified | 24-worker deterministic same-nonce control; SQLite WAL same host |
| Digest-conflict fail-closed control | Implemented, unverified | Conflicting anchor digest must leave local pending |
| Missing intent / duplicate payload controls | Implemented, unverified | Four unittest methods; exact checkout execution pending |
| Real SIGKILL / restart integration | Partial | See draft #168; this experiment does not inject crashes |
| Production receiver/actuation interlocks | Blocked | No vehicle/hardware validation; no command dispatch in this module |
| Independent authenticated anchor | Blocked | Second SQLite database is not a trusted authority |
| Authentic VeReMi NextGen and CAN ingest | Pending | No dataset-derived outcomes |
| Matched multi-seed baseline inference | Pending | No statistical or scientific effectiveness claims |
| Paper | Not ready | Synthetic concurrency control is not a publishable main result |

## Reproduce

```bash
python -m unittest discover -s tests -p 'test_concurrent_recovery_control.py' -v
python -m research_contracts.concurrent_recovery_control --workers 24
python -m unittest discover -s tests -v
```

The test models a partial intent surviving a crash and concurrent restart workers reconciling it. It does not show authenticated external finality, rollback resistance, real network behavior, physical emergency-stop properties, or a new cryptographic primitive. Next: execute exact checkout tests; integrate real subprocess SIGKILL and restart races; validate no duplicate command authorization in the production ingress path.
