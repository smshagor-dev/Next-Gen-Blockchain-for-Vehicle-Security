# Research status — nonce / ledger fault boundary (2026-11-22)

| Workstream | Status | Evidence / limitation |
| --- | --- | --- |
| Authenticated TCP and bounded ingress | Partial | Main contains MAC verification and per-session bounds; independent full integration pending |
| Local emergency stop isolation | Partial | Network-originated actuation disabled in code; no physical interlock or HIL evidence |
| SQLite nonce process-crash boundaries | Implemented, execution pending | tests/test_nonce_ledger_fault_boundary.py; process exit 73 after commit and 74 before commit |
| Nonce claim + ledger atomicity | Blocked | Separate durability domains; committed nonce before failed ledger write rejects legitimate retry |
| Ledger finality / rollback resistance | Blocked | Local checkpoint and mock receipts cannot prove independent finality |
| Evidence-gated incident admission | Partial | Policy prototypes and synthetic threat-model checks; independent incident truth missing |
| Authentic VeReMi/CAN incident ground truth | Blocked | CAM attacker labels are not independently sourced incident labels |
| Matched multi-seed external experiments | Upcoming | Require frozen baselines, paired incidents, effect sizes and uncertainty |
| Publishable scientific efficacy | Not ready | Fixture CSVs, 3-peer sanity, 5-iteration microbenchmarks excluded |

## Reproduction
```bash
python -m unittest discover -s tests -p 'test_nonce_ledger_fault_boundary.py' -v
```

The experiment uses real subprocess termination and a temporary SQLite WAL database, but does not simulate storage power cuts. The post-commit child never writes a ledger entry: this deliberately demonstrates a crash-window availability failure, not a successful recovery guarantee. Never interpret n >= 30 as significance without specified inference.

## Next code task
Implement a durable event inbox with idempotent event IDs, atomic nonce+inbox insertion in the same SQLite transaction, and a recoverable ledger delivery state machine. Test crashes before/after inbox commit and after ledger append; ensure replay rejection does not suppress recovery of already-accepted events. Keep local emergency control outside network/ledger availability.
