# OmniGuard V2X research evidence status (2026-11-18)

| Workstream | State | Evidence / remaining gap |
|---|---|---|
| Production authenticated bounded ingress | PARTIAL | Existing hardware_bridge has HMAC, replay cache, bounded TCP; replay claim is not ledger-atomic |
| Local physical emergency precedence | BLOCKED | Remote actuator output is disabled; physical interlock/receiver validation unavailable |
| Ledger failure/retransmission negative control | IMPLEMENTED, UNVERIFIED | `research_contracts/ledger_failure_retransmission_control.py` uses production verifier with injected ledger write failure; tests committed but not executed against checkout |
| Durable replay and crash consistency | PARTIAL | SQLite experiments in separate draft PRs; cross-store atomicity and rollback resistance unresolved |
| Real VeReMi NextGen / CAN provenance | BLOCKED | No authenticated original datasets validated in this change |
| Independent attack experiments and baselines | PARTIAL | Synthetic controls only; no publishable matched real-data evidence |
| Runtime performance and multi-seed uncertainty | UPCOMING | Need real CPU/RAM/latency/throughput, paired splits and cluster-aware uncertainty |
| Manuscript and numerical claim ledger | BLOCKED | Do not promote fixtures, three-peer sanity checks, five-iteration timings or offline formulas to main findings |

## Next engineering action

Implement an explicit durable admission/ledger transaction protocol or an idempotent
inbox/outbox with stable event identifiers and crash recovery. Test injected
failure before/after each durable boundary and verify that a legitimate
retransmission is neither lost nor double-applied. Keep actuator output disabled.

## Verification commands

```sh
python -m unittest discover -s tests -p 'test_ledger_failure_retransmission_control.py' -v
python research_contracts/ledger_failure_retransmission_control.py --output /tmp/ledger-failure-control.json
```

The negative control is a deterministic engineering fault probe, not
publication-ready evidence of real-world attack effectiveness or power-loss durability.
