# Ledger delivery bounded-state exploration — 2026-11-22

| Workstream | Status | Evidence / blocker |
|---|---|---|
| Abstract crash/retry state exploration | Completed (isolated model) | Four local unittest cases passed; 9-step BFS |
| Atomic nonce + inbox in production | Partial | Prototype PR #197 not verified against hardware bridge |
| Downstream ledger event-id idempotency | Blocked | No verified production integration |
| Receiver-authenticated actuation | Blocked | Physical interlocks and lab access unavailable; remote commands disabled |
| Durable serial replay | Partial | PR #194 pending integration |
| Authentic VeReMi NextGen/CAN provenance | Blocked | No independently verified raw dataset here |
| Paired attack effectiveness baselines | Upcoming | Requires incident-level held-out splits |
| Multi-seed performance/statistical study | Upcoming | No publishable runs |
| Manuscript numeric claim ledger | Blocked | No validated original effectiveness evidence |

## Reproducibility
`python -m unittest discover -s tests -p 'test_ledger_delivery_model.py' -v`
`python research_contracts/ledger_delivery_model.py`

Model is deliberately abstract: an 'atomic' ingest is one indivisible state transition and 'idempotent' ledger is an assumed event-ID uniqueness property. It does not verify production code, power loss, distributed finality, liveness under permanent faults, or Byzantine consensus. State-space bounds are nine transitions. No publishable V2X effectiveness claim follows.
