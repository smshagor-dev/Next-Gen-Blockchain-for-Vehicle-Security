# Research status — 2026-11-22 — atomic nonce/event inbox

| Workstream | Status | Evidence / limitation |
|---|---|---|
| Atomic nonce plus event admission | Partial | Standalone SQLite WAL/FULL prototype; not wired into hardware bridge |
| Replay rejection after restart | Partial | Regression test authored; exact GitHub checkout not executed |
| Failed INSERT rollback | Partial | Fault trigger regression authored |
| Idempotent ledger delivery | Blocked | Event ID available, but ledger consumer must implement idempotency |
| Hardware TCP/serial authentication | Partial | Open PRs #190, #191, #194 require integration |
| Local emergency interlock | Blocked | No physical hardware safety validation |
| Consensus finality | Blocked | Mock contract not independent finality |
| Authentic VeReMi/CAN data | Blocked | No verified licensed dataset acquired |
| Matched multi-seed experiments | Upcoming | No publishable effectiveness data |
| Paper evidence | Not ready | Fixtures and microbenchmarks excluded |

## Scope and safety
This module is an isolated research prototype. No hardware actuation. It atomically commits a unique nonce and canonical event to one SQLite transaction, avoiding the post-nonce/pre-inbox loss window within this database. It does NOT make ledger append atomic with SQLite, does not guarantee exactly-once remote delivery, and cannot protect against privileged disk rollback or power loss beyond filesystem guarantees. Consumers must deduplicate event_id and only mark delivered after durable acknowledgment.

## Reproduce
`python -m unittest discover -s tests -p 'test_atomic_event_inbox.py' -v`

Local equivalent prototype passed six tests on 2026-11-22; exact GitHub committed checkout remains unverified because git access from execution container cannot resolve github.com. Do not merge without exact-checkout tests and code review.

## Next
Integrate authenticated verified envelope into atomic inbox with explicit schema migration from SQLiteNonceStore, then simulate crashes before/after inbox commit and after ledger append but before delivered acknowledgment; verify at-least-once delivery and ledger idempotency. No scientific effectiveness claims from these engineering tests.
