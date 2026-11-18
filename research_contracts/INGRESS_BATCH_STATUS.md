# Authenticated ingress batch-failure negative control (2026-11-18)

| Workstream | Status | Evidence / next step |
| --- | --- | --- |
| TCP MAC, bounded reads, non-actuating dispatch | Partial | Main has these protections; full production stress validation pending |
| Multi-frame partial nonce claim | Test committed; unverified | `tests/test_ingress_batch_atomicity.py` exercises real verifier and session; run in repository checkout |
| Durable nonce/replay state | Partial / unintegrated | Existing verifier uses volatile nonce cache; stacked experimental SQLite gate is not wired into production |
| Replay rollback, SIGKILL | Partial | Prior draft fault campaign; independent validation pending |
| Ledger crash consistency and finality | Partial | Fault injection and real finality claims pending |
| Independent-group evidence admission | Partial | Synthetic baselines only; honest/malicious domain assumptions need validation |
| VeReMi NextGen / CAN ingest | Blocked | Authentic dataset provenance and leakage-safe splits needed |
| Runtime CPU/RAM/throughput | Upcoming | Matched bounded-client and overload loopback runs |
| Hardware emergency control | Blocked | No physical bench access; network actuator remains disabled |
| Statistical manuscript claims | Blocked | No publishable multi-seed, authentic dataset evidence |

## Hypothesis and interpretation

A TCP recv may contain multiple authenticated lines. `AuthenticatedPiTelemetrySession.receive` verifies each line, claiming replay nonces as it goes, but returns its verified list only after the entire batch succeeds. A later invalid frame may therefore suppress delivery of an earlier valid observation while consuming that observation's nonce. Retransmission is rejected. This is a **legitimate availability / transaction-boundary** negative control, not an authentication bypass or physical safety finding.

## Commands

```sh
python -m unittest discover -s tests -p 'test_ingress_batch_atomicity.py' -v
python -m unittest discover -s tests -v
```

Do not claim a test pass until executed on the committed checkout. Next code change: move authenticated frame delivery to per-frame explicit commit semantics, or implement a transactional verified-batch API with clear replay-claim atomicity, then test with forced ledger failures. Never weaken MAC/replay checks or enable remote actuation to fix availability.
