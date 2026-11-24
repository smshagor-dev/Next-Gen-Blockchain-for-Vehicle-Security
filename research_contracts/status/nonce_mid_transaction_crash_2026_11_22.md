# Nonce mid-transaction crash experiment — 2026-11-22

## Incremental research status matrix

| Workstream | State | Evidence / limitation |
|---|---|---|
| Authenticated bounded TCP/serial ingress | Partial | Existing main and draft PRs #175–#180; full integration and hardware validation missing |
| SQLite nonce after-INSERT, before-COMMIT SIGKILL | Implemented, unverified | `tests/test_nonce_mid_transaction_sigkill.py`; tests not executed on exact checkout |
| Durable acknowledged nonce and replay rejection | Partial | Existing #181 and current negative control; not evidence of power-loss safety |
| Ledger event inbox crash consistency | Partial | Main includes #150; independent multi-process validation outstanding |
| Independent consensus finality | Blocked | Mock contract cannot establish distributed finality |
| Safety-isolated command authorization | Partial | Local emergency-stop precedence not physically verified |
| Authentic VeReMi NextGen and CAN ingestion | Pending | No authentic dataset evidence from this change |
| Incident-level matched baselines and ablations | Pending | No publishable effectiveness results |
| Runtime multi-seed measurements and uncertainty | Pending | n>=30 is not a significance test |
| Defensible paper and numeric claim ledger | Blocked | Await authentic incident-level experiments |

## Fault protocol

On POSIX, provision a new SQLite nonce store, start an independent child, let the production store execute `INSERT INTO nonce_claims` within `BEGIN IMMEDIATE`, then SIGKILL the child before `COMMIT`. Reopen the database; the interrupted nonce must be absent and claimable exactly once. Negative control: an acknowledged committed claim must remain rejected after reopen.

Reproduce: `python -m unittest discover -s tests -p 'test_nonce_mid_transaction_sigkill.py' -v`.

The fault occurs **after INSERT returns but before COMMIT begins**, not during SQLite's internal COMMIT write. No claims about storage power-loss, filesystem rollback, hostile root, real hardware, or V2X scientific effectiveness. No fixture/microbenchmark/offline-formula evidence is publication-ready.

Next: execute exact-checkout tests; instrument COMMIT-phase crash windows with controlled failpoints; then test ledger inbox recovery under process termination and matched authentic incident-level baselines.
