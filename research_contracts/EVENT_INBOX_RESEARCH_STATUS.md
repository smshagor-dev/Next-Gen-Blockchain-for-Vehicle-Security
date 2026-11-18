# Event admission research status — 2026-11-18

| Workstream | State | Evidence / limitation |
|---|---|---|
| Durable SQLite event identity and pending journal | IMPLEMENTED / UNVERIFIED | `durable_event_inbox.py`; SQLite WAL, FULL sync, BEGIN IMMEDIATE |
| Restart, duplicate and conflicting payload controls | IMPLEMENTED / UNVERIFIED | Five tests in `tests/test_durable_event_inbox.py`; repository checkout not executed |
| Authenticated production ingress integration | PARTIAL | Caller must verify MAC/freshness before invoking inbox; not wired |
| Ledger reconciliation / exactly-once external effects | BLOCKED | External ledger append and inbox state cannot share an atomic SQLite transaction; PENDING must be reconciled, never blindly replayed |
| Durable replay under storage rollback | BLOCKED | Old SQLite snapshot can restore old state; independent anchor required |
| Hardware local emergency stop | BLOCKED | No physical lab verification; no remote actuation enabled |
| Authentic VeReMi NextGen and CAN experiments | UPCOMING | Dataset license, original checksums, split provenance and independent runs needed |
| Statistical main results | NOT READY | Fixture CSV, 3-peer sanity checks, five-iteration benchmarks and formula-only estimates excluded |

## Falsifiable hypothesis

After a clean process restart, a previously admitted event must remain PENDING
or COMMITTED under the same (device_id, nonce, payload digest); a changed
payload with the same identity/nonce must be rejected. This is a local
persistence property, **not** ledger finality, physical power-loss resilience,
or end-to-end exactly-once delivery.

## Next engineering task

Add a ledger reconciliation adapter using an immutable event identifier and
verified inclusion lookup. Inject failure after ledger append but before inbox
mark-committed; verify that recovery does not append twice. Keep actuation off.
Then test SIGKILL and concurrent writers on an actual checkout.

## Verification command

`python -m unittest discover -s tests -p 'test_durable_event_inbox.py' -v`

No numerical effectiveness result is claimed from this code alone.

## 2026-11-18 continuation: verified-inclusion reconciliation contract

| Workstream | State | Evidence / limitation |
|---|---|---|
| Atomic-idempotent ledger adapter | IMPLEMENTED / UNVERIFIED | `ledger_inbox_reconciliation.py`; requires externally enforced atomic append_once and verified lookup; fake ledger only |
| Crash after append before inbox commit | TEST ADDED / UNVERIFIED | Restart reopens inbox, ledger lookup reconciles without another append |
| Ambiguous append acknowledgement | TEST ADDED / UNVERIFIED | Fail closed until inclusion can be verified |
| Lookup outage, non-idempotent ledger, conflicting digest | TEST ADDED / UNVERIFIED | Refuse append / reconciliation |
| Production ledger integration and consensus finality | BLOCKED | Real chain lacks proven lookup/append_once contract; no exactly-once or finality claim |
| Repository checkout validation | BLOCKED / TRANSIENT | github.com DNS resolution unavailable in execution container |

Commands: `python -m unittest discover -s tests -p 'test_ledger_inbox_reconciliation.py' -v`; `python -m unittest discover -s tests -v`.

Next: validate on actual checkout, implement durable ledger inclusion adapter, run subprocess SIGKILL and concurrency fault experiments. No remote actuation or publication-ready numeric result.
