# OmniGuard V2X research status — 2026-11-18

| Workstream | Status | Evidence and limitation |
|---|---|---|
| Production TCP authentication, bounded framing and non-actuating controls | PARTIAL | Draft #148; full checkout validation pending |
| Local emergency control isolation | BLOCKED | No physical safety interlock test or hardware access; never enable remote actuation |
| Durable replay state and storage rollback | PARTIAL | Drafts #145–#146; rollback negative control, no independent rollback-resistant anchor |
| Durable event inbox and reconciliation | PARTIAL | Draft #150; separate SQLite and ledger cannot share one atomic transaction |
| Actual subprocess SIGKILL after ledger append | IMPLEMENTED / UNVERIFIED | This branch: separate SQLite ledger surrogate, SIGKILL child, reopen and reconcile, assert single record; checkout tests not run |
| Real ledger inclusion and consensus finality | BLOCKED | SQLite surrogate is not a blockchain, consensus or verified finality proof |
| Authentic VeReMi NextGen and CAN datasets | UPCOMING | Need licensed source data, hashes, provenance and independent splits |
| Independent adversarial experiments, baselines and ablations | UPCOMING | Existing fixture CSV, three-peer poisoning, five-iteration microbenchmarks excluded |
| Runtime resource scaling and multi-seed inference | UPCOMING | No significance inferred from n >= 30 |
| Defensible scientific paper | NOT READY | No publication-grade evidence or physical safety claim |

## Falsifiable crash-boundary property

Under a *surrogate* ledger with durable atomic append_once and verified lookup, killing the writer **after ledger COMMIT but before inbox COMMITTED** must leave exactly one ledger row and a recoverable PENDING inbox record. A subsequent reconciliation must mark COMMITTED without appending another row. This tests process crash only, not abrupt power loss, corrupted storage, rollback, network partitions, consensus finality or malicious enrolled peers.

## Reproduction

```bash
python -m research_contracts.sigkill_ledger_recovery --trials 10
python -m unittest discover -s tests -p 'test_sigkill_ledger_recovery.py' -v
python -m unittest discover -s tests -v
```

**Execution status:** not run on a repository checkout; GitHub DNS resolution failed in execution container. Code and assertions committed, outcomes not measured.

## Next engineering task

Bind the reconciler to an actual production ledger inclusion adapter with verified digest and identity, inspect finality guarantees, then test simultaneous writers and interruption boundaries. Retain non-actuating simulation and fail closed on ambiguous inclusion.
