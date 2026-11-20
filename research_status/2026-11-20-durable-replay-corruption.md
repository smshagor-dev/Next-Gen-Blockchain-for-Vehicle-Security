# OmniGuard V2X research validation matrix — 2026-11-20

| Workstream | State | Evidence and limitation |
| --- | --- | --- |
| Durable nonce atomic claims | Partial | SQLite WAL/FULL implementation in draft PR #160; exact checkout regression not yet executed |
| Startup replay-state corruption rejection | Implemented, unverified | PR #160 adds PRAGMA quick_check and two regression cases; local SQLite smoke check confirmed damaged header raises DatabaseError, but exact repo tests remain pending |
| Process concurrency and SIGKILL | Partial | Regression code exists on PR #160; actual exact-branch runs pending |
| Rollback-resistant replay | Blocked | Restored DB snapshot can erase nonce history; needs independently trusted monotonic anchor |
| Hardware ingress and local emergency override | Partial / blocked | Remote interlocks need runtime audit; physical emergency-stop independence cannot be asserted without hardware |
| Ledger finality and crash consistency | Partial | SQLite surrogates do not prove blockchain consensus or finality |
| Authentic VeReMi NextGen / CAN provenance | Upcoming | No independently verified authentic experimental cohort yet |
| Matched attack and ablation experiments | Upcoming | No publishable effectiveness measurements |
| Statistical comparison and runtime scaling | Upcoming | Need real independent multi-seed measurements, cluster-aware uncertainty and effect sizes |
| Manuscript and claim ledger | Blocked | Publishable evidence incomplete; fixtures and microbenchmarks excluded from main claims |

## Reproduction

```bash
python -m unittest discover -s tests -p 'test_durable_replay_corruption.py' -v
python -m unittest discover -s tests -p 'test_nonce_transaction_boundaries.py' -v
python -m unittest discover -s tests -p 'test_durable_nonce_process_faults.py' -v
python -m unittest discover -s tests -v
```

Do not merge draft #160 until exact-checkout tests and review. Next code task: integrate fail-closed durable store into production bridge configuration and exercise receiver restart, concurrent ingress, and database fault injection without actuating hardware.
