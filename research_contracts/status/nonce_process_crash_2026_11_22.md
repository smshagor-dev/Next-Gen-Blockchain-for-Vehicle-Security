# Nonce crash-boundary experiment status — 2026-11-22

| Workstream | State | Evidence / limitation |
|---|---|---|
| Process termination after committed nonce claim | Implemented; exact-checkout execution pending | Spawned child acknowledges SQLite commit, is terminated, reopened store must reject replay |
| Concurrent duplicate claims | Implemented; execution pending | 64 claims / 12 threads; exactly one winner required |
| Nonce capacity recovery | Implemented; execution pending | Reopened full store must fail closed |
| Authenticated TCP ingress | Partial | Existing main; outstanding integration drafts #190/#191 |
| Arduino persistent nonce | Partial | Draft #194, integration unverified |
| Nonce claim + ledger atomicity | Blocked | Separate SQLite transactions; no transactional coupling |
| Physical emergency-stop validation | Blocked | No laboratory or vehicle evidence |
| Independent consensus finality | Blocked | Mock contract does not prove finality |
| Evidence-gated admission and baselines | Partial | Draft #189; no authentic held-out effectiveness |
| VeReMi NextGen and CAN provenance | Partial | Drafts #185–#188; authentic source validation pending |
| Paired multi-seed experiments | Upcoming | No publishable effectiveness estimates |
| Publication-ready research | Blocked | Do not use fixtures, 3-peer poisoning, 5-iteration microbenchmarks or offline formulas as primary evidence |

## Reproduce
```bash
python -m unittest discover -s tests -p 'test_nonce_crash_experiment.py' -v
python -m unittest discover -s tests -v
```

The process-kill test only examines recovery after an acknowledged SQLite commit. It cannot establish sudden power-loss durability, filesystem integrity, storage rollback resistance, ledger exactly-once delivery, or independent blockchain finality. The same nonce may be committed before a failed ledger write, causing a legitimate retransmission to be rejected. Follow-up: instrument the nonce-to-ledger boundary with deterministic fault injection and reconcile the existing durable event inbox rather than treating nonce persistence as end-to-end atomicity.
