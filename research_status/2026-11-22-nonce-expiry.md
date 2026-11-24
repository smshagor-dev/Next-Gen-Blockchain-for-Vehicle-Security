# Research status — 2026-11-22 (nonce expiry boundary run)

| Workstream | Status | Evidence / limitation |
|---|---|---|
| Production nonce expiry overflow and precision-loss rejection | Implemented, checkout tests pending | Finite and strictly advancing expiry enforced before BEGIN IMMEDIATE; tests/test_nonce_expiry_boundaries.py |
| Durable nonce replay after restart | Partial | Regression covers reopening; SIGKILL / mid-COMMIT crash evidence still pending (draft #181) |
| Hardware TCP authentication and bounded ingestion | Partial | Integration and physical validation pending |
| Local emergency-stop isolation | Blocked | No physical actuator or HIL access |
| Ledger receipt authenticity and external finality | Blocked | Local mock receipts are not consensus finality; see issue #91 |
| Independently labeled V2X incidents | Partial | World-truth/source-join issue #92; synthetic fixtures excluded from main results |
| Authentic VeReMi NextGen and CAN datasets | Partial | Provenance, incident labels and matched baselines not validated |
| Multi-seed latency, scaling, effect sizes | Upcoming | No publication-grade evidence |
| Scientific manuscript | Blocked | Wait for independently sourced and replicated evidence |

## Reproduce

```bash
python -m unittest discover -s tests -p 'test_nonce_expiry_boundaries.py' -v
python -m unittest discover -s tests -v
```

The code changes are software hardening, not original cryptography or vehicle-safety validation. No tests were claimed passing in this run: the execution host could not resolve github.com to obtain the exact checkout. Avoid merging until exact-checkout tests and PR overlap review complete.
