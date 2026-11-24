# OmniGuard V2X research status — 2026-11-22 — JSON nesting ingress boundary

| Workstream | State | Evidence / remaining work |
|---|---|---|
| Excessive hardware JSON nesting | Implemented; exact-checkout tests pending | Hardware transport converts Python parser recursion exhaustion to unauthenticated fail-closed transport error; 3 regression tests |
| Authenticated TCP ingress | Partial | Cross-PR reconciliation and signed loopback workload still needed |
| Serial durable replay | Partial | Draft #194 needs integration verification |
| Local emergency control | Partial / physical validation blocked | Remote actuation disabled; no HIL evidence |
| Atomic nonce + event inbox | Partial | Draft #197; production integration missing |
| Ledger idempotency/finality | Blocked | No independent distributed finality evidence |
| Evidence-gated incident admission | Partial | Need independently labeled incident world truth and matched baselines |
| Authentic VeReMi/CAN evaluation | Partial | Verify official provenance and independent splits |
| Multi-seed paired statistics | Upcoming | No claim of significance from n>=30 |
| Original research article | Not ready | Fixture CSVs, microbenchmarks, and formula estimates excluded |

## Verification protocol

```sh
python -m unittest tests.test_hardware_json_nesting -v
python -m unittest discover -s tests -v
```

No tests have been executed on the exact committed checkout in this run. This change is an engineering DoS-boundary fix, **not** original V2X detection effectiveness evidence. Next: run the exact-checkout test, fuzz malformed signed/unsigned frames under the same resource budget, and integrate durable nonce/inbox processing.
