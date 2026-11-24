# OmniGuard V2X research status — 2026-11-22

| Workstream | Status | Evidence / limitation |
| --- | --- | --- |
| TCP authenticated ingress | Partial | Existing MAC, durable nonce, deadline and byte guards; end-to-end adversarial test needed |
| Serial byte and frame quotas | Implemented, unverified | This branch adds byte quota and pre-MAC frame ceiling; no hardware test |
| TCP pre-MAC frame ceiling | Implemented, unverified | This branch checks batch quota before nonce claim |
| Local emergency precedence | Partial | Remote actuation disabled; physical emergency controls not validated |
| Ledger crash durability / finality | Partial / blocked | Fault injection not proof of distributed finality |
| Evidence-gated incident admission | Partial | Synthetic threat-model checks not real-world effectiveness |
| VeReMi NextGen / CAN provenance | Partial | Authentic incident labels and independent ground truth incomplete |
| Frozen matched multi-seed experiments | Upcoming | Incident-level uncertainty and ablations outstanding |
| Publication-ready research claims | Blocked | No physical tests, independent incident evidence or validated comparative statistics |

## This branch: reproducibility

```bash
python -m unittest tests.test_preverify_frame_budget -v
python -m unittest discover -s tests -v
```

Test file uses a mock verifier and deliberately checks invocation count: excess
frames must not call `verify`, because it can persistently consume a nonce.
This is an isolated source-contract test, **not** a live TCP/serial experiment.
The implementation and tests have not been run on the exact GitHub checkout.

Next: behavioral fake-serial / loopback TCP tests with signed frames and
persistent SQLite nonce store, including mid-batch quota exhaustion,
restart replay, malformed frame, trickle DoS, and emergency-control isolation.
No fixture-derived effectiveness, physical safety, or statistical significance
claims are permitted.

## Mainline reconciliation (2026-11-24)
Retained mainline serial budgets, persistent replay store and quarantine. Both serial and TCP pass the remaining frame allowance to the shared receive iterator. Existing regression controls are retained. Exact-head CI required.
