# V2X research readiness — 2026-11-23 quota clock negative controls

| Workstream | Status | Evidence / limitation |
|---|---|---|
| Global telemetry budget clock rollback | Implemented, unverified | high-water mark; reject nonfinite and backwards readings |
| Deterministic negative controls | Written, unverified | tests/test_telemetry_budget_clock_faults.py; no exact-checkout run |
| Authenticated hardware TCP ingress | Partial | integration and independent fault campaigns pending |
| Local emergency actuation isolation | Partial | remote actuation disabled; no physical HIL validation |
| Ledger crash consistency/finality | Partial | no external finality proof |
| Genuine VeReMi/CAN source provenance | Partial | CAM labels are not independent incident truth |
| Independent incident-level effectiveness | Blocked | independently sourced world-state incident labels absent |
| Runtime scaling and statistical inference | Upcoming | no matched multi-seed effect estimates |
| Original research article | Blocked | no defensible publication-grade incident evidence |

This is a safety-oriented engineering negative control, **not** evidence of attack detection efficacy, physical safety, or original cryptography. Existing fixture CSVs, three-peer poisoning sanity checks, five-iteration microbenchmarks and offline communication formulas remain non-publishable main results.

Run: `python -m unittest discover -s tests -p 'test_telemetry_budget_clock_faults.py' -v` then `python -m unittest discover -s tests -v`.

Next: exact-checkout focused/full regression, authenticated TCP saturation and rollback fault injection, independently annotated incident joins.
