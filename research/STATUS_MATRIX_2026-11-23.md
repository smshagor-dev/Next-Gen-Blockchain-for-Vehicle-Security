# Original research readiness matrix (2026-11-23)

| Workstream | Status | Evidence / next validation |
|---|---|---|
| Explicit signed motion and GPS evidence | Implemented in draft | Missing speed/acceleration/GPS rejected; tests added, not yet executed |
| Authenticated bounded hardware ingress | Partial | Integrate and test open hardware ingress PRs, including #207–#213 |
| Local emergency control isolation | Partial | Software remote-actuation fail-closed; independent physical validation unavailable |
| Ledger crash consistency and mock finality | Partial | Fault-injection and durable replay-claim tests required |
| Evidence-gated admission mechanism | Partial | Formalize independent safety properties and baseline equivalence |
| Authentic VeReMi NextGen/CAN provenance | Blocked | Publisher-pinned artifacts and independent split evidence required |
| Multi-seed adversarial comparisons | Upcoming | Held-out independent incidents, effect sizes, uncertainty, ablations |
| Original research article | Blocked | No publication-grade numerical results yet |

Fixture CSVs, three-peer poisoning checks, five-iteration microbenchmarks, and offline communication estimates are **not** main research evidence.

This branch's tests have **not** been executed against an exact checkout. Review potential compatibility effects on legacy telemetry producers before merge.
