# Go ledger generation-rollback negative control — 2026-11-19

| Workstream | State | Evidence / next step |
| --- | --- | --- |
| Unauthenticated TCP ingestion / safe actuation | Partial on main; physical safety blocked | Existing MAC/framing and disabled ECU output inspected; no hardware test |
| Go ledger cross-generation rollback | Counterexample and monitor committed, unverified | Existing `GoLedgerSnapshotVerifier.reset()` forgets prefix when generation changes; five focused tests added |
| Ledger crash consistency | Partial, stacked draft PRs #149–#153 | Validate exact checkout and production inclusion adapter |
| External durable checkpoint/finality | Blocked | Process-local monitor loses pins at restart; obtain independent authenticated anchor |
| Evidence-gated V2X authorization | Upcoming | Formalize independent admission and non-actuating command policy |
| Authentic VeReMi NextGen/CAN data | Blocked | No authentic dataset/provenance verified in this run |
| Adversarial baseline comparisons and statistics | Upcoming | Multi-seed, common splits, uncertainty/effect sizes; n>=30 is not significance |
| Publishable paper | Blocked | No independent validated effectiveness evidence |

This branch is a **negative-control / instrumentation** change, not a fix for
distributed finality, and does not permit physical actuation. The unit test
mocks Go hash verification deliberately to isolate the generation-reset defect;
actual Go hash/link validation remains covered separately. No publication claim
may be based on these synthetic examples.
