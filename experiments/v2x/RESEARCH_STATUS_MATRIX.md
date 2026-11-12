# Research evidence status (12 November 2026)

| Workstream | Status | Evidence / next action |
|---|---|---|
| Hardware bridge TCP authentication, bounded ingress, replay, safe actuation | PARTIAL / REVIEW REQUIRED | Review PR #74 and validate emergency-local bypass before deployment |
| Ledger crash consistency | PARTIAL | Draft PR #90; fault-injected subprocess checks, no real power-cut evidence |
| Ledger rollback resistance and contract finality | BLOCKED | Valid older checkpoint rollback and unkeyed receipt forgery remain possible; independent trust anchor needed |
| Evidence-gated incident admission | PARTIAL | Synthetic policy and adversarial checks; independent real incident truth absent |
| Incident universe / hub capture provenance | PARTIAL | This branch implements source-pinned world universe and HMAC-bound export join; synthetic tests only; external trusted labels and hub key management absent |
| Authentic VeReMi CAM baseline | PARTIAL | PRs #82/#85 and transfer study; CAM attacker labels are not incident ground truth |
| CAN / in-vehicle datasets | UPCOMING | Verify rights, authentic source hashes and physically meaningful split protocol |
| Independent attack / fault / DoS experiments | BLOCKED | Need real-world incident labels, authenticated captures, independent scenarios and matching baselines |
| Network latency, CPU, RAM, throughput | UPCOMING | Record actual measured environment, repetitions and raw samples |
| Multi-seed statistics and paper | BLOCKED | No independent incident-level replication; n>=30 alone never establishes significance |

No fixture CSV, 3-peer poisoning sanity check, 5-iteration microbenchmark, or offline formula is publication-ready evidence. Never infer physical actuation safety from offline simulations.
