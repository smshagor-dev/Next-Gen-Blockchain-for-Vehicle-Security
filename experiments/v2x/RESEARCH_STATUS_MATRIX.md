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

### 19 November 2026 — emergency-reset replay and one-shot control

| Workstream | Status | Evidence / next action |
|---|---|---|
| Epoch emergency-reset replay preservation | IMPLEMENTED / UNVERIFIED | PR #157: local stop/reset retains authenticated nonce and incident history; execute exact branch tests |
| One-shot incident authorization | IMPLEMENTED / UNVERIFIED | PR #157: quorum emits at most one positive decision per incident/epoch/event; test restart and cross-process replay persistence |
| Restart durability / independent epoch authority | BLOCKED | In-memory controls only; process restart loses pins; caller-supplied verified flag is not authentication |
| Hardware physical emergency precedence | BLOCKED | No physical bench or vehicle verification; bridge ECU/network egress remains disabled |

These are protocol regression controls, not independent effectiveness or publication evidence. Local operator reset is not a cryptographic re-enrollment event.
