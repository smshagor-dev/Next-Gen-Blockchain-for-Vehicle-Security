# Research status — durable hardware replay (2026-11-20)

| Workstream | State | Evidence / limitation |
|---|---|---|
| Authenticated hardware ingress | Partial | Existing MAC verifier; production socket and hardware validation pending |
| Durable nonce claims | Implemented, unverified | SQLite WAL/FULL, atomic claim before authorization; exact checkout tests blocked by GitHub DNS |
| Restart/replay regression | Implemented, unexecuted | Synthetic unit tests; no SIGKILL or power-cut experiment |
| Rollback resistance | Blocked | Host can restore old SQLite files; trusted monotonic anchor required |
| Emergency local authority | Blocked | No physical interlock test or actuator access |
| Ledger finality/crash consistency | Partial | Mock finality cannot establish consensus finality |
| Genuine VeReMi/CAN provenance | Partial | Existing separate issues/PRs; no incident-world truth from CAM labels |
| Matched adversarial comparisons | Upcoming | Same seeds/splits and negative controls needed |
| Runtime and statistical evaluation | Upcoming | No independent replicated process/network/CPU/RAM measurements |
| Publication-ready original research | Not ready | Fixture/microbench and synthetic checks not publishable effectiveness evidence |

Next: execute exact-branch tests, check bridge integration and durable path deployment, inject process crash and SQLite corruption, demonstrate rollback counterexample, then benchmark matched controls.
