# Independent replay anchor experiment — 2026-11-21

| Research component | State | Evidence / limitation |
| --- | --- | --- |
| SQLite durable nonce admission | Partial | Existing stacked draft PRs; exact branch tests not yet executed |
| Live database path substitution guard | Partial | Prior stacked branch, runtime verification outstanding |
| Historical snapshot rollback counterexample | Partial | Non-actuating test exists; independent runtime execution outstanding |
| Independent reservation-first anchor protocol | Implemented, unverified | `independent_replay_anchor.py` and three falsifiable tests |
| Real independent trusted monotonic authority | Blocked | No external non-rollbackable hardware/service access or trust proof |
| Crash-safe availability | Blocked | Reserve-first can consume nonce before SQLite commit; intentional safety/availability trade-off |
| Production receiver integration | Upcoming | Must not enable without authenticated independent anchor, timeout policy, and integration tests |
| Local emergency actuation | Blocked | No physical actuator or emergency-control test evidence |
| VeReMi NextGen / CAN independent evaluation | Upcoming | Authentic data provenance and matched baselines required |
| Publishable research evidence | Not ready | No validated multi-seed attack/latency results |

Hypothesis H1: under a restored historical SQLite snapshot, a nonce previously reserved by an *independently retained* anchor will be rejected; SQLite-only admission can reaccept it. H2: reservation-first produces false rejection after a local DB failure, a measurable safety/availability cost. These are protocol properties, not cryptographic novelty or measured field effectiveness.

Run: `python -m unittest discover -s tests -p 'test_independent_replay_anchor.py' -v` then `python -m unittest discover -s tests -v`. Do not count fixture results, 3-peer sanity checks, 5-iteration microbenchmarks, or offline formulas as main research evidence. The simulation anchor is an in-memory oracle, **not** a trusted hardware anchor. No production or physical safety claims.
