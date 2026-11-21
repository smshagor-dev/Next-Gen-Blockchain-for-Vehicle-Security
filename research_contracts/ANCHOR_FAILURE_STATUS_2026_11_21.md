# Replay anchor fault-ordering research matrix — 2026-11-21

| Component | Status | Evidence / limitation |
| --- | --- | --- |
| Authenticated ingress and bounded TCP parsing | Partial | Earlier stacked draft branches; exact integrated tests outstanding |
| Local emergency stop and physical interlocks | Blocked | No physical access or demonstrated safety |
| SQLite durability / corruption / snapshot rollback | Partial | Earlier draft code and negative controls; no trusted rollback guarantee |
| Independent reservation protocol | Partial | PR #164 simulation oracle; not a trusted external authority |
| Paired failure-ordering experiment | Implemented, unverified | `research_contracts/anchor_failure_tradeoff.py`, three protocols, shared seeded incident faults |
| Six model invariants | Implemented, unexecuted | `tests/test_anchor_failure_tradeoff.py` |
| Real crash/network fault injection | Upcoming | Subprocess kills, network timeouts, receiver integration |
| VeReMi NextGen and CAN provenance | Upcoming | Authentic raw files and licensing/label provenance required |
| Matched attack baselines and uncertainty | Upcoming | No publishable independent evidence |
| Research manuscript | Blocked | No validated dataset-based effects or performance evidence |

**Model assumptions:** all incidents are synthetic, each with one nonce. Snapshot rollback clears the local nonce set but leaves the simulated anchor intact. Bernoulli faults are generated once per seed and shared across protocols. The model has no network, actual SQLite, clock drift, concurrency, hardware or external trust authority. It is for hypothesis falsification and experiment planning, not the main scientific result. A seed count of 30 does not establish statistical significance.

**Run:** `python -m unittest discover -s tests -p 'test_anchor_failure_tradeoff.py' -v` and `python -m research_contracts.anchor_failure_tradeoff --seeds 30 --incidents 1000 --output /tmp/anchor_faults.csv`. Full suite: `python -m unittest discover -s tests -v`.

**Next:** execute exact checkout tests, add actual subprocess fault injection and independent anchor service boundary with authenticated calls and explicit timeout policy. No physical actuation or claims of field protection.
