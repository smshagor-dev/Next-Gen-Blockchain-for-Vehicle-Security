# Research validation checkpoint — 2026-11-20

Scope: draft PR #158; non-actuating paired SQLite/in-memory admission overhead only.

| Workstream | Status | Evidence / limitation |
| --- | --- | --- |
| Paired construction-order bias | Implemented, not executed | Benchmark now constructs each gate immediately before its assigned phase; previous code initialized SQLite first in every trial |
| Initialization-order regression | Implemented, not executed | `tests/test_paired_initialization_order.py` checks both assigned orders and the restart check |
| Crash / concurrency consistency | Partial | Existing tests need execution on exact branch and independent fault injection |
| Hardware authenticated ingress / emergency interlock | Partial, physical verification blocked | No physical vehicle or ECU access |
| Authentic VeReMi NextGen and CAN provenance | Pending | No independently verified authentic cohort in this change |
| Matched adversarial effectiveness and baselines | Pending | No publishable outcome from fixture traces |
| Multi-seed CPU/RAM/network/latency scaling | Pending | Current microbenchmark is non-publishable |
| Ledger finality and trusted rollback resistance | Blocked | SQLite durability is not blockchain consensus finality |
| Paper / numeric claim ledger | Pending | Do not write quantitative effectiveness claims before independent evidence |

Validation required before merge:

```sh
python -m unittest discover -s tests -p 'test_paired_initialization_order.py' -v
python -m unittest discover -s tests -p 'test_durable_admission_benchmark.py' -v
python -m unittest discover -s tests -v
python -m research_contracts.benchmark_durable_admission --repeats 30 --seed 20261120 --output /tmp/omni-initialization-order.json
```

The first two gate construction calls are part of the randomized phase order; the third SQLite construction is a deliberate restart replay probe. This correction removes a deterministic initialization-order confound, not cache, disk, temporal drift, OS scheduling or process effects. No tests or experiments were executed in this checkpoint. Next: execute exact checkout, investigate failures, then isolate processes and collect authenticated V2X/CAN evidence with source hashes.
