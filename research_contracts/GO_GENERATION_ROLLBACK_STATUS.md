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

## 2026-11-19 follow-up: real-hash restart negative controls

- Added `tests/test_go_generation_real_hash_restart.py` (commit `df967e0`): four deterministic tests generating internally Go-hash-valid synthetic chains without mocking `verify_go_block`. Covers same-process truncation rejection, same-process rewritten suffix rejection, restart truncation acceptance, and fresh-observer rewritten-history acceptance.
- **Implemented, not yet executed on exact checkout:** GitHub DNS remains unavailable in local execution container. No pass/fail or latency claims. The controls demonstrate a missing external anchor; they do not establish ledger consensus finality or V2X effectiveness.
- **Next:** execute exact checkout tests and repair failures; implement a durable independently authenticated checkpoint/receipt provider with an explicit rollback trust model; revisit hardware ingress and authentic datasets before publication.

## 2026-11-19: stale pending recovery control (draft PR #154)

| Area | State | Evidence / limitation |
|---|---|---|
| Pre-rename SIGKILL leftover `.pending` | Implemented; exact checkout unverified | Under POSIX exclusive writer lock, discard stale pending bytes and fsync directory before reading committed state; never promote pending bytes |
| Restart with existing committed prefix | Regression authored, unexecuted | Replayed identical hashes must retain revision; shorter chain rejected after stale cleanup |
| Pending cleanup permission failure | Regression authored, unexecuted | Fail closed before issuing any new revision |
| Crash after rename but before directory fsync | Partial | Durable rename under real power loss not established; needs deterministic subprocess injection and filesystem-specific experiments |
| Independent key custody / monotonic trusted storage | Blocked | Same-host rollback and issuer-key compromise remain out of scope |
| Authenticated hardware ingress / physical emergency stop | Partial / blocked | No physical actuation enabled; physical validation unavailable |
| Authentic VeReMi NextGen and CAN matched baseline evidence | Pending | No publishable incident-level effectiveness results |
| Statistical publication claims | Blocked | Do not treat fixture CSVs, 3-peer sanity checks, five-iteration microbenchmarks or offline formulas as main evidence; n >= 30 is not a significance test |

Validation command (not executed on exact branch because GitHub checkout DNS failed):
`python -m unittest discover -s tests -p 'test_independent_checkpoint_issuer.py' -v`.
Next: run committed tests; instrument subprocess SIGKILL at write/fsync/replace/directory-fsync boundaries, and then integrate verified Go ledger hashes with the issuer. The POSIX advisory lock assumes cooperating writers and independently controlled directory permissions.


## 2026-11-19: real subprocess SIGKILL persistence-boundary controls

| Area | State | Evidence / limitation |
|---|---|---|
| SIGKILL before pending-file fsync | Test committed, unexecuted | Old committed prefix must remain authoritative; stale pending is discarded under lock |
| SIGKILL before atomic replace | Test committed, unexecuted | Old committed prefix must survive restart |
| SIGKILL after replace | Test committed, unexecuted | New prefix is expected visible to a restarted process; not proof of power-loss durability |
| SIGKILL before directory fsync | Test committed, unexecuted | New prefix expected visible after process kill; actual storage crash semantics unknown |
| Restart rollback and replay | Test committed, unexecuted | Shorter history must be refused and extension idempotent after recovery |
| Physical interlocks / authentic incident evidence | Blocked | No physical test or publishable attack-effectiveness evidence |

Code: `tests/test_issuer_sigkill_boundaries.py` (commit `fc95d1b2`), four subprocess fault boundaries using actual `IndependentCheckpointIssuer.issue()` and fresh temporary directories. Command: `python -m unittest discover -s tests -p 'test_issuer_sigkill_boundaries.py' -v`. **Not executed on exact repository checkout**; do not claim passing trials. SIGKILL is not power loss. Next: run exact tests, fix any process synchronization/portability failures, add authenticated Go hash-chain validation at issuer ingress and independently owned checkpoint anchor, then prioritize authentic VeReMi/CAN baseline experiments. No physical actuation or merge.
