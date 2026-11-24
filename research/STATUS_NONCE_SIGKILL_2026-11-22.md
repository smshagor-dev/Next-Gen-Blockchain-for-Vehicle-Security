# OmniGuard research status matrix — 2026-11-22

This branch is an isolated draft experiment, not a publication result. It does not claim physical vehicle validation.

| Workstream | Status | Evidence / limitation |
|---|---|---|
| Production SQLite nonce persistence | Partial | Existing `hardware_nonce_store.py` uses WAL, FULL synchronous, BEGIN IMMEDIATE; privileged snapshot rollback remains possible |
| SIGKILL after acknowledged nonce commit | Implemented, unverified | `tests/test_nonce_sigkill_durability.py::test_kill_after_acknowledged_commit` |
| SIGKILL before nonce claim | Implemented, unverified | `tests/test_nonce_sigkill_durability.py::test_kill_before_claim` |
| SIGKILL during SQLite COMMIT | Upcoming | Requires deterministic fault hook or external syscall instrumentation; never infer result from pre/post tests |
| Production TCP/serial safety integration | Partial | Pending combined exact-checkout regression |
| Emergency-stop independence | Blocked | No physical hardware or actuator test |
| Ledger crash consistency / external finality | Partial / blocked | SQLite local durability is not distributed consensus finality |
| Authentic VeReMi NextGen and CAN provenance | Pending | No authentic dataset evidence in this branch |
| Matched incident baselines and ablations | Pending | Fixture CSVs and microbenchmarks excluded from publication claims |
| Statistical comparison and paper | Blocked | Await authentic multi-seed incident-level experiments |

## Reproduction

```bash
python -m unittest tests.test_nonce_sigkill_durability -v
python -m unittest discover -s tests -v
```

The experiment uses independent OS processes, a temporary on-disk SQLite database, and a barrier immediately before the claim or after a successful acknowledged claim. It deliberately does **not** assert what happens to a transaction killed inside COMMIT. Run on Linux for SIGKILL semantics. Record OS, Python, SQLite version, filesystem and storage durability assumptions before using evidence in a paper.

## Next implementation

Introduce a narrowly scoped fault-injection hook around production transaction COMMIT (disabled in production), exercise SIGKILL during the transaction with multiple seeds, verify no double-acknowledged nonce, and compare crash behavior against a memory-only negative control. Resolve overlaps with open hardware ingress PRs before merge.
