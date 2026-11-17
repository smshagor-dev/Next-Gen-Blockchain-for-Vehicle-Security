# OmniGuard V2X research status — 2026-11-17 recovery checkpoint

| Workstream | Status | Evidence / remaining gap |
| --- | --- | --- |
| Missing replay database fail-closed recovery | Implemented, execution pending | `SQLiteAtomicReplayGate(..., require_existing=True)` rejects missing and empty files; five regression cases added |
| Atomic authenticated replay batch | Partial | Simulation code present; full regression execution and production wiring pending |
| Pi authenticated TCP, bounds, DoS | Partial | Production path and simulation must be reviewed together; no live socket experiment in this checkpoint |
| Local emergency actuation isolation | Unverified | No physical hardware evidence; network authorization must never override local emergency |
| Crash consistency and ledger finality | Partial / blocked | Normal SQLite reopen is not power-loss durability; mock contracts cannot establish consensus finality |
| Original evidence-gated V2X mechanism | Upcoming | Threat model, safety properties, prior-art comparison, preregistered hypotheses needed |
| Authentic VeReMi NextGen and CAN provenance | Blocked | Dataset licenses, checksums, splits and genuine records not yet validated |
| Independent matched adversarial experiments | Blocked | Fixture and microbenchmark outputs excluded from publication evidence |
| Multi-seed runtime and effect-size analysis | Upcoming | No statistical significance inferred from n >= 30 |
| Research manuscript | Not ready | Await authentic independent evidence and numeric-claim ledger |

## Changes

- `b9b00f4`: recovery-only opt-in prevents silently recreating a deleted replay DB.
- `5a1103b`: five executable recovery/provisioning regressions.
- Draft PR: https://github.com/smshagor-dev/Next-Gen-Blockchain-for-Vehicle-Security/pull/141

## Validation

Repository tests **not executed** in this run; GitHub connector writes are not test results.

```bash
python -m unittest discover -s research_contracts -p 'test_replay_missing_database_recovery.py' -v
python -m unittest discover -s research_contracts -p 'test_*.py' -v
```

## Important limitations and next code task

The recovery flag is **opt-in**, not wired to production startup. A stat-before-connect path check is susceptible to concurrent filesystem replacement and is not a defense against a privileged adversary; further work should use securely owned storage, explicit provisioning markers, schema/integrity validation, and a verified production recovery path. Never enable network-controlled physical actuation without independent local interlocks.

Next: audit production `hardware_bridge` replay-store startup and implement fail-closed recovery (separate explicit provisioning) with authenticated loopback fault injection and measured honest-client throughput/rejection latency. Review PR #140/#141 dependencies before merge.

## 2026-11-17 storage rollback counterexample

- Implemented `experiment_replay_storage_rollback.py` (commit `fab47c29`) to capture an online SQLite backup at high-water 10, advance to 11, then restore the older committed backup and attempt sequence 11 again.
- **Observed in a separate local SQLite probe:** WAL mode enabled; high-water before restore 11; after restoring an older consistent backup 10. This establishes a storage rollback counterexample for unanchored SQLite persistence, not execution of the committed experiment script or a production receiver test.
- A legitimate MAC plus durable replay database does not prevent re-admission after privileged snapshot rollback. The experiment intentionally asserts the vulnerability to prevent falsely claiming anti-rollback protection.
- Research implication: require a separately protected monotonic anchor / attested secure counter or clearly exclude privileged rollback from the threat model. A mere `require_existing=True` existence check does not detect a valid older snapshot.
- Run: `python research_contracts/experiment_replay_storage_rollback.py --trials 3 --output /tmp/replay_storage_rollback.csv`. The committed script has **not** been executed in a complete repository checkout due to GitHub DNS failure.
- Matrix: SQLite snapshot rollback resistance = **blocked / demonstrated design limitation**; production durable replay integration = **upcoming**; physical emergency control = **unverified**; authentic dataset and multi-seed V2X results = **blocked**. This CSV is not publishable primary attack-detection evidence.
- Next code task: implement explicit recovery integrity/anti-rollback policy and production fail-closed replay-store wiring, then run real authenticated loopback replay and slow-peer experiments.

## 2026-11-17 schema recovery hardening

- **Implemented (not executed):** Recovery now checks SQLite integrity, requires the replay_highwater table to exist, validates expected node/seq column types and primary key, and rejects negative/null persisted high-water. It no longer creates the replay table when require_existing=True. Commit `1152f7f`.
- **Regression suite added:** `test_replay_recovery_schema.py` covers unrelated SQLite files, incompatible schemas, valid persisted replay rejection, and corrupt nonempty files. Commit `f774140`.
- **Validation:** No checked-in tests executed this run. Execute `python -m unittest discover -s research_contracts -p 'test_replay_recovery_schema.py' -v` and the full replay suite before merge. No claim of production safety or empirical effectiveness.
- **Remaining gap:** Schema checking does not detect a valid older snapshot, malicious database replacement, or guarantee startup integration in hardware_bridge. Next code task: explicit provision/recovery integration and authenticated loopback fault experiments, with emergency control isolated from network authorization.
