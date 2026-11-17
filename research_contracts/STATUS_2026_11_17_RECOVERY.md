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
