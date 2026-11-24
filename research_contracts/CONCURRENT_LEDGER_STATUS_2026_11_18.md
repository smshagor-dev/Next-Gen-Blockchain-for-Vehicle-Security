# Concurrent ledger/inbox research evidence matrix — 2026-11-18

| Workstream | Status | Evidence / limitation |
| --- | --- | --- |
| Authenticated bounded TCP ingress | PARTIAL | Production integration and hardware isolation require independent verification; draft #148 |
| Durable replay and rollback | PARTIAL | SQLite prototype; snapshot rollback negative control; draft #145–#146 |
| Ledger crash recovery | PARTIAL | Separate SQLite surrogate and SIGKILL boundary; draft #150–#151; not blockchain finality |
| Concurrent same-identity writer campaign | IMPLEMENTED, UNVERIFIED | This branch adds independent SQLite connections, barrier-synchronized workers, conflicting digest controls, per-trial JSON, four tests |
| Production ledger inclusion/finality | BLOCKED | No verified production append_once/lookup or consensus finality adapter |
| Emergency-stop hardware behavior | BLOCKED | No physical lab/hardware access; remote actuation remains disabled |
| Authentic VeReMi NextGen/CAN cohort evaluation | PENDING | Do not promote fixture or synthetic sanity checks |
| Multi-seed adversarial effectiveness/uncertainty | PENDING | No publishable matched-baseline evidence |
| Runtime latency/CPU/RAM/throughput | PENDING | No independent measured scaling study |
| Research paper | BLOCKED | Claims ledger, baselines, provenance and uncertainty incomplete |

## Test protocol
`python -m unittest discover -s tests -p 'test_concurrent_ledger_recovery.py' -v`

`python -m research_contracts.concurrent_ledger_recovery --trials 20 --workers 4`

`python -m unittest discover -s tests -v`

No tests executed on the actual repository checkout in this run because github.com DNS resolution failed in the execution container. Expected assertions are not measured results. The thread barrier synchronizes attempt start, not exact SQLite transaction overlap. SQLite surrogate is not a distributed blockchain; process concurrency, power loss, Byzantine consensus, physical actuation and authenticated ingress integration remain outside this campaign. No statistical significance can be inferred from trial count.

Next: execute checkout tests, inspect SQLite initialization contention, add process-based concurrent writers and fault-injected verified inclusion adapter; keep draft until review.
