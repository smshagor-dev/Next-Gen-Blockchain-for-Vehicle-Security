# Research validation status — bounded TCP admission branch

Updated 2026-11-14. No publication or hardware safety certification is implied.

| Workstream | Status | Evidence / gap |
| --- | --- | --- |
| TCP admission capacity primitive | Implemented, unverified | BoundedSemaphore prevents unbounded handler threads; immediate socket close on saturation |
| Loopback saturation regression | Locally validated (isolated copy) | Two additional real loopback tests: partial-frame slow peer does not block independent admitted worker; saturated peer rejected without queue. Both passed locally 2026-11-13. Full repository CI pending |
| Integration with hardware_bridge.run_pi_mode | Implemented, unverified | Production accept loop now dispatches to bounded worker pool, with shared verifier and ledger/actuator locks; no full checkout tests or live fault injection yet |
| Shared verifier / token-bucket / ledger thread safety | Partial | Shared replay verification and chain/dispatcher serialized with locks, token bucket locked; full stress validation and lock-order review pending |
| Authenticated ingress / interlocks | Partial | Existing draft branch and main differ; no physical emergency stop evidence |
| Durable nonce and crash consistency | Partial | Simulation-only tests; no physical power-loss or rollback guarantee |
| Contract finality | Blocked | Mock finality is not consensus finality |
| Novel mechanism / formal properties | Upcoming | Independent prior-art comparison and falsifiable safety hypotheses |
| Authentic VeReMi NextGen and CAN datasets | Upcoming | Provenance and license verification required |
| Independent multi-seed adversarial evaluation | Blocked | Existing synthetic world experiments are not independent incident truth |
| Runtime scaling / statistical analysis | Blocked | No credible multi-seed system benchmark or effect-size report |
| Manuscript | Blocked | Fixture CSVs, three-peer sanity checks, five-iteration microbenchmarks and formulas are not publishable primary results |

## Validation commands
`python -m unittest discover -s tests -p 'test_bounded_tcp_admission.py' -v`
`python -m py_compile bounded_tcp_admission.py tests/test_bounded_tcp_admission.py`

Two new tests in tests/test_slow_peer_admission.py passed (2/2) in a local isolated copy of the fetched admission implementation; this does not validate the full GitHub checkout or production Pi server. Original branch tests were not run. Do not merge as a production DoS fix until integration and live fault-injection validation.

Additional command: `python -m unittest discover -s tests -p 'test_slow_peer_admission.py' -v`\n\nNew validation: `python -m unittest discover -s tests -p 'test_shared_tcp_budget.py' -v`. Not yet executed against full checkout; no passing claim.\n\n## Next coding task
Refactor the existing authenticated Pi per-connection loop into a worker function, wire this bounded admission, protect shared verifier replay state and global token buckets with locks, serialize ledger mutations, then test slow-client starvation and concurrent authenticated sessions on real loopback sockets.

## 2026-11-14 integration checkpoint
Production Pi accept loop refactored to bounded per-connection workers (max clients 1–64). Admission budget is charged before worker dispatch; saturated sockets are closed immediately. Shared verifier replay check-and-claim and ledger/dispatcher mutation now use separate locks. New AST integration guards added. Commits: 46d6f8f, e673cd6, 59dae5f. GitHub checkout DNS failed in this environment; **no repository tests executed**. These changes are not proof of resistance to distributed DoS, and physical emergency control is unchanged and unverified.

Next: execute `python -m unittest discover -s tests -p 'test_pi_worker_integration.py' -v` and existing socket tests on an actual checkout; perform simultaneous authenticated replay and Slowloris tests, review lock contention and remote actuator blocking, and do not merge until verified.
