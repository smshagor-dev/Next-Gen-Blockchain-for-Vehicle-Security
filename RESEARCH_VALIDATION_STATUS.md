# Research validation status — bounded TCP admission branch

Updated 2026-11-14. No publication or hardware safety certification is implied.

| Workstream | Status | Evidence / gap |
| --- | --- | --- |
| TCP admission capacity primitive | Implemented, unverified | BoundedSemaphore prevents unbounded handler threads; immediate socket close on saturation |
| Loopback saturation regression | Locally validated (isolated copy) | Two additional real loopback tests: partial-frame slow peer does not block independent admitted worker; saturated peer rejected without queue. Both passed locally 2026-11-13. Full repository CI pending |
| Integration with hardware_bridge.run_pi_mode | Upcoming | Current production accept loop is sequential; this branch alone does NOT fix production Slowloris starvation |
| Shared verifier / token-bucket / ledger thread safety | Partial | GlobalTelemetryBudget claim now locked with concurrent regression; verifier replay cache, ledger and actuation remain unprotected. Production worker integration blocked |
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
