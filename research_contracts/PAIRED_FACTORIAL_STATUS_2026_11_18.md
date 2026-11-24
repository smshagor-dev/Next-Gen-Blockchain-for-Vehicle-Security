# OmniGuard V2X research status — 2026-11-18

| Workstream | State | Evidence / blocker |
|---|---|---|
| Bounded authenticated TCP receiver | PARTIAL | Draft #140/#141 simulation; production hardware_bridge interlock and emergency-stop isolation unverified |
| Durable replay / ledger crash consistency | PARTIAL | Draft #141 SQLite admission precursor; power-loss and ledger finality not demonstrated |
| Evidence-gated admission mechanism | PARTIAL | Explicit independent-group vs sender quorum comparisons; compromised groups defeat independence |
| Factorial paired threat campaign | IMPLEMENTED, NEEDS REPO VALIDATION | This branch: seeded 0/1/2 compromised group scenarios, honest and correlated error, four policies and per-incident ground truth |
| Authentic VeReMi NextGen / CAN provenance | BLOCKED | Real source recordings, license, checksums and independent cohort validation required |
| Runtime TCP DoS / latency / CPU / RAM | UPCOMING | Safe non-actuating loopback campaign and bounded receiver instrumentation required |
| Statistical publication evidence | BLOCKED | Real held-out data, multiple independent trial clusters, effect estimates and uncertainty absent |
| Physical emergency-stop safety | BLOCKED | No hardware access or physical verification; do not claim vehicle safety |
| Scientific paper | NOT READY | Fixture/synthetic results, 3-peer poisoning and 5-iteration microbenchmarks are not main evidence |

## Current branch validation

Local equivalent of the standalone simulation and five unit tests executed (5/5 pass); exact committed repository test not yet executed. Smoke experiment: 5 seeds × 3 compromise levels × 30 incidents × 4 policies = 1800 simulated rows. **These are synthetic methodological checks, not efficacy results.**

Run against checkout:

```bash
python -m unittest discover -s tests -p 'test_paired_factorial_fault_campaign.py' -v
python research_contracts/paired_factorial_fault_campaign.py --incidents 1000 --output results/paired_factorial.csv
```

Next code task: instrument a non-actuating bounded authenticated TCP loopback receiver for per-client deadlines, replay/tamper outcomes, legitimate availability and resource consumption. Keep all physical actuator paths disconnected.
