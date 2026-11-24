# Serial ingress safety research status (2026-11-21)

| Workstream | State | Evidence / gap |
| --- | --- | --- |
| Pi TCP MAC, nonce, deadlines and concurrency | Existing main implementation | Hardware bridge source inspected; full runtime suite not rerun |
| Arduino serial byte and authenticated frame caps | Implemented in this draft | Pure-budget six tests passed locally, bridge integration not executed |
| Arduino serial authenticated rate budget | Implemented in this draft | Existing shared token-bucket class reused; serial device experiment pending |
| Local emergency-control precedence | Design-isolated | Remote actuation remains disabled; no physical HIL validation |
| Ledger crash consistency and external finality | Partial / blocked | No independent trusted anchor |
| Evidence-gated incident admission | Partial | Existing PR #79; source-independent world truth unresolved (#92) |
| Authentic VeReMi CAM evaluation | Partial | PRs #81, #84, #86; CAM labels are not incident truth |
| Real CAN/in-vehicle adversarial experiments | Upcoming | Source verification and matched baselines needed |
| Multi-seed runtime and statistical uncertainty | Upcoming | No inferential significance claim from sample size alone |
| Publishable independent evidence | Blocked | Hardware and authentic incident truth not available |

## Reproduction

```bash
python -m unittest discover -s tests -p 'test_serial_ingress_budget.py' -v
python -m compileall -q serial_ingress_budget.py hardware_bridge.py
```

The pure budget tests were executed on a local copy (6 passed). The full exact
GitHub checkout and real serial-port integration tests have not run because
direct Git access in the execution container cannot resolve github.com.

## Experimental controls and limits

A signed peer may still supply false measurements. Budget limits constrain
per-session work and do not establish physical safety or Byzantine resilience.
A serial port is closed on quota exhaustion; a local hardwired emergency-stop
must remain available independently of software and network admission.
The existing synthetic fixtures and microbenchmarks are non-publishable main
research results. No vehicle commands were issued.

## Mainline reconciliation (2026-11-24)
Reapplied byte, frame and rate budgets on top of current main's explicit SQLite serial nonce provisioning, observation freshness and disabled remote actuation. Quota exhaustion closes both the port and nonce store; the authenticated frame quota is evaluated after nonce verification, so quota rejection can consume a nonce. New mocked serial integration tests cover byte and frame exhaustion before ledger mutation. Exact merged-head CI is pending; no physical or publication efficacy claim.
