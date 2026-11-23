# OmniGuard original research readiness — 2026-11-23 concurrent budget check

| Workstream | Status | Evidence / remaining gate |
| --- | --- | --- |
| Concurrent aggregate telemetry budget | PARTIAL | Three deterministic regression scenarios committed; exact checkout execution pending |
| Signed ingress and replay/tamper resistance | PARTIAL | Integrated authenticated loopback adversarial evaluation still required |
| Independent local emergency control | BLOCKED | No physical interlock/HIL evidence; network-originated actuation must remain disabled |
| Ledger crash consistency and finality | PARTIAL | No distributed-finality proof; crash/restart and external anchor validation pending |
| Incident-level original research | BLOCKED | Independently labeled world truth and real incident evidence missing |
| VeReMi NextGen / CAN | PARTIAL | Message-level CAM evidence is not independently annotated incident truth |
| Multi-seed comparative inference | UPCOMING | Matched baselines, effect sizes, confidence intervals, preregistered analysis needed |
| Manuscript | BLOCKED | Do not promote fixtures, 3-peer poisoning checks, five-iteration microbenchmarks, or communication formulas to primary results |

## Test contract
`python -m unittest discover -s tests -p 'test_telemetry_budget_concurrent_admission.py' -v`

The three tests require the **real** GlobalTelemetryBudget and verify that a shared process quota cannot be multiplied by concurrent TCP sessions. They do not verify network fairness, replay handling, sensor truth, or real-time performance. Run focused and full suite in an exact repository checkout before merge. Related draft #218 tests clock rollback; this branch tests concurrent budget claims without changing that implementation.

Next: integrate an authenticated loopback TCP flood with legitimate and malicious enrolled identities and record latency, legitimate admission fraction, rejected frames, CPU/RAM and source digests. No physical actuation.
