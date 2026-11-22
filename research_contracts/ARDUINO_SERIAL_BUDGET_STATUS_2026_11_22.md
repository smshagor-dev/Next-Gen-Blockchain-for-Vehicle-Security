# OmniGuard V2X research status — 2026-11-22 (serial ingress budgets)

Scope: draft branch `fix/bounded-arduino-serial-ingress`; no vehicle or physical safety claims.

| Workstream | Status | Evidence / limitation |
|---|---|---|
| Arduino per-session byte and authenticated-frame ceilings | Implemented; exact-checkout execution pending | Production loop now quarantines on budget exhaustion |
| Arduino replay persistence | Partial | Separate draft PR #180; not duplicated here |
| TCP authenticated bounded admission | Partial | Existing production implementation; integration review needed |
| Independent local emergency stop | Preserved by design; physical validation blocked | No remote actuation enabled |
| Ledger crash consistency and finality | Partial / blocked | SQLite/ledger fault experiments and independent finality missing |
| Evidence-gated admission mechanism | Partial | Existing #189; no real-world effectiveness evidence |
| Authentic VeReMi NextGen / CAN incident labels | Blocked | CAM attacker flags are not independently labeled incidents |
| Matched multi-seed incident experiments | Upcoming | Freeze independent incident universe and baselines first |
| Publication-ready evidence | Blocked | No validated real incident or hardware experiment |

## Validation protocol

```sh
python -m compileall -q hardware_bridge.py tests/test_arduino_serial_budgets.py
python -m unittest discover -s tests -p 'test_arduino_serial_budgets.py' -v
```

The source-contract tests are narrow checks, not serial behavioral tests. Next implement
fake-serial end-to-end injection with authentic signed frames and assert no ledger mutation
after caps; reconcile replay persistence PR #180 before merging. A peer can still spend
bounded work on a frame whose nonce is verified before the frame counter is checked;
future work should enforce the limit before nonce claim.
