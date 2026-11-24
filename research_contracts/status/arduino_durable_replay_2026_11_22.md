# OmniGuard V2X research status — 2026-11-22

| Workstream | Status | Evidence / limitation |
|---|---|---|
| Arduino serial crash-persistent replay claims | Implemented; exact-checkout tests pending | `hardware_bridge.py` now requires provisioned SQLite nonce store; recovery fails closed |
| Pi TCP authenticated ingress | Partial | Existing bounded authenticated transport; independently test saturation and malformed frames |
| Local emergency stop isolation | Partial / physical validation blocked | No remote ECU actuation enabled; hardware safety tests not available |
| Ledger crash-consistent event admission | Partial | Nonce claim and ledger write are not one atomic transaction |
| Consensus finality | Blocked | Mock contract cannot establish independent finality |
| Evidence-gated admission and baselines | Prototype | Authentic held-out incidents and compromised-domain experiments missing |
| Authentic VeReMi NextGen/CAN acquisition | Blocked | Provenance and ground truth not independently validated |
| Matched multi-seed statistics | Upcoming | No publishable effectiveness estimates |
| Scientific manuscript | Blocked | Await independent data and experiments |

## Safety and evidence protocol
Run `python -m unittest discover -s tests -p 'test_arduino_durable_replay.py' -v` on the exact branch.
Provision `SMARTCAR_HW_SERIAL_NONCE_STORE_PATH` once using `SMARTCAR_HW_SERIAL_NONCE_STORE_PROVISION=true`; restart with false. Keep the serial store separate from the Pi TCP configuration.
Do not use the same nonce DB concurrently for independent bridge processes without validating deployment semantics.
Do not present these tests, fixture CSVs, three-peer poisoning sanity checks, five-iteration microbenchmarks, or offline formulas as publication-ready main research evidence.
Next: signed serial-envelope fake-device behavioral tests, fault injection between nonce claim and ledger commit, and authenticated Pi TCP replay/DoS integration.

## Mainline reconciliation (2026-11-24)
The production replay implementation is already integrated. Preserve the current shared provisioning helper, serial-specific configuration, cleanup and admission quotas. This PR retains the restart and missing-store regressions and adapts its source contract to main. Exact-head CI is required; no physical validation is claimed.
