# OmniGuard V2X research status (2026-11-21)

This matrix distinguishes code review, isolated checks, integration validation, and scientific evidence. It does not supersede status files in other draft PRs.

| Area | Status | Evidence / next gate |
| --- | --- | --- |
| TCP enrolled-device authentication and bounded receive | Partial | Present on main; full hostile-network integration and HIL unverified |
| Serial lazy-verifier failure quarantine | Implemented, unverified | This branch wraps generator consumption; four regression tests committed, exact checkout not executed |
| Serial sustained flooding and quotas | Partial | Coordinate with serial budget work in separate PR; do not infer integration |
| Local emergency-control independence | Software boundary present; physical blocked | ECU gateway refuses remote actuation; hardwired emergency interlock requires physical tests |
| Durable nonce replay and crash consistency | Partial | SQLite replay exists; independent crash/reboot and rollback experiments outstanding |
| Distributed ledger finality | Blocked | Mock contract / same-host storage cannot prove independent finality |
| Evidence-gated V2X incident admission | Partial | Policy exists; colluding enrolled nodes and partition availability remain research gaps |
| VeReMi NextGen/CAN provenance | Partial | CAM attacker labels are not independently validated incident truth |
| Independent matched incident baselines and ablations | Upcoming | Require world-state manifest, zero-capture incident accounting and authentic sources |
| Latency/CPU/RAM/throughput statistical comparisons | Upcoming | Multiple independent trials and uncertainty intervals; n>=30 alone is never significance |
| Publication-ready original scientific evidence | Blocked | No independent real-world incident efficacy or hardware validation |

## Reproduce this patch

```bash
python -m unittest discover -s tests -p 'test_serial_generator_quarantine.py' -v
python -m unittest discover -s tests -v
```

Risk: the fix quarantines serial framing/authentication failures during *iteration* instead of leaking a raw transport exception. Previously emitted verified frames may already have reached the ledger before a later frame fails; no atomic batch rollback is claimed. This is an engineering safety correction, not a publishable detection result.
