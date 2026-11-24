# OmniGuard V2X research status — 2026-11-21

| Workstream | Status | Evidence / next action |
|---|---|---|
| Socket fragmentation, frame-size and total receive deadline | COMPLETED (isolated experiment) | 7 local socketpair tests passed; exact GitHub checkout not executed |
| Evidence-only socket session | COMPLETED (isolated experiment) | Closes connection, no actuation API |
| Production hardware_bridge integration | BLOCKED | Direct Git clone DNS failure; production receiver not inspected |
| Authenticated ingress and persistent replay | PARTIAL | Separate draft #173 and #172; not integrated into this branch |
| Connection concurrency quotas / worker exhaustion | UPCOMING | No listener or concurrency budget in this experiment |
| Local emergency override | BLOCKED | No physical hardware or production interlock validation |
| Ledger crash recovery and independent finality | PARTIAL | Drafts #168–#170; independent trusted anchor unavailable |
| Evidence-gated V2X admission | PARTIAL | Draft #171; colluding enrolled sources remain |
| VeReMi NextGen and authentic CAN provenance | UPCOMING | No real dataset loaded |
| Matched baseline, ablation and uncertainty analysis | UPCOMING | No publication-ready effectiveness data |
| Paper numerical claim ledger | BLOCKED | Await independent authentic evidence |

## Reproduce
`python -m unittest discover -s tests -p 'test_socket_boundary_experiment.py' -v`

Observed isolated local execution: 7 passed, 0 failed, approximately 0.219 seconds. This is a socketpair experiment, **not** a production TCP server, vehicle hardware or publishable V2X detection result. It has no authentication of its own: integrate only after independently reviewing production ingress and #173. Do not connect this to actuators.

## Next
Read actual hardware_bridge and any nested AGENTS.md after checkout is restored; combine frame limits, HMAC verification, durable nonce reservation, connection quotas, and local emergency precedence in an isolated integration branch. Run real localhost TCP adversarial experiments and independent authentic dataset baselines. Never infer statistical significance from n>=30 alone.
