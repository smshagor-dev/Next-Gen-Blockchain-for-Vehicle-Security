# V2X research status matrix — 2026-11-23

| Workstream | Status | Evidence / blocker |
| --- | --- | --- |
| Hardware TCP admission saturation and recovery | PARTIAL | Added socketpair-based negative controls for rejected excess peers, slot recovery and invalid capacity; exact-checkout tests pending |
| Authenticated TCP telemetry, bounded framing and local emergency stop | PARTIAL | Existing main modules; integration and physical actuation verification pending |
| Ledger crash consistency and rollback | PARTIAL | Separate draft PRs; production finality not established |
| Evidence-gated event admission and formal safety invariants | PARTIAL | Independent enrolled-colluder, partition and emergency-stop trials required |
| Authentic VeReMi NextGen/CAN provenance | BLOCKED | Independently sourced artifacts and license/provenance validation needed |
| Paired campaign statistics and baseline comparison | PARTIAL | Draft PRs #204–#206; no verified held-out effectiveness claims |
| Publication-grade multi-seed independent experiments | UPCOMING | Must establish genuine independent incidents and cluster-aware uncertainty |

## This change
The bounded TCP admission class is exercised without real hardware or vehicle actuation. The test verifies an occupied slot rejects an additional socket, recovers after the blocked handler exits, releases capacity on injected failure, and rejects invalid worker budgets. These controls **do not** demonstrate MAC verification, replay resistance, or a security improvement on authentic V2X data.

## Verification
Required on exact checkout:
`python -m unittest discover -s tests -p 'test_bounded_tcp_slow_peer_recovery.py' -v`
`python -m unittest discover -s tests -v`

Tests have not been executed in the GitHub checkout. No fabricated performance measurements or significance claims. Next: authenticated Pi TCP handler integration test with malformed MAC, replay, partial-frame deadline, and independent local emergency-stop continuity.
