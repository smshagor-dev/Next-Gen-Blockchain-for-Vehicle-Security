# OmniGuard research matrix — 2026-11-22

| Area | Status | Evidence / blocker |
|---|---|---|
| Hardware TCP authentication and bounded ingress | PARTIAL | Main contains MAC/replay and bounded TCP paths; draft #180, #190-#192 require integration verification |
| Local emergency safety isolation | PARTIAL | Remote actuation disabled in bridge; physical interlock tests BLOCKED |
| Ledger crash consistency | PARTIAL | Main has durable inbox; commit-phase/power-loss validation BLOCKED |
| Consensus finality | BLOCKED | Mock contract does not establish independent consensus finality |
| Evidence-gated event admission | PARTIAL | Draft #189 reference model; independent attack effectiveness not established |
| Authentic VeReMi NextGen / CAN ingestion | PARTIAL | Draft #185-#188; source provenance and authentic labelled incident datasets BLOCKED |
| Offline CAN replay/spoof/false-data injection | IMPLEMENTED, isolated validation | This branch: deterministic seed, canonical trace hash, injection-only labels; six local equivalent tests passed |
| Matched baseline/ablation experiments | UPCOMING | Require frozen authentic incident splits and independent labels |
| Network latency/CPU/RAM/scaling | UPCOMING | No credible multi-seed runtime results |
| Paper and numeric claim ledger | BLOCKED | No publishable effectiveness evidence |

## Protocol constraints
Synthetic injection labels must never be treated as independently observed real attacks. No real CAN hardware, vehicle bus, actuator, or lab experiment was used. Replayed source data are placed at later observation timestamps and preserve source-index metadata; this is a simplified CAN-level perturbation, not a V2X cryptographic replay. The generated scenarios are suitable for negative controls and engineering pretests, not primary publication outcomes.

## Reproduction
`python -m unittest discover -s tests -p 'test_can_attack_protocol.py' -v`

Six isolated tests passed on the equivalent implementation before connector commit; exact GitHub checkout/full integration suite unverified. Review draft #188 for source-format integration and draft #189 for admission-model integration. Next: independent held-out incident tests with identical splits and compromised-domain adversaries.
