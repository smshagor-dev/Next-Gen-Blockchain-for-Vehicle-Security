# Original research article evidence matrix — 2026-11-23

| Workstream | Status | Evidence and next action |
| --- | --- | --- |
| Hardware TCP authentication, bounded reads, replay and local stop isolation | Partial / unverified | Review existing stacked draft PRs; require actual hardware-bridge integration and fail-closed regression suite |
| Ledger crash consistency and finality | Partial / unverified | Distinguish SQLite surrogate and mock-contract assertions from production ledger finality |
| Evidence-gated event admission | Partial | Formal threat model, enrolled colluder and partition counterexamples; require identical held-out incident comparisons |
| Authentic VeReMi NextGen / CAN ingest | Blocked | No independently verified source recordings in this branch; pin publisher, hash and license before use |
| Campaign-held-out descriptive gate | Implemented in draft | SHA-256 input integrity, disjoint campaign splits, unique incident IDs, per-campaign balanced accuracy and equal-campaign paired differences |
| Replay/spoof/DoS and fault experiments | Upcoming | Run independent source-pinned campaigns; synthetic unit fixtures are not effectiveness evidence |
| Latency, CPU/RAM, throughput, multi-seed uncertainty | Upcoming | Measure on declared runtime and cluster independent campaign units; n>=30 does not imply significance |
| Original article numeric claims | Blocked | No publishable performance, superiority or finality claims yet |

Focused command: `python -m unittest discover -s tests -p 'test_heldout_campaign_descriptive_gate.py' -v`

Scope: the new gate is a *descriptive protocol utility*, not an attack detector. It accepts binary alarms, not calibrated continuous scores. Its SHA-256 integrity check is not publisher authenticity. Campaigns lacking both classes are retained but excluded from balanced-accuracy differences; the number of evaluable campaigns is explicit. Exact GitHub checkout full-suite verification remains required before merge.
