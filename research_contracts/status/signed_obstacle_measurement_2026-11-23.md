# OmniGuard V2X research status — 2026-11-23

| Workstream | Status | Evidence / next gate |
|---|---|---|
| Signed obstacle measurement omission | Implemented, unverified | Explicit obstacle_distance now mandatory; 4 focused regression methods; exact-checkout execution pending |
| Authenticated TCP and bounded admission | Partial | Existing draft PRs #207–#212 require overlap review and integrated regression |
| Local emergency-stop independence | Partial | Remote actuator paths disabled; physical receiver and interlock validation unavailable |
| Ledger crash consistency and mock finality | Partial | Durable atomicity and independent finality evidence pending |
| Evidence-gated V2X event admission | Partial | Formal properties, threat model and strong baseline comparisons pending |
| Authentic VeReMi NextGen and CAN datasets | Blocked | Source-pinned acquisition, provenance, independent campaign splits pending |
| Independent adversarial experiments | Upcoming | Replay, spoofing, malicious enrolled node, false data, DoS, faults |
| Multi-seed runtime and statistical validation | Upcoming | Paired cluster effects, confidence intervals, CPU/RAM/latency/throughput |
| Original research article | Not ready | No publishable effectiveness evidence yet |

Fixtures, three-peer poisoning sanity checks, five-iteration microbenchmarks, and offline communication formulas are excluded from main publication claims.

## Reproduction gate

`python -m unittest discover -s tests -p 'test_signed_obstacle_measurement.py' -v`

`python -m unittest discover -s tests -v`

Tests have not been executed on this exact GitHub checkout. Do not merge until verified. This change prevents one unsafe missing-value interpretation but does not establish physically safe actuation or authentic dataset performance.
