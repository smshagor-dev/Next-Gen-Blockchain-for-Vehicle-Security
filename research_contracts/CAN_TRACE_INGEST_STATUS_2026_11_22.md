# Research status matrix — 2026-11-22

Base main: e35f94e. Draft PRs #184–#187 already cover incident statistics, manifest provenance, split leakage, and temporal embargo; this branch only adds a strict **classic SocketCAN candump** parser. No hardware access, dataset acquisition, independent labels, or vehicle control.

| Workstream | Status | Evidence / blocker |
| --- | --- | --- |
| Classic SocketCAN candump offline parser | Implemented; isolated local verification | 8 unittest cases passed against equivalent local source; exact GitHub checkout pending |
| Input digest, time ordering, CAN ID/DLC validation | Implemented | SHA-256, integer nanosecond timestamps, bounded source size; not origin authentication |
| CAN FD and alternate log formats | Blocked | Explicitly rejected pending documented source-specific parser |
| Authentic VeReMi NextGen and CAN labelled data | Blocked | No verified acquisition, license, labels or clock calibration |
| Cross-file identity/temporal splits | Partial | Drafts #186/#187, integration not verified |
| Hardware ingress and local emergency isolation | Partial | Review #176–#183 and run integration; physical interlock not validated |
| Ledger crash consistency and independent finality | Partial / blocked | Drafts #181/#183; mock finality not consensus evidence |
| Matched incident baselines, attacks, ablations | Upcoming | Freeze independently verified splits first |
| Runtime network/CPU/RAM/latency scaling | Upcoming | Need real measurements, not formulas |
| Publication-ready scientific effectiveness | Blocked | No authentic incident-level evidence |

## Reproduce
`python -m unittest discover -s tests -p 'test_can_trace_ingest.py' -v`
`python -m research_contracts.can_trace_ingest path/to/trace.log > trace.json`

The 8 isolated tests passed locally in 0.009 seconds. Exact GitHub checkout remains untested due to container DNS failure. Test fixtures are not publishable scientific results.

## Limitations
The parser accepts only `(timestamp) interface ID#DATA` classic CAN records, rejects CAN FD, and does not infer attacks. Source SHA-256 verifies local bytes only; timestamps, vehicle/session identity, sensor labels, and source authenticity remain unverified. The input size limit does not establish streaming memory bounds; emitted records are accumulated in RAM. Source file replacement during reading is not fully prevented; immutable source snapshot and fd-based digest/size verification are next. No physical commands are emitted.

Next code task: implement immutable snapshot reading and bounded streaming output; then obtain authentic source-specific CAN/V2X data with licensing, clock and label provenance and connect to frozen incident-level baselines.
