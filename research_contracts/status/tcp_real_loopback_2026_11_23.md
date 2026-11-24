# TCP loopback experiment status — 2026-11-23

| Workstream | Status | Evidence / limitation |
|---|---|---|
| TCP worker admission saturation | PARTIAL | New executable 127.0.0.1 ephemeral-port campaign and focused tests; exact checkout not executed |
| Authenticated Pi TCP ingress | PARTIAL | Existing production MAC/replay code; this campaign does NOT test MACs |
| Local emergency-stop isolation | PARTIAL | Remote ECU dispatch disabled in main; independent hardware interlock not validated |
| Ledger crash consistency and finality | PARTIAL | Existing surrogate controls do not establish production finality |
| Authentic VeReMi NextGen/CAN data | BLOCKED | No verified source-pinned datasets ingested in this change |
| Independent adversarial effectiveness study | UPCOMING | Need matched incident splits, strong baselines, ablations and uncertainty |
| Publication evidence | BLOCKED | Loopback admission timing is engineering characterization, not publishable efficacy |

Run `python -m unittest discover -s tests -p 'test_tcp_loopback_saturation.py' -v` and `python -m research_contracts.tcp_loopback_saturation --peers 16 --slots 2` on exact GitHub checkout. Also run full test suite. This branch intentionally does not merge overlapping draft #207–#209 and does not claim hardware access, significance, or security efficacy.
