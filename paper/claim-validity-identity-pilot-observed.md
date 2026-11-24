# Observed identity admission pilot — 2026-11-24

Run: https://github.com/smshagor-dev/Next-Gen-Blockchain-for-Vehicle-Security/actions/runs/45391371875
Head: a9b3cd8bca6f21acc9bb69ea6cd849a5d3bceeac
Artifact: https://github.com/smshagor-dev/Next-Gen-Blockchain-for-Vehicle-Security/actions/runs/45391371875/artifacts/14919615475
CI-reported ZIP SHA256: 629b5d99178fe88da591034b8164ef4a30610b17865da8d2d2e1af58cc0e1dd6.

Six focused controls passed after the severity-expectation correction.
CI logs report the following totals; archive bytes have not been
independently downloaded/recomputed in this session.

| Configuration | ACK / 16 | Unlisted accepted / 16 | STRONG with observed alerts / 16 |
|---|---:|---:|---:|
| registry_strict | 4 | 0 | 4 |
| registry_with_compatibility | 4 | 0 | 4 |
| unconfigured_deny | 0 | 0 | 0 |
| global_lab | 4 | 4 | 4 |
| registry_declared_open | 4 | 0 | 4 |
| global_declared_deny | 4 | 4 | 4 |
| Total | 20 | 8 | 20 |

All 96 constructed connected, alert-free wrappers yielded STRONG.
With observed alerts 20 yielded STRONG. Global compatibility deliberately
enabled without enrollment accepted four unlisted identities per applicable
configuration, including the inconsistent DENY_UNCONFIGURED declaration.
This is a controlled local handler result with deliberately constructed
configuration, not a production remote bypass or human-use finding.
No socket or physical test and no inferential statistics claimed.
