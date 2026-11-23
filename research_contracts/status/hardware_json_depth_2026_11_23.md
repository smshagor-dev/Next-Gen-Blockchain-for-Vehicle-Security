# Hardware JSON depth failure controls — 2026-11-23

| Workstream | Status | Evidence / limitation |
|---|---|---|
| Parser RecursionError normalization | Implemented, unverified | `hardware_transport_security._strict_json_loads` maps recursion exhaustion to `HW_JSON_MALFORMED` |
| Canonical serializer exhaustion normalization | Implemented, unverified | `_canonical_bytes` maps recursion/overflow to `HW_CANONICAL_ENCODING_INVALID` |
| Five deterministic negative/positive controls | Written, not executed | `tests/test_hardware_json_depth_fail_closed.py` |
| Exact-checkout test execution | Blocked | Container `git ls-remote` failed: Could not resolve host github.com |
| Authenticated TCP + local emergency safety | Partial | No hardware tests; physical local emergency control must remain independent |
| Ledger crash consistency | Partial | No new ledger experiment this change |
| Authentic VeReMi NextGen and CAN provenance | Blocked | No authentic data acquired/validated |
| Independent multi-seed original research evidence | Upcoming | No publication-grade effectiveness claims |

Next: execute focused and full tests on an exact checkout; integrate with open ingress drafts #207–#216; add authenticated loopback malformed-frame and replay campaigns, then ledger crash-injection experiments. Existing fixtures, 3-peer poisoning and microbenchmarks are not main-paper evidence.
