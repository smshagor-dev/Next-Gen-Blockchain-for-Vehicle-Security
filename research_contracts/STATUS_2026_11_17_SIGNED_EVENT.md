# Signed event admission checkpoint — 2026-11-17

| Workstream | Status | Evidence or blocker |
| --- | --- | --- |
| Signed event type/size/control validation | Implemented, unverified | hardware_bridge.py uses _signed_event_label before both ledger push paths; commit d2044c8 |
| Regression suite | Committed, not executed | tests/test_signed_event_label.py; commit a78c6e2 |
| Authenticated production ingress | Partial | Durable replay gate not wired into production; current verifier uses process-local replay cache |
| Emergency control isolation | Partial | Remote actuator dispatch disabled; independent local physical stop not verified |
| Ledger crash consistency / mock finality | Partial / blocked | SQLite gate is not distributed consensus; privileged snapshot rollback remains possible |
| Authentic V2X/CAN dataset provenance | Pending | No independently verified dataset ingest or license evidence |
| Independent adversarial baselines and multi-seed statistics | Pending | No publishable incident-level results |
| Manuscript | Blocked | Fixtures, 3-peer sanity check, 5-iteration microbenchmarks and offline formulas are non-publishable primary evidence |

Run: `python -m unittest discover -s tests -p 'test_signed_event_label.py' -v`
Then run full repository suite and authenticated real loopback tests before merging.

Next substantive task: integrate durable replay with explicit provisioning/recovery into production Pi ingress, preserving the network-actuation default deny and independent local emergency controls. Measure authenticated replay/slow-peer behavior against matched baselines. No hardware access or research effectiveness is claimed.

## Follow-up: UTF-8 budget alignment

Implemented: hardware_bridge._signed_event_label now enforces the transport's 160-byte UTF-8 event limit, rather than an inconsistent 128-codepoint limit. This preserves acceptance of valid 129–160 byte ASCII labels and rejects multibyte labels exceeding the wire budget. Regression cases now cover 161 ASCII bytes and 162 UTF-8 bytes. Commits: 844517a, 2d408b0.

Validation: GitHub DNS resolution failed in the execution container; committed tests were not run. Run `python -m unittest discover -s tests -p 'test_signed_event_label.py' -v` and the full suite before merging. Independent safety and publishable adversarial results remain blocked. Next: durable production replay recovery and actual authenticated loopback experiments.
