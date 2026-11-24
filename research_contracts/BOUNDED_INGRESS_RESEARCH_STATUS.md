# Research status matrix — 2026-11-21

| Workstream | Status | Evidence / limitation |
|---|---|---|
| Bounded HMAC-authenticated ingress reference | Locally verified | Eight isolated unittest cases passed on 2026-11-21; exact GitHub checkout untested |
| Durable nonce rejection after restart | Locally verified | SQLite WAL + unique (device, nonce); no SIGKILL durability experiment in this branch |
| Production hardware_bridge integration | BLOCKED | No exact main checkout; no socket receiver or actuation modifications made |
| Local emergency override | BLOCKED | Reference has no actuation capability; physical interlock not validated |
| External anchor/finality | BLOCKED | SQLite is not independent finality |
| VeReMi NextGen and CAN provenance | UPCOMING | Authentic data not ingested |
| Independent multi-seed matched baselines | UPCOMING | No publishable outcome data |
| Formal evidence-gated authorization | PARTIAL | Earlier abstract models; production boundary not established |
| Paper and numerical claim ledger | BLOCKED | No validated real-world effectiveness evidence |

## Reproduction
`python -m unittest discover -s tests -p 'test_bounded_ingress_probe.py' -v`

Local test execution: 8 tests, 0 failures, 0.042 s, isolated file copy. This does not establish exact-checkout integration.

## Critical limitations
This is an evidence-only reference and MUST NOT be connected directly to vehicle actuation. It does not implement bounded socket reads, timeouts, connection quotas, key rotation, independent witness identity, or a physical emergency stop. Timestamp freshness depends on a trusted clock. HMAC proves knowledge of a shared key, not honest sensor measurements. Nonce storage grows without bound; production needs a retention and rollback-resistant replay policy.

Next: inspect exact hardware_bridge source and AGENTS.md if present; add bounded socket reader with deadlines and local emergency priority; test actual network fragmentation, flood and restart behavior before considering integration.
