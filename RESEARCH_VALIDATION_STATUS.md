# Research validation status (working branch)

Updated 2026-11-13. This is an evidence gate, not a publication claim.

| Workstream | State | Evidence / limitation |
| --- | --- | --- |
| Authenticated hardware ingress | Partial | Prior draft PR #99 changes require full regression and live loopback validation |
| Safe actuation and local emergency override | Blocked | No independent physical interlock / HIL verification; simulator never actuates |
| Durable nonce admission | Partial | SQLite WAL and crash-boundary test code exists; rollback and real power-loss resistance unverified |
| Challenge-bound simulator receipt | Partial | HMAC receipt code and malformed/oversized-input tests added; execution of current branch tests pending |
| Bounded concurrent TCP sessions / Slowloris | Upcoming | Implement bounded worker/session budget and real loopback fault injection |
| Ledger finality / crash consistency | Partial | Mock finality is not real consensus finality |
| Novel evidence-gated V2X mechanism | Upcoming | Specify falsifiable hypotheses, threat model, safety invariants and strong baselines |
| Authentic VeReMi NextGen and CAN ingest | Upcoming | Require dataset provenance, license, checksums, split leakage checks |
| Independent adversarial experiments | Blocked | No validated multi-seed identical-split baseline comparisons |
| Runtime / statistical study | Blocked | No publishable CPU/RAM/latency scaling or uncertainty/effect-size analysis |
| Manuscript | Blocked | Fixture CSVs, 3-peer sanity check, five-iteration microbenchmarks and offline formulas are non-publishable main evidence |

## Current branch change
Receipt verification rejects non-primitive and oversized attacker-controlled fields before JSON canonicalization. New tests cover nested values and long strings. Commits bde8eb7 and 6a7a7d1. **Tests not executed**: local checkout cannot resolve github.com. No passing result is asserted.

## Next code task
Bound concurrent TCP ingress and write real loopback socket Slowloris/connection-exhaustion fault injection. Keep local emergency control independent of remote admission.
