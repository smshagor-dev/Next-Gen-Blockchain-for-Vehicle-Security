# Adversarial evidence-gate research checkpoint — 2026-11-19

| Workstream | Status | Evidence / limitation |
|---|---|---|
| Enrolled two-node collusion | Implemented synthetic counterexample | Both authenticated colluders falsely corroborate; quorum admits false event |
| Network partition | Implemented synthetic counterexample | True event with only one reachable sender is denied |
| Replay / local emergency stop | Implemented synthetic regression | Replay cannot become second sender; local stop blocks remote admission |
| Hardware TCP ingress/interlocks | Partial, unverified | No physical actuation or production receiver proof |
| Ledger durable inclusion / independent finality | Partial / blocked | Mock and SQLite controls are not consensus |
| Authentic VeReMi NextGen and CAN cohorts | Blocked | No independently sourced raw data, pinned hashes or world truth |
| Matched multi-seed effectiveness and performance | Upcoming | Current traces are constructed logical counterexamples, not independent trials |
| Scientific paper | Blocked | No publishable efficacy or safety measurements |

Run `python -m unittest discover -s tests -p 'test_evidence_gate_adversarial_controls.py' -v` and `python -m research_contracts.evidence_gate_adversarial_controls`.

Candidate falsifiable hypotheses: H1 quorum reduces single-enrolled-sender false admission under non-collusion; H2 quorum worsens detection availability when independent witnesses are unreachable; H3 two enrolled colluders defeat simple sender-count quorum. This script demonstrates logical possibilities, **not measured frequencies**. Next: authenticated timestamp/epoch constraints and non-actuating identical-trace baseline with real incident provenance, then full checkout tests.
