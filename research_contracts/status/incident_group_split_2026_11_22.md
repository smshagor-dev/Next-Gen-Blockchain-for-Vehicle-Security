# OmniGuard V2X research status — 2026-11-22

This matrix distinguishes source changes, verified evidence, and publication readiness. Draft PRs are **not merged**.

| Workstream | State | Evidence / blocker |
| --- | --- | --- |
| Hardware TCP authentication, bounded framing and local emergency interlocks | Partial | Open security drafts #175–#180; exact-checkout integration and physical verification outstanding |
| Nonce/ledger crash recovery | Partial | Drafts #181–#183; COMMIT-phase and power-loss finality unverified |
| Independent consensus finality | Blocked | Mock contract and local ledger do not establish distributed finality |
| Evidence-gated V2X admission hypothesis and formal safety isolation | Partial | Need comparative threat-model review and model checking |
| Authentic VeReMi NextGen/CAN acquisition | Blocked | No independently verified dataset bytes, incident labels or provenance |
| Dataset byte provenance | Partial | Draft #185 SHA-256 manifest gate; operator metadata not independent attestation |
| Incident-level paired inference | Partial | Draft #184; no authentic paired effectiveness evidence |
| Incident/vehicle/session leakage guard | Implemented, prototype tested | This draft: source-scoped group disjointness; nine standalone local tests passed, exact checkout not run |
| Multi-seed matched baselines, ablations, scaling | Upcoming | Requires independently labelled authentic incidents and frozen splits |
| Publishable numerical claim ledger and manuscript | Blocked | No independent main-effectiveness evidence |

## Split protocol

Require `record_id,source_sha256,incident_id,vehicle_id,session_id,split,label` CSV columns. Each source-file SHA-256 and record identifier must be unique. No incident, vehicle or session within a source file may cross train/validation/test. This intentionally conservative policy may exclude useful samples; report exclusion rates before comparing methods. Output records manifest SHA-256 and class counts.

**Critical limitations:** Group keys are scoped by source SHA-256, so cross-file identity leakage is not detected. This tool does not verify dataset origin, labels, chronological embargo, or that group identifiers correspond to real incidents. Empty class counts are reported, not treated as statistical significance. No dataset was evaluated; fixtures and local tests are NON-PUBLISHABLE effectiveness evidence.

## Reproduce

```bash
python -m unittest discover -s tests -p 'test_incident_split_guard.py' -v
python -m research_contracts.incident_split_guard /path/to/independently_verified_split.csv
```

Next: source-agnostic pseudonymous vehicle/incident linkage across files, temporal embargo and source-acquisition records, then authentic incident experiments with frozen matched splits. Review draft #184/#185 for integration before merging.
