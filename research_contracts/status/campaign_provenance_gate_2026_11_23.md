# Campaign provenance gate status — 2026-11-23

| Workstream | Status | Evidence / blocker |
| --- | --- | --- |
| Recording SHA-256 integrity | Completed (utility only) | Byte hash verification and mismatch rejection |
| Campaign-disjoint train/validation/test | Completed (utility only) | Cross-split campaign ID and identical-byte rejection |
| Negative-control unit tests | Completed locally (standalone prototype) | 8/8 Python unittest tests passed after fixing symlink detection and closing file handles |
| Exact repository checkout suite | Blocked | Not run on full GitHub checkout; review required |
| Authentic VeReMi NextGen / CAN recordings | Blocked | No verified source artifact ingested |
| Hardware ingress, local emergency interlock | Partial | Existing main and outstanding draft security PRs require integration review |
| Ledger crash finality | Partial | SQLite surrogate is not production blockchain finality |
| Independent multi-seed V2X experiments | Upcoming | Require source-pinned independent campaigns, frozen thresholds and matched baselines |
| Paper numerical claims | Blocked | No publication-grade effect sizes or real-world performance measurements |

This manifest verifier is a precondition for data analysis, not proof of a novel mechanism or an experimental result. Source field is declarative, not an external provenance attestation. Threat model includes a malicious curator able to edit paths and files; a curator able to edit both file and digest can bypass bare SHA-256, so external signed release manifests and immutable archives are still required.

Usage: `python -m research_contracts.campaign_provenance MANIFEST.json --root DATA_ROOT`
Focused tests: `python -m unittest discover -s tests -p 'test_campaign_provenance.py' -v`
Full tests: `python -m unittest discover -s tests -v`
