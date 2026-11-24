# OmniGuard V2X research status (2026-11-22)

This is a research readiness matrix, not a certification or publication claim.

| Workstream | State | Evidence / blocker |
|---|---|---|
| TCP/serial authenticated ingress | PARTIAL | Main has transport guards; outstanding draft PRs #175–#183 require reconciliation and integration tests |
| Local emergency actuation precedence | BLOCKED | No independent hardware-in-loop evidence; remote actuation must remain disabled |
| SQLite nonce crash recovery | PARTIAL | Crash-boundary tests in draft PRs; power loss and privileged rollback not validated |
| Independent ledger finality | BLOCKED | Mock-contract acknowledgement is not independent consensus finality |
| Evidence-gated V2X event admission | UPCOMING | Formal hypotheses, matched baselines and incident ground truth required |
| Authentic dataset provenance | PARTIAL | This PR checks manifest paths, byte lengths and SHA-256; provenance claims are supplied by operator and not independently attested |
| VeReMi NextGen/CAN genuine ingest | BLOCKED | Authentic files, licenses, label mappings and source checksums not yet verified |
| Replay/spoof/DoS/fault independent evaluation | UPCOMING | Identical incident splits, baseline predictions and multi-seed runs required |
| CPU/RAM/latency/throughput measurements | UPCOMING | Runtime measurement scripts and calibrated environment required |
| Paper numeric claims | BLOCKED | Fixture CSV, 3-peer sanity checks, 5-iteration microbenchmarks and offline formulas are excluded |

## Reproducible local provenance gate

Prepare a manifest with exactly: `dataset`, `source_url`, `license`, `acquired_utc`, `files`.
Each file record must contain exactly `path`, `sha256`, `bytes`, `role`; role is raw, labels or metadata. Paths are relative to the dataset root.

```bash
python -m unittest discover -s tests -p 'test_authentic_dataset_manifest.py' -v
python -m research_contracts.authentic_dataset_manifest --root /path/to/dataset --manifest /path/to/manifest.json
```

The verifier intentionally does not download, redistribute or identify a dataset by filename alone. A valid checksum proves only local byte consistency with the operator-supplied manifest. It does not establish genuine acquisition, ground-truth correctness, independent source attestation or permission to publish.

Next code task: implement independently reviewed acquisition records and parser-specific incident/vehicle/time grouping with leakage-resistant split validation before any effectiveness numbers.
