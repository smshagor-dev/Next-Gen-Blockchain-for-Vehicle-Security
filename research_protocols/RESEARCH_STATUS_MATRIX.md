# OmniGuard V2X research status matrix (2026-11-22)

| Workstream | Status | Evidence / next action |
| --- | --- | --- |
| Authenticated TCP/serial ingress and bounded resources | PARTIAL | Draft PRs #172–#180 require integration and exact-checkout verification |
| Local emergency-control precedence | BLOCKED | Physical actuation and emergency-stop validation unavailable; do not claim certification |
| Durable nonce / mid-transaction crash handling | PARTIAL | Draft PRs #181–#183; COMMIT-phase and restart experiments outstanding |
| Ledger finality | BLOCKED | Mock contract does not establish independent consensus finality |
| Distinguishable evidence-gated admission mechanism | UPCOMING | Formalize safety invariants, attacker capabilities, matched baselines and ablations |
| Authentic VeReMi NextGen and CAN datasets | BLOCKED | Acquire verified original archives, hashes, licenses, and independent incident labels |
| Incident-level paired statistical evaluator | PARTIAL | This branch adds input validation, incident-cluster bootstrap, seed and SHA-256 provenance; no authentic dataset run yet |
| Real latency/CPU/RAM/throughput measurements | UPCOMING | Run identical workloads and collect raw traces on specified hardware |
| Publishable independent effectiveness evidence | BLOCKED | Existing fixture CSVs, three-peer sanity checks, five-iteration microbenchmarks and offline formulas excluded |

## Evaluation protocol

Input CSV columns: `incident_id,truth,baseline,candidate`; truth=1 means attack-positive. Candidate and baseline must be generated using identical held-out incidents and a pre-registered decision threshold. One incident can contain many rows, but its truth must be consistent. Bootstrap resamples *incidents* (not packets) with replacement, preserving pairing; report TPR/FPR differences and 95% percentile intervals, seed, source SHA-256 and valid replicate counts. A missing class produces an undefined metric rather than a fabricated zero. Bootstrap intervals alone do not establish statistical significance; n>=30 is not a significance rule.

No original VeReMi/CAN data is bundled or implied. Synthetic regression fixtures are NON-PUBLISHABLE. Never present this evaluator as a demonstrated safety benefit without independent labeled experiments.

Run: `python -m unittest discover -s tests -p 'test_paired_incident_evaluation.py' -v`.
Run evaluator: `python -m research_protocols.paired_incident_evaluation incidents.csv --output results.json --seed 17 --repetitions 2000`.
