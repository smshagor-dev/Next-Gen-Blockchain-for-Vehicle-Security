# Evidence-gated V2X research checkpoint — 2026-11-19

This matrix is scoped to the candidate experiment in this branch; it does not replace repository-wide status.

| Area | Status | Evidence / next action |
|---|---|---|
| Synthetic evidence-gate negative controls | Completed locally; repository integration unverified | Seven focused unittest cases passed in isolated container; committed branch full suite pending |
| Authenticated-only vs two-sender evidence-gate comparison | Synthetic only, NON-PUBLISHABLE | Seed 19, 200 incidents, deliberately simplified independent corroborator; no empirical effectiveness inference |
| Local emergency-stop dominance | Unit-level candidate property | No physical hardware integration; must remain local and non-overridable |
| Authenticated malicious enrolled collusion | Blocked | Quorum alone fails if multiple enrolled senders collude; add adversarial scenarios |
| Replay after restart, stale epochs and memory bounds | Partial | In-memory nonce cache only; persisted replay state, expiry, input-size limits absent |
| Hardware TCP ingress / safe actuation | Unverified | Audit actual receiver and implement fail-closed authenticated bounded protocol before any actuation |
| Ledger crash consistency / independent finality | Partial / blocked | Existing draft PRs #154 and related work need exact checkout validation; mock finality is not consensus |
| Authentic VeReMi NextGen / CAN provenance | Blocked | No authenticated source dataset, licensing, independent incident truth or leakage-safe split |
| Independent multi-seed matched-baseline evaluation | Upcoming | Cluster-aware uncertainty and effects; never treat n>=30 as automatic significance |
| Paper | Blocked | Only after authentic independently validated experimental evidence |

Candidate safety properties: (P1) local_stop => remote_authorize=False; (P2) fewer than two distinct authenticated corroborating senders => deny; (P3) repeated (sender,epoch,nonce) cannot increase evidence. These are candidate software properties, NOT verified vehicle safety or a novel cryptographic primitive.

Commands:
```sh
python -m unittest discover -s tests -p 'test_evidence_gate_experiment.py' -v
python -m research_contracts.evidence_gate_experiment --seed 19 --incidents 200
```

Local isolated run: 7/7 passed; synthetic counts authenticated_only tp=110 fp=19 tn=71 fn=0; evidence_gate tp=110 fp=0 tn=90 fn=0. The synthetic generator structurally favors the gate: DO NOT present these numbers as research effectiveness, measured network performance, or safety assurance. Full repository suite and branch checkout were not run.

Next: add malicious corroborator collusion, delayed/out-of-order and network-partition cases, plus identical incident trace baselines. Then integrate verified receiver-side safe actuation separately.
