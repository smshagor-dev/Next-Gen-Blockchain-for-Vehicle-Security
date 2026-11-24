# V2X original research status — 2026-11-22

| Workstream | Status | Evidence / next action |
|---|---|---|
| Authenticated TCP/serial admission and local emergency interlocks | Partial | Multiple unmerged security drafts; exact-checkout integration and physical safety verification required |
| Durable nonce and ledger crash consistency | Partial | SQLite surrogate counterexamples are not production Go ledger finality |
| Evidence-gated admission threat model and formal safety | Partial | Candidate negative controls exist; prove isolation and evaluate colluding enrolled nodes |
| Genuine VeReMi NextGen and CAN provenance | Blocked | Verify original source hashes, licenses, recording/campaign IDs and split independence |
| Independent replay/spoof/DoS experiments | Upcoming | Frozen baselines, independent incident truth, same splits |
| Cluster-level paired statistical inference | Implemented locally; repository verification pending | `research_contracts/cluster_signflip.py`; six isolated tests passed in local prototype; GitHub checkout suite not run |
| Runtime and scaling experiments | Upcoming | Actual network CPU/RAM/latency traces and multi-seed uncertainty |
| Original research article | Blocked | No publishable primary effectiveness results yet |

## Protocol guardrails

- A cluster is a recording, vehicle/campaign, or higher-level independent unit established before outcome inspection; do not equate individual CAN frames with independent samples.
- Scores and comparison baselines must be pre-specified, bounded [0,1], paired on the same incident IDs and audited for split leakage before using this utility.
- Two-sided sign-flip p-values assume exchangeable signs under the sharp null; they do not establish causality or generalize automatically to observational datasets.
- Exact enumeration up to 16 clusters; above this, seeded Monte Carlo with plus-one correction. No blanket rule that n >= 30 implies significance.
- Synthetic tests are regression controls only, not research outcomes.
- Next: exact-checkout suite, add source-provenance and campaign-level split adapter, run actual independent held-out paired trials.
