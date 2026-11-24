# Admission fairness sensitivity status — 2026-11-23

| Workstream | State | Evidence / next gate |
|---|---|---|
| Global admission-budget synthetic fairness model | Completed implementation; execution unverified | Seeded request-order simulator, global/per-identity/unlimited controls |
| Synthetic negative controls | Implemented; exact-checkout unverified | Seven unittest methods in tests/test_ingress_budget_adversarial_sensitivity.py |
| Actual authenticated TCP adversarial traffic | Upcoming | Integrate real loopback handler, MAC and replay checks, measure per-device denial |
| Local emergency-stop isolation | Partial | Existing fail-closed remote actuation requires independent hardware validation |
| Ledger crash consistency/finality | Partial | Do not equate SQLite surrogate or mock contract with finality |
| Authentic VeReMi NextGen/CAN evidence | Blocked | Source-pinned original recordings and provenance needed |
| Multi-seed independent experiments | Upcoming | Frozen splits, strong baselines, cluster uncertainty, effect sizes |
| Publication-grade effectiveness claims | Blocked | No authentic experiments or physical safety evidence |

This is a deterministic synthetic *admission policy* model, not a production
TCP benchmark, MAC experiment, Sybil defense, or original-research result.
The unlimited policy intentionally violates capacity and is only a negative
control. The per-identity policy assumes trustworthy unique identities and
does not establish fairness under stolen/enrolled colluding identities.

Run after checkout:
```sh
python -m unittest discover -s tests -p 'test_ingress_budget_adversarial_sensitivity.py' -v
python -m research_contracts.ingress_budget_adversarial_sensitivity --seeds 20 --adversaries 3 --output admission_sensitivity.csv
python -m unittest discover -s tests -v
```
No tests claimed passing until executed on the exact branch checkout.
