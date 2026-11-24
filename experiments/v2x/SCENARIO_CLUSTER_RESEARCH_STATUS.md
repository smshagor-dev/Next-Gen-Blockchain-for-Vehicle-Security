# Scenario-clustered V2X evidence status — 2026-11-19

| Workstream | Status | Evidence / blocker |
|---|---|---|
| Authenticated hardware ingress and safety-isolated emergency control | Partial / physical validation blocked | No hardware safety claims; local emergency override must remain independent |
| Crash-consistent ledger and independently verified finality | Partial / finality blocked | Draft #154 and related surrogate experiments are not consensus evidence |
| Evidence-gated V2X admission mechanism | Partial | No independently validated incident-level effectiveness |
| Authentic VeReMi NextGen / CAN provenance | Partial | Dataset attack labels cannot be silently treated as physical incident truth |
| Matched baseline incident decisions | Blocked | Requires independently annotated common incident universe and identical splits |
| Incident-level stratified bootstrap | Implemented / exact branch verification pending | Existing PR #155 method ignores scenario correlation |
| Scenario-clustered paired bootstrap | Implemented / isolated 5 tests passed; exact checkout pending | Whole-scenario resampling; missing-class bootstrap draws fail closed |
| Independent scenario support | Blocked | Independent scenario sampling and enough class-diverse clusters required |
| Publishable scientific effectiveness | Not ready | No physical experiments, credible multi-seed matched comparisons, or validated uncertainty yet |

Validation command: `python -m unittest discover -s tests -p 'test_scenario_cluster_bootstrap.py' -v`.

Isolated copy of the module and five tests passed locally on 2026-11-19. Exact GitHub branch checkout and repository-wide suite were not executed. The CI/checkout outcome must not be inferred from the isolated test run. The method reports descriptive uncertainty only; no n>=30 significance shortcut, no p-value, no hardware actuation.

Next: integrate the cluster method into the incident CSV CLI, retain source SHA-256 and paired scenario identity, run exact checkout tests, and build authenticated incident-ground-truth provenance before effectiveness claims.
