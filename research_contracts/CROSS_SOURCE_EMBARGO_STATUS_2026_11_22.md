# Cross-source and chronological evaluation preflight — 2026-11-22

Base: main e35f94e. Related drafts: #184 paired incident statistics, #185 byte provenance, #186 source-scoped split guard. This draft adds a separate, stricter cross-file check and does not replace those drafts.

| Workstream | State | Evidence / next action |
| --- | --- | --- |
| Cross-file incident/vehicle/session identity disjointness | Implemented, local isolated verification | 11 unittest cases; exact checkout still pending |
| Chronological train/validation/test ordering and strict embargo | Implemented, local isolated verification | Rejects overlap, reversed order, nonfinite times and equality at embargo |
| Manifest digest and duplicate source record checks | Implemented | SHA-256 of raw manifest; no authenticity guarantee |
| Hardware ingress and local emergency isolation | Partial | Reconcile open ingress PRs; physical safety blocked |
| Ledger crash consistency and finality | Partial / blocked | SIGKILL and durable inbox drafts; no independent finality |
| Authentic VeReMi NextGen and CAN acquisition / parser | Blocked | Require original source, license, independently checked labels and identities |
| Strong matched baselines, multi-seed attacks and ablations | Upcoming | Freeze source and incident splits before model selection |
| Network/CPU/RAM/latency scaling | Upcoming | Run measured execution, not offline formula |
| Publishable evidence | Blocked | No authentic incident-level performance evidence yet |

## Reproduction
`python -m unittest discover -s tests -p 'test_cross_source_embargo.py' -v`
`python -m research_contracts.cross_source_embargo manifest.csv --embargo-seconds 10`

Local isolated copy: 11 tests passed, 0 failures in 0.011s. The exact GitHub checkout and full suite were not run: git clone DNS resolution failed. No paper metrics or hardware claims.

## Scope and threats
A source-specific incident ID can recur in different files or represent the same real incident. The input therefore requires globally linked incident, vehicle and session identities. The validator cannot infer that linkage, prove ground-truth labels or detect inaccurate clocks. Strict global vehicle disjointness may make a temporal split impossible on small datasets; do not silently relax it to obtain a result. All timestamps must use the same declared clock basis. A holdout is accepted only if the entire earlier split ends more than the configured embargo before the later split begins.

Next code task: implement dataset-specific verified import with explicit clock provenance, source manifests and cross-file identity mapping; then evaluate independent attack incidents with frozen matched splits. Keep this PR draft until exact checkout validation and reconciliation with #186.
