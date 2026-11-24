# Research status — 2026-11-19

| Workstream | State | Evidence / limitation |
|---|---|---|
| Hardware ingress authentication, bounded receive, replay and safe interlocks | Partial / physical validation blocked | Never enable actuation; local emergency control must remain independent |
| Ledger crash consistency and independent finality | Partial | Draft #154 checkpoint hardening is not proof of distributed finality |
| Evidence-gated V2X incident admission | Partial | Threat-model simulations are not independently annotated world-state evidence |
| Genuine VeReMi/CAN source ingest | Partial | CAM attacker labels are not incident truth; CAN physical provenance not established |
| Independent adversarial trials and matched baselines | Blocked | Requires trustworthy incident world-state and authenticated capture |
| Paired incident-level uncertainty control | Implemented, exact checkout unverified | `experiments/v2x/paired_incident_uncertainty.py`; descriptive stratified bootstrap, no p-value; correlated incidents across scenario may invalidate interval |
| Network and resource scaling | Upcoming | Need measured independent runs |
| Manuscript | Blocked | No defensible publication-ready incident-level effectiveness results |

## This change

Add strict CSV incident universe validation, duplicate rejection, source SHA256,
paired balanced-accuracy difference and reproducible class-stratified bootstrap
interval. Four synthetic contract tests check identical methods, deterministic
improvement, single-class support and duplicate/extra-field rejection.

Run: `python -m unittest discover -s tests -p 'test_paired_incident_uncertainty.py' -v`

No manuscript result is inferred from these synthetic tests. Source observations
must be independently authenticated and world-state labeled before use.
The bootstrap does not establish statistical significance, and clustered
scenario dependence must be modeled before scientific inference.

Next: validate exact checkout, then implement scenario-clustered uncertainty
and test against independently sourced incident world truth with matched
baseline decisions. Existing fixture CSVs, 3-peer sanity checks,
5-iteration microbenchmarks and offline communication formulas are non-publishable.
