# Evidence-gated admission research status (2026-11-22)

| Workstream | Status | Evidence / next step |
|---|---|---|
| Reference event admission and signature-only / quorum-only baselines | Completed prototype | Offline model; no network or actuation |
| Adversarial unit tests | Completed locally | 8/8 isolated tests; exact checkout pending |
| Hardware ingress and local emergency control | Partial | Existing security PRs require integration; local stop independent |
| Ledger crash consistency and independent finality | Partial / blocked | No finality evidence |
| Authentic VeReMi NextGen and CAN datasets | Blocked | Authentic acquisition and labels unverified |
| Paired multi-seed effectiveness and runtime experiments | Upcoming | Frozen incident splits and matched baselines |
| Physical actuation validation | Blocked | No physical test; remote authorization always false |
| Publication-ready evidence | Blocked | No authentic effectiveness measurements |

## Falsifiable hypotheses and assumptions
H1: independent-domain corroboration plus evidence and freshness checks reduces incident-level false admission compared with signature-only and domain-quorum-only, with a measurable benign rejection cost. H2: remote actuation authorization is false for all inputs. Assume external domain enrollment, synchronized clocks and honest independent corroborators; malicious independent domains, correlated sensors, compromised clocks and evidence fabrication are not solved. No new cryptographic primitive is claimed.

## Formal model invariants
S1: all decisions have remote_actuation_authorized=False. S2: malformed, duplicate-source, stale, unauthenticated, conflicting and insufficient-domain observations are rejected. S3: local physical emergency stop must never depend on this policy. S4: mock-contract acknowledgements are not independent finality.

## Research protocol and exclusions
Use independently labelled held-out incidents, matched splits, paired cluster bootstrap uncertainty and effect sizes; report false admission, benign rejection, latency, CPU and RAM. Fixture CSVs, 3-peer poisoning sanity check, 5-iteration microbenchmarks, offline communication formulas and these synthetic unit tests are NON-PUBLISHABLE main research results.
