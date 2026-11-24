# OmniGuard V2X research status — 2026-11-22

| Workstream | Status | Evidence / gate |
|---|---|---|
| Authenticated TCP/serial ingress, DoS, replay, interlocks | PARTIAL | Open security drafts #194, #200–#202; exact-checkout integration and hardware interlock validation outstanding |
| Durable nonce + event inbox | PARTIAL | Draft #197; production integration and ledger idempotency missing |
| Ledger finality | BLOCKED | Mock contract cannot establish independent consensus finality |
| Evidence-gated V2X admission and safety isolation | PARTIAL | Threat model, formal properties and matched baselines still needed |
| Authentic VeReMi NextGen and CAN provenance | BLOCKED | No verified dataset acquisition and immutable provenance manifest in this change |
| Incident-level paired analysis protocol | IMPLEMENTED, UNVERIFIED | incident_paired_evaluation.py, five regression tests; exact-checkout execution pending |
| Replay/spoofing/malicious enrolled node/false-data/DoS experiments | UPCOMING | Freeze incident splits and run authentic/safe-simulation campaigns |
| CPU/RAM/network/latency/scaling | UPCOMING | Actual runtime instrumented measurements needed |
| Publication-grade results and manuscript | BLOCKED | No defensible main effectiveness result yet |

## Analysis protocol contract

One incident is one independent unit, not one frame. Reject any incident ID spanning train/validation/test. Scores are aggregated by incident max, with pre-frozen threshold (default 0.5 only as placeholder). Both classes required in test. Stratified paired bootstrap samples incidents jointly for both systems and reports a 95% exploratory interval. This is **not** a p-value, proof of statistical significance, or a substitute for campaign/vehicle-level clustering. Do not use n>=30 as a significance rule. Do not select threshold using test data.

Fixture CSVs, three-peer poisoning sanity checks, five-iteration microbenchmarks, and offline communication formulas remain NON-PUBLISHABLE main research evidence.

## Required validation

`python -m unittest discover -s tests -p 'test_incident_paired_evaluation.py' -v`
`python -m unittest discover -s tests -v`

## Next code task

Integrate verified authentic dataset provenance manifests and immutable incident grouping (vehicle/campaign/session) into the evaluation loader, then compare evidence-gated admission against signature-only, plausibility-only, and trust-score baselines using identical frozen splits. No hardware actuation. Review open ingress security drafts before merging.
