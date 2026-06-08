# Adversarial Validation Limitations

OmniGuard V2X currently reports adversarial validation as single-run adversarial sanity checks. These are prototype attack-trigger validation runs, not evidence for a general detection-rate claim.

## Current Validation Metadata

```json
{
  "adversarial_validation_level": "single_run_sanity_check",
  "supports_general_detection_claim": false,
  "detection_rate_headline_allowed": false,
  "attack_trials_per_type": 1,
  "statistical_significance": false,
  "known_trivial_triggers": ["350_kmh_speed", "100x_fl_weight_delta"]
}
```

## Why Single Trial Is Insufficient

A single trial per attack type cannot estimate detection reliability, false positive rate, false negative rate, or variance across random seeds and operating conditions. It can only show that a specific trigger path fired once.

## Why 350 km/h Speed Is Trivial

A 350 km/h speed value is far outside normal smart-car telemetry ranges. Rule-based anomaly checks should flag it by construction. Detecting that value does not prove performance against realistic sensor drift, GPS jitter, CAN spoofing near legal limits, or stealthy gradual changes.

## Why 100x Weight Delta Is Trivial

A 100x federated-learning weight delta is an extreme outlier. Norm gates and MAD-style filters are expected to catch it. That does not prove robustness against low-magnitude poisoning, adaptive sign-flip attacks, label-flip attacks, backdoors, or random updates crafted to remain inside clipping thresholds.

## Required Future Protocol

Future adversarial validation should include:

- Multi-seed randomized trials.
- Realistic speed, acceleration, brake, GPS, and sensor-noise ranges.
- Stealthy attacks that avoid obvious threshold violations.
- False positive and false negative rates.
- Precision, recall, and F1.
- ROC/AUC where applicable.
- Confidence intervals for all reported aggregate metrics.
- Reproducible logs and dataset/model versions for any published table.

Until that protocol is complete, use only the wording `limited attack-trigger demonstration` or `single-run adversarial sanity checks`.
