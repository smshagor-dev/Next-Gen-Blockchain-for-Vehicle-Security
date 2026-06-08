# FL Validation Limitations

OmniGuard V2X currently treats its federated-learning poisoning run as a prototype-level FL poisoning detection sanity check. It is a limited three-peer demonstration, not statistically sufficient for Byzantine-robustness claims.

## Current Validation Metadata

```json
{
  "fl_validation_level": "prototype_sanity_check",
  "num_peers": 3,
  "samples_per_peer": 10,
  "test_samples": 24,
  "byzantine_peers": 1,
  "attack_type": "100x_weight_delta",
  "statistical_significance": false,
  "supports_byzantine_robustness_claim": false
}
```

## Why The Current Run Is Insufficient

The current setup uses only three peers, ten samples per peer, one Byzantine peer, and a 24-sample test set. That scale is useful for verifying that code paths execute, that obvious update outliers can be rejected, and that metadata is reported. It is too small to estimate fleet behavior, adversarial robustness, or realistic model performance.

A 24-sample test set has high variance. One changed prediction moves accuracy by more than four percentage points, so a single-trial accuracy number should not be treated as reliable evidence. Repeated trials with confidence intervals are required before reporting performance as a research result.

## Why 100x Scaling Is Trivial

A 100x weight-delta attack creates an extreme norm outlier. Norm gates and MAD-style filters are expected to flag this kind of update because it is far outside the benign update distribution. Passing this test does not show robustness against stealthier attacks such as sign-flip, label-flip, low-magnitude backdoors, adaptive scaling, or random updates crafted to remain inside clipping thresholds.

## Why Krum Needs Meaningful Peer Counts

Krum-style Byzantine aggregation relies on enough honest peers to compare update distances meaningfully. With three peers and one Byzantine peer, there is not enough population diversity to evaluate neighborhood scoring, honest-majority behavior, or attacker collusion. Future Krum or MAD-Krum experiments should include larger peer counts such as 5, 10, 20, and 50 peers across multiple Byzantine fractions.

## Why Single-Trial Accuracy Is Not Valid

Single-trial accuracy cannot separate real model behavior from sampling luck, seed effects, or dataset ordering. A valid report should include accuracy mean and standard deviation, detection precision/recall/F1, attack success rate, aggregation latency, and a confidence interval across repeated seeds. The default future protocol should use at least 30 seeds.

## Required Future Validation Protocol

Future validation should use:

- Peer counts: 3, 5, 10, 20, and 50.
- Byzantine fractions: 0%, 10%, 20%, and 30%.
- Attack types: sign-flip, label-flip, Gaussian noise, scaling attack, backdoor trigger, and random update.
- Repeated trials: default 30 seeds.
- Metrics: accuracy mean/std, attack success rate, detection precision/recall/F1, aggregation latency, and 95% confidence interval.
- Real dataset/model integration before publishing any new benchmark table.

Until that protocol is executed, the project should state only that it has a small-scale FL sanity check and prototype-level FL poisoning detection.
