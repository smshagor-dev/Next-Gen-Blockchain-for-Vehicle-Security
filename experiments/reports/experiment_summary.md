# OmniGuard V2X Experiment Summary

This summary is generated only from available experiment JSON artifacts. It does not infer, impute, or fabricate missing metrics.

## Summary

- `latency_results.json`: found at `experiments\reports\latency_profile_smoke\latency_results.json` with status `measured_local_components`
- `scalability_results.json`: found at `experiments\reports\scalability_smoke_committee\scalability_results.json` with status `communication_volume_analysis_only`
- `adversarial_results.json`: found at `experiments\reports\adversarial_fixture_smoke\out\adversarial_results.json` with status `computed_from_labeled_csv`
- `fl_results.json`: found at `experiments\reports\fl_fixture_smoke\out\fl_results.json` with status `computed_from_fl_csv`

## Latency Benchmarks

- Source: `experiments\reports\latency_profile_smoke\latency_results.json`
- `status`: `measured_local_components`

| row | numeric metrics found |
| --- | --- |
| security_capabilities | `cold_start_ms=0.0016`, `iterations=5`, `max_ms=0.0006`, `mean_ms=0.0004`, `measured_iterations=5`, `min_ms=0.0003`, `seed=7`, `std_ms=0.000126`, `warm_start_p50_ms=0.0003`, `warm_start_p95_ms=0.00058`, `warm_start_p99_ms=0.000596`, `warmup=1` |
| identity_security | `cold_start_ms=0.01`, `iterations=5`, `max_ms=0.0031`, `mean_ms=0.0021`, `measured_iterations=5`, `min_ms=0.0017`, `seed=7`, `std_ms=0.000518`, `warm_start_p50_ms=0.0018`, `warm_start_p95_ms=0.0029`, `warm_start_p99_ms=0.00306`, `warmup=1` |
| consensus_security | `cold_start_ms=0.0011`, `iterations=5`, `max_ms=0.0004`, `mean_ms=0.00028`, `measured_iterations=5`, `min_ms=0.0002`, `seed=7`, `std_ms=7.5e-05`, `warm_start_p50_ms=0.0003`, `warm_start_p95_ms=0.00038`, `warm_start_p99_ms=0.000396`, `warmup=1` |
| pedersen_privacy | `cold_start_ms=0.001`, `iterations=5`, `max_ms=0.0003`, `mean_ms=0.00018`, `measured_iterations=5`, `min_ms=0.0001`, `seed=7`, `std_ms=7.5e-05`, `warm_start_p50_ms=0.0002`, `warm_start_p95_ms=0.00028`, `warm_start_p99_ms=0.000296`, `warmup=1` |
| reviewer_audit | `cold_start_ms=0.0011`, `iterations=5`, `max_ms=0.0002`, `mean_ms=0.0002`, `measured_iterations=5`, `min_ms=0.0002`, `seed=7`, `std_ms=0.0`, `warm_start_p50_ms=0.0002`, `warm_start_p95_ms=0.0002`, `warm_start_p99_ms=0.0002`, `warmup=1` |
| blockchain_append_validate | `cold_start_ms=297.9069`, `iterations=5`, `max_ms=1067.377`, `mean_ms=814.26474`, `measured_iterations=5`, `min_ms=564.2093`, `seed=7`, `std_ms=177.445299`, `warm_start_p50_ms=804.7759`, `warm_start_p95_ms=1042.18884`, `warm_start_p99_ms=1062.339368`, `warmup=1` |
| ... | 1 additional rows omitted from summary |

## Scalability Communication Analysis

- Source: `experiments\reports\scalability_smoke_committee\scalability_results.json`
- `status`: `communication_volume_analysis_only`
- Runtime benchmark: no. Treat this as analysis/simulation or offline metric aggregation only.

| row | numeric metrics found |
| --- | --- |
| committee | `active_validators=10`, `average_messages_per_node=1.8`, `committee_size=10`, `fanout=8`, `messages_per_round=90`, `node_count=100`, `rounds=2`, `seed=0`, `total_messages=180` |

## Adversarial Detection Evaluation

- Source: `experiments\reports\adversarial_fixture_smoke\out\adversarial_results.json`
- `status`: `computed_from_labeled_csv`
- Runtime benchmark: no. Treat this as analysis/simulation or offline metric aggregation only.
- Statistical significance: false.

| row | numeric metrics found |
| --- | --- |
| overall | `accuracy=0.5`, `f1=0.5`, `false_negative_rate=0.5`, `false_positive_rate=0.5`, `fn=1`, `fp=1`, `precision=0.5`, `recall=0.5`, `sample_count=4`, `specificity=0.5`, `tn=1`, `tp=1` |
| per_attack_type | `accuracy=0.5`, `f1=0.0`, `false_negative_rate=0.0`, `false_positive_rate=0.5`, `fn=0`, `fp=1`, `precision=0.0`, `recall=0.0`, `sample_count=2`, `specificity=0.5`, `tn=1`, `tp=0` |
| per_attack_type | `accuracy=0.5`, `f1=0.666667`, `false_negative_rate=0.5`, `false_positive_rate=0.0`, `fn=1`, `fp=0`, `precision=1.0`, `recall=0.5`, `sample_count=2`, `specificity=0.0`, `tn=0`, `tp=1` |

## Federated Learning Evaluation

- Source: `experiments\reports\fl_fixture_smoke\out\fl_results.json`
- `status`: `computed_from_fl_csv`

| row | numeric metrics found |
| --- | --- |
| sign-flip | `accuracy_max=0.8`, `accuracy_mean=0.7`, `accuracy_min=0.6`, `accuracy_std=0.141421`, `aggregation_latency_ms_max=16.0`, `aggregation_latency_ms_mean=14.0`, `aggregation_latency_ms_min=12.0`, `aggregation_latency_ms_std=2.828427`, `attack_success_rate_max=0.4`, `attack_success_rate_mean=0.3`, `attack_success_rate_min=0.2`, `attack_success_rate_std=0.141421`, `byzantine_fraction=0.1`, `count=2`, `f1_max=0.65`, `f1_mean=0.55`, `f1_min=0.45`, `f1_std=0.141421`, `peer_count=10`, `precision_max=0.7`, `precision_mean=0.6`, `precision_min=0.5`, `precision_std=0.141421`, `recall_max=0.6`, `recall_mean=0.5`, `recall_min=0.4`, `recall_std=0.141421` |

## Missing Results / TODOs

- No missing result files detected by the aggregator. Review claim-safety notes before citing results.

## Claim Safety Notes

- Do not claim full PQ security.
- Do not claim Sybil resistance under open registration.
- Do not claim 51% attack resistance.
- Do not claim 100% detection.
- Do not claim statistically significant FL/adversarial results unless count/repeated runs support it.
- Do not claim measured scalability from communication simulation.
