# Federated Learning Result Aggregation

This runner computes grouped statistics only from provided FL experiment CSV logs. It does not fabricate FL results.

## Input Schema

- `seed`
- `peer_count`
- `byzantine_fraction`
- `attack_type`
- `accuracy`
- `precision`
- `recall`
- `f1`
- `attack_success_rate`
- `aggregation_latency_ms`

## Statistic Definitions

- `count`: number of CSV rows in the group.
- `mean`: arithmetic mean for each metric.
- `std`: sample standard deviation for each metric; `0` for single-row groups.
- `min` / `max`: observed metric bounds within the group.
- `statistical_significance`: `true` only when group `count >= 30`.

## Summary

- `experiment`: `federated_learning`
- `status`: `computed_from_fl_csv`
- `created_at`: `2026-06-05T14:25:03.386725+00:00`
- `input_csv`: `experiments\reports\fl_fixture_smoke\fixture.csv`
- `input_rows`: `2`
- `group_by`: `attack_type,peer_count,byzantine_fraction`
- `metrics`: `accuracy,precision,recall,f1,attack_success_rate,aggregation_latency_ms`
- `dataset_required`: `False`
- `seed`: `0`

## Results

| group_by | attack_type | peer_count | byzantine_fraction | count | statistical_significance | dataset_required | accuracy_mean | accuracy_std | accuracy_min | accuracy_max | precision_mean | precision_std | precision_min | precision_max | recall_mean | recall_std | recall_min | recall_max | f1_mean | f1_std | f1_min | f1_max | attack_success_rate_mean | attack_success_rate_std | attack_success_rate_min | attack_success_rate_max | aggregation_latency_ms_mean | aggregation_latency_ms_std | aggregation_latency_ms_min | aggregation_latency_ms_max |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| attack_type,peer_count,byzantine_fraction | sign-flip | 10 | 0.1 | 2 | False | False | 0.7 | 0.141421 | 0.6 | 0.8 | 0.6 | 0.141421 | 0.5 | 0.7 | 0.5 | 0.141421 | 0.4 | 0.6 | 0.55 | 0.141421 | 0.45 | 0.65 | 0.3 | 0.141421 | 0.2 | 0.4 | 14.0 | 2.828427 | 12.0 | 16.0 |
