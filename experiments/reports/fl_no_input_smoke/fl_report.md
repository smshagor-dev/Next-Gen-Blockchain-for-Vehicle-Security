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
- `status`: `dataset_required`
- `created_at`: `2026-06-05T14:25:03.371050+00:00`
- `input_csv`: ``
- `input_rows`: `0`
- `group_by`: `attack_type,peer_count,byzantine_fraction`
- `metrics`: `accuracy,precision,recall,f1,attack_success_rate,aggregation_latency_ms`
- `dataset_required`: `True`
- `seed`: `0`

No input CSV was provided, so no FL metric statistics were computed.
Provide `--input-csv` with the schema above to generate grouped statistics.

## Results

| group_by | attack_type | peer_count | byzantine_fraction | count | statistical_significance | dataset_required | accuracy_mean | accuracy_std | accuracy_min | accuracy_max | precision_mean | precision_std | precision_min | precision_max | recall_mean | recall_std | recall_min | recall_max | f1_mean | f1_std | f1_min | f1_max | attack_success_rate_mean | attack_success_rate_std | attack_success_rate_min | attack_success_rate_max | aggregation_latency_ms_mean | aggregation_latency_ms_std | aggregation_latency_ms_min | aggregation_latency_ms_max |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| attack_type,peer_count,byzantine_fraction | TODO_ATTACK_TYPE | TODO_PEER_COUNT | TODO_BYZANTINE_FRACTION |  | False | True |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |  |
