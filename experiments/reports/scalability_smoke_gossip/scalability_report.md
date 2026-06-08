# Scalability Communication-Volume Analysis

This is communication-volume simulation/analysis, not a distributed runtime benchmark.
It validates expected message-count growth only; it does not claim measured latency, throughput, CPU, RAM, or consensus duration.

## Formulas

- `full-mesh`: `messages_per_round = n * (n - 1)`; complexity `O(n^2)`.
- `gossip-fanout`: `messages_per_round = n * min(fanout, n - 1)`; complexity `O(n*fanout)`.
- `committee`: `active_validators = min(committee_size, n)`, `messages_per_round = c * (c - 1)`; complexity `O(c^2)`.

## Summary

- `experiment`: `scalability`
- `status`: `communication_volume_analysis_only`
- `created_at`: `2026-06-05T14:08:01.500002+00:00`
- `node_counts`: `10`
- `rounds`: `2`
- `topology`: `gossip-fanout`
- `fanout`: `3`
- `committee_size`: `50`
- `metrics`: `total_messages,messages_per_round,average_messages_per_node,theoretical_complexity`
- `measured_runtime_benchmark`: `False`
- `seed`: `0`

## Results

| topology | node_count | rounds | messages_per_round | total_messages | average_messages_per_node | theoretical_complexity | measured_runtime_benchmark |
| --- | --- | --- | --- | --- | --- | --- | --- |
| gossip-fanout | 10 | 2 | 30 | 60 | 6.0 | O(n*fanout) | False |
