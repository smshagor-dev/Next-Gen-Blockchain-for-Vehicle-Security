# Latency Benchmark Report

This report contains measured local prototype callable latency where components were importable.
Skipped rows are not measurements.

## Summary

- `experiment`: `latency`
- `status`: `measured_local_components`
- `created_at`: `2026-06-05T13:57:07.195520+00:00`
- `mode`: `local`
- `iterations`: `5`
- `warmup`: `1`
- `seed`: `7`
- `raw_traces_exported`: `True`
- `raw_trace_rows`: `49`
- `measured_components`: `7`
- `skipped_components`: `0`

## Results

| component | status | measured_iterations | cold_start_ms | warm_start_p50_ms | warm_start_p95_ms | warm_start_p99_ms | mean_ms | std_ms | min_ms | max_ms | reason |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| security_capabilities | measured | 5 | 0.0019 | 0.0004 | 0.00202 | 0.002324 | 0.00082 | 0.000791 | 0.0004 | 0.0024 |  |
| identity_security | measured | 5 | 0.0088 | 0.0016 | 0.00246 | 0.002572 | 0.00182 | 0.000417 | 0.0015 | 0.0026 |  |
| consensus_security | measured | 5 | 0.001 | 0.0003 | 0.0004 | 0.0004 | 0.00034 | 4.9e-05 | 0.0003 | 0.0004 |  |
| pedersen_privacy | measured | 5 | 0.0009 | 0.0002 | 0.00036 | 0.000392 | 0.00024 | 8e-05 | 0.0002 | 0.0004 |  |
| reviewer_audit | measured | 5 | 0.0011 | 0.0002 | 0.00028 | 0.000296 | 0.00022 | 4e-05 | 0.0002 | 0.0003 |  |
| blockchain_append_validate | measured | 5 | 303.8451 | 802.9422 | 1058.13888 | 1078.903376 | 813.45776 | 191.326575 | 544.2623 | 1084.0945 |  |
| fl_validation | measured | 5 | 0.0025 | 0.0004 | 0.00072 | 0.000784 | 0.00046 | 0.000174 | 0.0003 | 0.0008 |  |

## Skipped Components

None.
