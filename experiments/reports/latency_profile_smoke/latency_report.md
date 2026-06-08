# Latency Benchmark Report

This report contains measured local prototype callable latency where components were importable.
Skipped rows are not measurements.

## Summary

- `experiment`: `latency`
- `status`: `measured_local_components`
- `created_at`: `2026-06-05T14:01:07.194364+00:00`
- `mode`: `local`
- `iterations`: `5`
- `warmup`: `1`
- `seed`: `7`
- `raw_traces_exported`: `True`
- `raw_trace_rows`: `49`
- `resource_profiling_requested`: `True`
- `resource_profiling_status`: `skipped`
- `resource_profiling_reason`: `psutil unavailable`
- `measured_components`: `7`
- `skipped_components`: `0`

## Results

| component | status | measured_iterations | cold_start_ms | warm_start_p50_ms | warm_start_p95_ms | warm_start_p99_ms | mean_ms | std_ms | min_ms | max_ms | resource_profiling_status | resource_profiling_reason | process_cpu_percent_before | process_cpu_percent_after | rss_mb_before | rss_mb_after | memory_delta_mb | reason |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| security_capabilities | measured | 5 | 0.0016 | 0.0003 | 0.00058 | 0.000596 | 0.0004 | 0.000126 | 0.0003 | 0.0006 | skipped | psutil unavailable | None | None | None | None | None |  |
| identity_security | measured | 5 | 0.01 | 0.0018 | 0.0029 | 0.00306 | 0.0021 | 0.000518 | 0.0017 | 0.0031 | skipped | psutil unavailable | None | None | None | None | None |  |
| consensus_security | measured | 5 | 0.0011 | 0.0003 | 0.00038 | 0.000396 | 0.00028 | 7.5e-05 | 0.0002 | 0.0004 | skipped | psutil unavailable | None | None | None | None | None |  |
| pedersen_privacy | measured | 5 | 0.001 | 0.0002 | 0.00028 | 0.000296 | 0.00018 | 7.5e-05 | 0.0001 | 0.0003 | skipped | psutil unavailable | None | None | None | None | None |  |
| reviewer_audit | measured | 5 | 0.0011 | 0.0002 | 0.0002 | 0.0002 | 0.0002 | 0.0 | 0.0002 | 0.0002 | skipped | psutil unavailable | None | None | None | None | None |  |
| blockchain_append_validate | measured | 5 | 297.9069 | 804.7759 | 1042.18884 | 1062.339368 | 814.26474 | 177.445299 | 564.2093 | 1067.377 | skipped | psutil unavailable | None | None | None | None | None |  |
| fl_validation | measured | 5 | 0.0027 | 0.0004 | 0.00074 | 0.000788 | 0.00046 | 0.000185 | 0.0003 | 0.0008 | skipped | psutil unavailable | None | None | None | None | None |  |

## Skipped Components

None.
