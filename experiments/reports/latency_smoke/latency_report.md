# Latency Benchmark Report

This report contains measured local prototype callable latency where components were importable.
Skipped rows are not measurements.

## Summary

- `experiment`: `latency`
- `status`: `measured_local_components`
- `created_at`: `2026-06-05T13:51:42.530755+00:00`
- `mode`: `local`
- `iterations`: `5`
- `warmup`: `1`
- `seed`: `7`
- `measured_components`: `7`
- `skipped_components`: `0`

## Results

| component | status | cold_start_ms | warm_start_p50_ms | warm_start_p95_ms | warm_start_p99_ms | mean_ms | std_ms | min_ms | max_ms | reason |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| security_capabilities | measured | 0.0016 | 0.0003 | 0.00074 | 0.000788 | 0.00044 | 0.000196 | 0.0003 | 0.0008 |  |
| identity_security | measured | 0.0095 | 0.0015 | 0.0023 | 0.00238 | 0.0017 | 0.000405 | 0.0013 | 0.0024 |  |
| consensus_security | measured | 0.0011 | 0.0003 | 0.00038 | 0.000396 | 0.00028 | 7.5e-05 | 0.0002 | 0.0004 |  |
| pedersen_privacy | measured | 0.0009 | 0.0002 | 0.00028 | 0.000296 | 0.0002 | 6.3e-05 | 0.0001 | 0.0003 |  |
| reviewer_audit | measured | 0.0011 | 0.0002 | 0.0002 | 0.0002 | 0.00018 | 4e-05 | 0.0001 | 0.0002 |  |
| blockchain_append_validate | measured | 295.7526 | 790.9525 | 1066.89442 | 1093.523924 | 811.19054 | 190.812145 | 558.3535 | 1100.1813 |  |
| fl_validation | measured | 0.003 | 0.0004 | 0.00074 | 0.000788 | 0.00046 | 0.000185 | 0.0003 | 0.0008 |  |
