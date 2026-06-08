# Metrics Source Of Truth

This file is the active source of truth for reported OmniGuard V2X prototype metrics. Values not listed here should not be used as headline results.

| Metric name | Value | Test condition | Measurement status | Limitation |
|---|---:|---|---|---|
| Warm-start prototype pipeline latency | 5.34 ms | Local warm-start prototype pipeline measurement | Active prototype metric | Single prototype environment; not a production SLA and not a cross-platform benchmark. |
| Deprecated latency value | 3.57 ms | Previously mentioned in draft material | Deprecated/removed | Not retained as an active metric unless backed by reproducible test logs. |
| Adversarial detection rate | Not reported | Single-run attack-trigger checks only | Headline disabled | Current checks are not statistically significant and do not support a general detection-rate claim. |
| FL poisoning robustness | Not reported | Three-peer, one-Byzantine sanity check with 100x weight-delta trigger | Headline disabled | Not statistically sufficient for Byzantine-robustness claims. |

Current latency wording to use:

`5.34 ms warm-start prototype pipeline latency`

Do not publish replacement values or benchmark tables without reproducible logs, test conditions, sample counts, and confidence intervals.
