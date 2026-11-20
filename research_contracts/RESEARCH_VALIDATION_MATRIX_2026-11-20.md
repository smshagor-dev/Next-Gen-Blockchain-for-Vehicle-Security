# Research validation matrix (2026-11-20)

This file records the scope of this branch's paired-overhead analysis. It does not supersede other repository research tracking.

| Workstream | Status | Evidence / limitation |
|---|---|---|
| Authenticated hardware ingress and bounded receives | Partial | Independent exact-checkout audit and physical interlock validation outstanding |
| Durable replay/one-shot admission | Partial | Implementation and crash/concurrency tests on draft PR; full checkout execution outstanding |
| Paired runtime timing collection | Partial | Balanced seeded benchmark implemented; no independently validated raw run in this update |
| Trial-cluster uncertainty analysis | Implemented, unverified | `research_contracts/analyze_paired_admission.py`; no fabricated numeric results |
| Analysis negative controls | Implemented, unexecuted | `tests/test_paired_admission_analysis.py` |
| Mock ledger finality and rollback | Blocked | No independently trusted finality or rollback-resistant checkpoint |
| Authentic VeReMi NextGen and CAN ingestion | Pending | No verified dataset provenance or real labelled experimental splits |
| Adversarial matched baselines and ablations | Pending | No publishable effectiveness evidence |
| Network/CPU/RAM scaling | Pending | No instrumented independent process runs |
| Defensible scientific manuscript | Blocked | Requires authentic datasets, baselines, multi-seed uncertainty and limitations |

## Reproduction commands

```sh
python -m unittest discover -s tests -p 'test_paired_admission_analysis.py' -v
python -m research_contracts.benchmark_durable_admission --repeats 30 --seed 20261120 --output /tmp/omni-paired-30.json
python -m research_contracts.analyze_paired_admission /tmp/omni-paired-30.json --output /tmp/omni-paired-summary.json
```

The bootstrap resamples complete trials rather than treating three operations within a trial as independent. The 95% interval is exploratory and cannot establish attack resistance or statistical significance from a sample-count rule. Tests above are prescribed, not claimed passed.

## Next engineering task

Execute exact checkout tests, repair failures, record immutable environment metadata, and implement paired CPU/RAM/process-isolated network experiments; then move to verified labelled dataset ingest and identical-split adversarial baselines.
