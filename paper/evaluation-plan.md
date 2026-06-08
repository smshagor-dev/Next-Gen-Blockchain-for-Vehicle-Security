# Evaluation Plan

The evaluation framework is designed to make future validation reproducible without fabricating benchmark results.

## Latency Local Microbenchmarks

`experiments/latency/run_latency_benchmarks.py` measures callable local prototype components where available. It supports iteration counts, warmup, seeds, raw per-iteration trace export, optional resource profiling, CSV/JSON output, plots, and Markdown reports. Missing components are marked as skipped rather than assigned synthetic values.

## Scalability Communication Analysis

`experiments/scalability/run_scalability.py` computes deterministic communication-volume metrics for full-mesh, gossip-fanout, and committee topologies. This validates expected message growth such as `O(n^2)`, `O(n*fanout)`, and `O(c^2)`. It is not a distributed runtime benchmark.

## CSV-Backed Adversarial Evaluation

`experiments/adversarial/run_adversarial_detection.py` computes TP, FP, TN, FN, precision, recall, specificity, F1, accuracy, false-positive rate, and false-negative rate from labeled CSV files. If no CSV is provided, it emits a dataset-required TODO report and no fake metrics.

## CSV-Backed Federated-Learning Evaluation

`experiments/fl/run_fl_experiments.py` computes grouped count, mean, standard deviation, minimum, and maximum from FL experiment result CSV files. Statistical significance is marked true only for groups with at least 30 observations.

## Experiment Summary Aggregator

`experiments/reports/build_experiment_summary.py` combines available latency, scalability, adversarial, and FL JSON outputs into a single Markdown summary. It marks missing files, dataset-required artifacts, non-runtime analyses, and non-significant results.

## No Fake Benchmark Rule

The paper must only report numbers produced by available experiment artifacts. Missing datasets, unavailable components, and unexecuted benchmarks must remain TODOs or limitations.

