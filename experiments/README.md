# OmniGuard V2X Experimental Validation Framework

This directory contains reproducible experiment scaffolds for future journal resubmission. The runners generate configuration grids, CSV/JSON schemas, Markdown reports, and PNG "no results yet" artifacts.

They do not fabricate results. Any metric marked `TODO_DATASET_OR_DEPLOYMENT_REQUIRED` must remain non-numeric until a real dataset, deployment harness, benchmark command, and raw logs are connected.

## CLI Usage

Install optional experiment dependencies before running profiling or report-generation commands:

```bash
pip install -r requirements-experiments.txt
```

```bash
python experiments/run_all.py --output-dir experiments/reports
python experiments/scalability/run_scalability.py --topology full-mesh --rounds 10 --output-dir experiments/reports/scalability
python experiments/fl/run_fl_experiments.py --output-dir experiments/reports/fl
python experiments/fl/run_fl_experiments.py --input-csv path/to/fl_results.csv --group-by attack_type,peer_count,byzantine_fraction --output-dir experiments/reports/fl
python experiments/adversarial/run_adversarial_detection.py --output-dir experiments/reports/adversarial
python experiments/adversarial/run_adversarial_detection.py --input-csv path/to/labeled_detections.csv --threshold 0.5 --output-dir experiments/reports/adversarial
python experiments/latency/run_latency_benchmarks.py --mode local --iterations 1000 --warmup 100 --export-raw --profile-resources --output-dir experiments/reports/latency
python experiments/reports/build_experiment_summary.py --input-dir experiments/reports --output experiments/reports/experiment_summary.md
```

## Architecture

- `scalability/`: deterministic communication-volume analysis for 10, 50, 100, 500, 1000, 5000, and 10000 nodes across full-mesh, gossip-fanout, and committee topologies. This is not a distributed runtime benchmark.
- `fl/`: CSV-backed FL result aggregator. Without `--input-csv`, it writes only a dataset-required schema report; with real FL logs it computes grouped count, mean, standard deviation, min, and max for accuracy, precision, recall, F1, attack success rate, and aggregation latency.
- `adversarial/`: CSV-backed adversarial-detection evaluator. Without `--input-csv`, it writes only a dataset-required schema report; with labeled rows it computes TP, FP, TN, FN, precision, recall, specificity, F1, accuracy, false-positive rate, and false-negative rate overall and per attack type.
- `latency/`: real local callable microbenchmarks for available prototype components, including cold start and warm-start p50, p95, and p99.
- `reports/`: generated CSV, JSON, PNG, Markdown artifacts, and a conservative `build_experiment_summary.py` aggregator that combines available JSON outputs without inventing missing results.

## Remaining TODOs

- Connect distributed deployment harnesses and collect CPU/RAM/network telemetry.
- Connect real FL datasets, models, and attack implementations.
- Connect labeled adversarial datasets and detector score exports.
- Extend latency coverage beyond local callable microbenchmarks to distributed end-to-end runs.
