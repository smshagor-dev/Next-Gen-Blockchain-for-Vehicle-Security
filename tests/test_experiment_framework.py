import tempfile
import unittest
import csv
import json
import math
from unittest import mock
from pathlib import Path

from experiments.adversarial.run_adversarial_detection import METRICS as ADV_METRICS
from experiments.adversarial.run_adversarial_detection import SCENARIOS, build_plan as build_adv_plan
from experiments.adversarial.run_adversarial_detection import main as adversarial_main
from experiments.adversarial.run_adversarial_detection import run as run_adversarial
from experiments.common import FRAMEWORK_STATUS
from experiments.fl.run_fl_experiments import ATTACKS, PEER_COUNTS, SEEDS, build_plan as build_fl_plan
from experiments.fl.run_fl_experiments import main as fl_main
from experiments.fl.run_fl_experiments import run as run_fl
from experiments.latency.run_latency_benchmarks import PERCENTILES, START_MODES, build_plan as build_latency_plan
from experiments.latency.run_latency_benchmarks import main as latency_main
from experiments.reports.build_experiment_summary import main as summary_main
from experiments.reports.build_experiment_summary import build_summary
from experiments.run_all import run_all
from experiments.scalability.run_scalability import METRICS as SCALABILITY_METRICS
from experiments.scalability.run_scalability import NODE_COUNTS, build_plan as build_scalability_plan
from experiments.scalability.run_scalability import main as scalability_main
from experiments.scalability.run_scalability import run as run_scalability


class ExperimentFrameworkTests(unittest.TestCase):
    def test_scalability_plan_uses_required_node_counts_and_metrics(self):
        self.assertEqual(NODE_COUNTS, [10, 50, 100, 500, 1000, 5000, 10000])
        for metric in ["total_messages", "messages_per_round", "average_messages_per_node", "theoretical_complexity"]:
            self.assertIn(metric, SCALABILITY_METRICS)
        self.assertEqual([cfg.nodes for cfg in build_scalability_plan()], NODE_COUNTS)

    def test_fl_plan_uses_required_peers_seeds_attacks(self):
        self.assertEqual(PEER_COUNTS, [10, 20, 50])
        self.assertEqual(len(SEEDS), 30)
        for attack in ["sign-flip", "label-flip", "gaussian-noise", "scaling-attack", "random-update", "backdoor"]:
            self.assertIn(attack, ATTACKS)
        self.assertEqual(len(build_fl_plan()), len(PEER_COUNTS) * len(SEEDS) * len(ATTACKS))

    def test_fl_runner_no_input_writes_dataset_required_schema_only(self):
        with tempfile.TemporaryDirectory() as tmp:
            result = run_fl(Path(tmp))
            self.assertEqual(result["status"], "dataset_required")
            self.assertTrue(result["dataset_required"])
            out = Path(tmp)
            for name in ["fl_results.csv", "fl_results.json", "fl_report.md", "fl_plot.png"]:
                self.assertTrue((out / name).exists(), name)
            payload = json.loads((out / "fl_results.json").read_text(encoding="utf-8"))
            row = payload["rows"][0]
            self.assertEqual(row["count"], "")
            self.assertEqual(row["accuracy_mean"], "")
            self.assertEqual(row["aggregation_latency_ms_mean"], "")
            report = (out / "fl_report.md").read_text(encoding="utf-8")
            self.assertIn("No input CSV was provided", report)

    def test_fl_runner_computes_grouped_means_from_fixture_csv(self):
        with tempfile.TemporaryDirectory() as tmp:
            input_csv = Path(tmp) / "fl_fixture.csv"
            input_csv.write_text(
                "\n".join(
                    [
                        "seed,peer_count,byzantine_fraction,attack_type,accuracy,precision,recall,f1,attack_success_rate,aggregation_latency_ms",
                        "0,10,0.1,sign-flip,0.8,0.7,0.6,0.65,0.2,12.0",
                        "1,10,0.1,sign-flip,0.6,0.5,0.4,0.45,0.4,16.0",
                    ]
                )
                + "\n",
                encoding="utf-8",
            )
            out = Path(tmp) / "out"
            rc = fl_main(["--input-csv", str(input_csv), "--output-dir", str(out)])
            self.assertEqual(rc, 0)
            for name in ["fl_results.csv", "fl_results.json", "fl_report.md", "fl_plot.png"]:
                self.assertTrue((out / name).exists(), name)
            payload = json.loads((out / "fl_results.json").read_text(encoding="utf-8"))
            self.assertEqual(payload["status"], "computed_from_fl_csv")
            self.assertFalse(payload["dataset_required"])
            row = payload["rows"][0]
            self.assertEqual(row["count"], 2)
            self.assertEqual(row["accuracy_mean"], 0.7)
            self.assertEqual(row["precision_mean"], 0.6)
            self.assertEqual(row["recall_mean"], 0.5)
            self.assertEqual(row["f1_mean"], 0.55)
            self.assertEqual(row["attack_success_rate_mean"], 0.3)
            self.assertEqual(row["aggregation_latency_ms_mean"], 14.0)
            self.assertFalse(row["statistical_significance"])

    def test_adversarial_plan_uses_required_scenarios_and_metrics(self):
        for scenario in [
            "realistic-speed-range",
            "replay-attack",
            "timing-attack",
            "gps-drift",
            "sensor-noise",
            "gradual-poisoning",
        ]:
            self.assertIn(scenario, SCENARIOS)
        for metric in ["tp", "fp", "tn", "fn", "precision", "recall", "specificity", "f1", "accuracy"]:
            self.assertIn(metric, ADV_METRICS)
        self.assertGreater(len(build_adv_plan()), 0)

    def test_latency_plan_uses_required_modes_and_percentiles(self):
        self.assertEqual(START_MODES, ["cold-start", "warm-start"])
        self.assertEqual(PERCENTILES, ["p50", "p95", "p99"])
        self.assertGreater(len(build_latency_plan()), 0)

    def test_run_all_writes_artifacts_without_results(self):
        with tempfile.TemporaryDirectory() as tmp:
            manifest = run_all(Path(tmp))
            self.assertEqual(manifest["status"], FRAMEWORK_STATUS)
            self.assertTrue((Path(tmp) / "manifest.json").exists())
            self.assertTrue(manifest["artifacts"])
            for artifact in manifest["artifacts"]:
                self.assertTrue(Path(artifact).exists(), artifact)
            scalability_csv = Path(tmp) / "scalability" / "scalability_results.csv"
            self.assertTrue(scalability_csv.exists())
            scalability_json = Path(tmp) / "scalability" / "scalability_results.json"
            payload = json.loads(scalability_json.read_text(encoding="utf-8"))
            self.assertFalse(payload["measured_runtime_benchmark"])

    def test_scalability_full_mesh_formula_and_outputs(self):
        with tempfile.TemporaryDirectory() as tmp:
            result = run_scalability(Path(tmp), node_counts=[10], rounds=2, topology="full-mesh")
            row = result["rows"][0]
            self.assertEqual(row["messages_per_round"], 90)
            self.assertEqual(row["total_messages"], 180)
            self.assertFalse(row["measured_runtime_benchmark"])
            out = Path(tmp)
            for name in ["scalability_results.csv", "scalability_results.json", "scalability_report.md", "scalability_plot.png"]:
                self.assertTrue((out / name).exists(), name)

    def test_scalability_gossip_fanout_formula(self):
        with tempfile.TemporaryDirectory() as tmp:
            rc = scalability_main(
                [
                    "--node-counts",
                    "10",
                    "--rounds",
                    "2",
                    "--topology",
                    "gossip-fanout",
                    "--fanout",
                    "3",
                    "--output-dir",
                    tmp,
                ]
            )
            self.assertEqual(rc, 0)
            payload = json.loads((Path(tmp) / "scalability_results.json").read_text(encoding="utf-8"))
            row = payload["rows"][0]
            self.assertEqual(row["messages_per_round"], 30)
            self.assertEqual(row["total_messages"], 60)
            self.assertFalse(row["measured_runtime_benchmark"])

    def test_scalability_committee_formula(self):
        with tempfile.TemporaryDirectory() as tmp:
            result = run_scalability(Path(tmp), node_counts=[100], rounds=2, topology="committee", committee_size=10)
            row = result["rows"][0]
            self.assertEqual(row["active_validators"], 10)
            self.assertEqual(row["messages_per_round"], 90)
            self.assertEqual(row["total_messages"], 180)
            self.assertFalse(row["measured_runtime_benchmark"])

    def test_adversarial_runner_computes_metrics_from_labeled_csv(self):
        with tempfile.TemporaryDirectory() as tmp:
            input_csv = Path(tmp) / "fixture.csv"
            input_csv.write_text(
                "\n".join(
                    [
                        "label,score,attack_type",
                        "0,0.1,normal",
                        "1,0.9,replay",
                        "1,0.4,replay",
                        "0,0.8,normal",
                    ]
                )
                + "\n",
                encoding="utf-8",
            )
            out = Path(tmp) / "out"
            rc = adversarial_main(["--input-csv", str(input_csv), "--threshold", "0.5", "--output-dir", str(out)])
            self.assertEqual(rc, 0)
            for name in ["adversarial_results.csv", "adversarial_results.json", "adversarial_report.md", "adversarial_plot.png"]:
                self.assertTrue((out / name).exists(), name)
            payload = json.loads((out / "adversarial_results.json").read_text(encoding="utf-8"))
            self.assertFalse(payload["dataset_required"])
            self.assertFalse(payload["measured_runtime_benchmark"])
            self.assertFalse(payload["statistical_significance"])
            overall = next(row for row in payload["rows"] if row["scope"] == "overall")
            self.assertEqual(overall["tp"], 1)
            self.assertEqual(overall["fp"], 1)
            self.assertEqual(overall["tn"], 1)
            self.assertEqual(overall["fn"], 1)
            self.assertEqual(overall["precision"], 0.5)
            self.assertEqual(overall["recall"], 0.5)
            self.assertEqual(overall["specificity"], 0.5)
            self.assertEqual(overall["f1"], 0.5)
            self.assertEqual(overall["accuracy"], 0.5)

    def test_adversarial_runner_no_input_writes_dataset_required_schema_only(self):
        with tempfile.TemporaryDirectory() as tmp:
            result = run_adversarial(Path(tmp))
            self.assertEqual(result["status"], "dataset_required")
            self.assertTrue(result["dataset_required"])
            out = Path(tmp)
            for name in ["adversarial_results.csv", "adversarial_results.json", "adversarial_report.md", "adversarial_plot.png"]:
                self.assertTrue((out / name).exists(), name)
            payload = json.loads((out / "adversarial_results.json").read_text(encoding="utf-8"))
            row = payload["rows"][0]
            self.assertEqual(row["scope"], "schema_example")
            for field in ["tp", "fp", "tn", "fn", "precision", "recall", "f1", "accuracy"]:
                self.assertEqual(row[field], "")
            report = (out / "adversarial_report.md").read_text(encoding="utf-8")
            self.assertIn("No input CSV was provided", report)

    def test_latency_runner_executes_and_writes_measured_outputs(self):
        with tempfile.TemporaryDirectory() as tmp:
            rc = latency_main(["--iterations", "5", "--warmup", "1", "--output-dir", tmp, "--seed", "7"])
            self.assertEqual(rc, 0)
            out = Path(tmp)
            for name in ["latency_results.csv", "latency_results.json", "latency_report.md", "latency_plot.png"]:
                self.assertTrue((out / name).exists(), name)

            payload = json.loads((out / "latency_results.json").read_text(encoding="utf-8"))
            rows = payload["rows"]
            self.assertTrue(rows)
            for row in rows:
                if row["status"] == "measured":
                    for field in [
                        "cold_start_ms",
                        "warm_start_p50_ms",
                        "warm_start_p95_ms",
                        "warm_start_p99_ms",
                        "mean_ms",
                        "std_ms",
                        "min_ms",
                        "max_ms",
                    ]:
                        self.assertIsInstance(row[field], (int, float), f"{row['component']} {field}")
                        self.assertFalse(math.isnan(float(row[field])), f"{row['component']} {field}")
                elif row["status"] == "skipped":
                    self.assertTrue(row.get("reason"), row["component"])
                else:
                    self.fail(f"Unexpected latency row status: {row}")

    def test_latency_runner_exports_raw_traces_when_requested(self):
        with tempfile.TemporaryDirectory() as tmp:
            rc = latency_main(
                [
                    "--iterations",
                    "5",
                    "--warmup",
                    "1",
                    "--output-dir",
                    tmp,
                    "--seed",
                    "7",
                    "--export-raw",
                ]
            )
            self.assertEqual(rc, 0)
            out = Path(tmp)
            raw_csv = out / "latency_raw_traces.csv"
            raw_json = out / "latency_raw_traces.json"
            self.assertTrue(raw_csv.exists())
            self.assertTrue(raw_json.exists())

            with raw_csv.open(newline="", encoding="utf-8") as f:
                csv_rows = list(csv.DictReader(f))
            self.assertTrue(csv_rows)
            self.assertEqual(
                set(csv_rows[0].keys()),
                {"component", "iteration", "phase", "latency_ms", "seed", "timestamp_utc", "status"},
            )

            payload = json.loads(raw_json.read_text(encoding="utf-8"))
            traces = payload["rows"]
            self.assertTrue(traces)
            phases = {row["phase"] for row in traces}
            self.assertIn("cold", phases)
            self.assertIn("warmup", phases)
            self.assertIn("measured", phases)

            measured_traces_by_component = {}
            warmup_traces_by_component = {}
            for row in traces:
                self.assertIn(row["phase"], {"cold", "warmup", "measured"})
                if row["phase"] == "measured":
                    self.assertIsInstance(row["latency_ms"], (int, float))
                    self.assertFalse(math.isnan(float(row["latency_ms"])))
                    measured_traces_by_component.setdefault(row["component"], []).append(row)
                elif row["phase"] == "warmup":
                    warmup_traces_by_component.setdefault(row["component"], []).append(row)

            summary = json.loads((out / "latency_results.json").read_text(encoding="utf-8"))
            self.assertTrue(summary["raw_traces_exported"])
            for row in summary["rows"]:
                if row["status"] != "measured":
                    continue
                component = row["component"]
                self.assertEqual(row["measured_iterations"], 5)
                self.assertEqual(len(measured_traces_by_component[component]), 5)
                self.assertEqual(len(warmup_traces_by_component[component]), 1)

    def test_latency_runner_profiles_resources_when_requested(self):
        with tempfile.TemporaryDirectory() as tmp:
            rc = latency_main(
                [
                    "--iterations",
                    "5",
                    "--warmup",
                    "1",
                    "--output-dir",
                    tmp,
                    "--seed",
                    "7",
                    "--profile-resources",
                ]
            )
            self.assertEqual(rc, 0)
            out = Path(tmp)
            with (out / "latency_results.csv").open(newline="", encoding="utf-8") as f:
                csv_rows = list(csv.DictReader(f))
            self.assertTrue(csv_rows)
            for field in [
                "resource_profiling_status",
                "resource_profiling_reason",
                "process_cpu_percent_before",
                "process_cpu_percent_after",
                "rss_mb_before",
                "rss_mb_after",
                "memory_delta_mb",
            ]:
                self.assertIn(field, csv_rows[0])

            payload = json.loads((out / "latency_results.json").read_text(encoding="utf-8"))
            self.assertTrue(payload["resource_profiling_requested"])
            measured_rows = [row for row in payload["rows"] if row["status"] == "measured"]
            self.assertTrue(measured_rows)
            for row in measured_rows:
                if row["resource_profiling_status"] == "measured":
                    for field in [
                        "process_cpu_percent_before",
                        "process_cpu_percent_after",
                        "rss_mb_before",
                        "rss_mb_after",
                        "memory_delta_mb",
                    ]:
                        self.assertIsInstance(row[field], (int, float), f"{row['component']} {field}")
                elif row["resource_profiling_status"] == "skipped":
                    self.assertEqual(row["resource_profiling_reason"], "psutil unavailable")

            report = (out / "latency_report.md").read_text(encoding="utf-8")
            self.assertIn("resource_profiling_status", report)

    def test_latency_runner_marks_resource_profiling_skipped_without_psutil(self):
        real_import = __import__

        def import_without_psutil(name, *args, **kwargs):
            if name == "psutil":
                raise ImportError("psutil unavailable")
            return real_import(name, *args, **kwargs)

        with tempfile.TemporaryDirectory() as tmp, mock.patch("builtins.__import__", side_effect=import_without_psutil):
            rc = latency_main(
                [
                    "--iterations",
                    "5",
                    "--warmup",
                    "1",
                    "--output-dir",
                    tmp,
                    "--seed",
                    "7",
                    "--profile-resources",
                ]
            )
            self.assertEqual(rc, 0)
            payload = json.loads((Path(tmp) / "latency_results.json").read_text(encoding="utf-8"))
            self.assertEqual(payload["resource_profiling_status"], "skipped")
            self.assertEqual(payload["resource_profiling_reason"], "psutil unavailable")
            for row in payload["rows"]:
                self.assertEqual(row["resource_profiling_status"], "skipped")
                self.assertEqual(row["resource_profiling_reason"], "psutil unavailable")
                self.assertIsNone(row["rss_mb_before"])
                self.assertIsNone(row["process_cpu_percent_before"])

    def test_latency_raw_traces_include_resources_when_both_flags_enabled(self):
        with tempfile.TemporaryDirectory() as tmp:
            rc = latency_main(
                [
                    "--iterations",
                    "5",
                    "--warmup",
                    "1",
                    "--output-dir",
                    tmp,
                    "--seed",
                    "7",
                    "--export-raw",
                    "--profile-resources",
                ]
            )
            self.assertEqual(rc, 0)
            payload = json.loads((Path(tmp) / "latency_raw_traces.json").read_text(encoding="utf-8"))
            for field in [
                "resource_profiling_status",
                "resource_profiling_reason",
                "process_cpu_percent_before",
                "process_cpu_percent_after",
                "rss_mb_before",
                "rss_mb_after",
                "memory_delta_mb",
            ]:
                self.assertIn(field, payload["schema"])
            measured = [row for row in payload["rows"] if row["phase"] == "measured"]
            self.assertTrue(measured)
            for row in measured:
                if row["resource_profiling_status"] == "measured":
                    self.assertIsInstance(row["rss_mb_before"], (int, float))
                    self.assertIsInstance(row["rss_mb_after"], (int, float))
                elif row["resource_profiling_status"] == "skipped":
                    self.assertEqual(row["resource_profiling_reason"], "psutil unavailable")

    def test_experiment_dependency_file_documents_resource_profiling_setup(self):
        requirements = Path("requirements-experiments.txt")
        self.assertTrue(requirements.exists())
        deps = requirements.read_text(encoding="utf-8").lower()
        self.assertIn("psutil", deps)
        readme = Path("experiments/README.md").read_text(encoding="utf-8")
        self.assertIn("pip install -r requirements-experiments.txt", readme)

    def test_experiment_summary_empty_input_marks_missing_results(self):
        with tempfile.TemporaryDirectory() as tmp:
            output = Path(tmp) / "summary.md"
            result_path = build_summary(Path(tmp), output)
            self.assertEqual(result_path, output)
            text = output.read_text(encoding="utf-8")
            self.assertIn("latency_results.json`: missing", text)
            self.assertIn("Scalability communication analysis: missing result file", text)
            self.assertIn("Do not claim 100% detection", text)

    def test_experiment_summary_reads_fixture_metrics_without_inventing_missing_metrics(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "latency").mkdir()
            (root / "latency" / "latency_results.json").write_text(
                json.dumps(
                    {
                        "status": "measured_local_components",
                        "rows": [
                            {
                                "component": "security_capabilities",
                                "warm_start_p50_ms": 1.25,
                                "status": "measured",
                                "note": "not numeric",
                            }
                        ],
                    }
                ),
                encoding="utf-8",
            )
            output = root / "experiment_summary.md"
            rc = summary_main(["--input-dir", str(root), "--output", str(output)])
            self.assertEqual(rc, 0)
            text = output.read_text(encoding="utf-8")
            self.assertIn("warm_start_p50_ms=1.25", text)
            self.assertNotIn("not numeric", text)
            self.assertIn("adversarial_results.json`: missing", text)

    def test_experiment_summary_flags_dataset_required_and_non_runtime(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "adversarial").mkdir()
            (root / "adversarial" / "adversarial_results.json").write_text(
                json.dumps({"status": "dataset_required", "dataset_required": True, "rows": [{"tp": "", "precision": ""}]}),
                encoding="utf-8",
            )
            (root / "scalability").mkdir()
            (root / "scalability" / "scalability_results.json").write_text(
                json.dumps(
                    {
                        "status": "communication_volume_analysis_only",
                        "measured_runtime_benchmark": False,
                        "rows": [{"topology": "full-mesh", "total_messages": 180, "measured_runtime_benchmark": False}],
                    }
                ),
                encoding="utf-8",
            )
            output = root / "summary.md"
            build_summary(root, output)
            text = output.read_text(encoding="utf-8")
            self.assertIn("Dataset required: yes", text)
            self.assertIn("Runtime benchmark: no", text)
            self.assertIn("total_messages=180", text)


if __name__ == "__main__":
    unittest.main()
