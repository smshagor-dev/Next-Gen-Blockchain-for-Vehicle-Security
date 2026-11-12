"""Research inference guardrails: descriptive CSV rows are not hypothesis tests."""
import json
import tempfile
import unittest
from pathlib import Path

from experiments.fl.run_fl_experiments import grouped_statistics, _load_rows
from experiments.reports.build_experiment_summary import build_summary


def fl_rows(count, *, unique_seeds=True):
    rows = []
    for i in range(count):
        rows.append({
            "seed": i if unique_seeds else 0,
            "peer_count": 10,
            "byzantine_fraction": 0.1,
            "attack_type": "sign-flip",
            "accuracy": 0.7,
            "precision": 0.6,
            "recall": 0.5,
            "f1": 0.55,
            "attack_success_rate": 0.3,
            "aggregation_latency_ms": 12.0,
        })
    return rows


class ResearchEvidenceIntegrityTests(unittest.TestCase):
    def test_thirty_seeds_do_not_make_metrics_significant(self):
        grouped = grouped_statistics(
            fl_rows(30), ["attack_type", "peer_count", "byzantine_fraction"]
        )
        self.assertEqual(grouped[0]["count"], 30)
        self.assertEqual(grouped[0]["distinct_seed_count"], 30)
        self.assertFalse(grouped[0]["statistical_significance"])
        self.assertEqual(grouped[0]["inference_status"], "not_performed")

    def test_duplicate_seed_rows_are_not_independent_runs(self):
        grouped = grouped_statistics(
            fl_rows(30, unique_seeds=False), ["attack_type", "peer_count", "byzantine_fraction"]
        )
        self.assertEqual(grouped[0]["count"], 30)
        self.assertEqual(grouped[0]["distinct_seed_count"], 1)
        self.assertFalse(grouped[0]["statistical_significance"])

    def test_nonfinite_fl_metrics_are_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "results.csv"
            path.write_text(
                "seed,peer_count,byzantine_fraction,attack_type,accuracy,precision,recall,f1,attack_success_rate,aggregation_latency_ms\n"
                "0,10,0.1,sign-flip,nan,0.5,0.5,0.5,0.1,12.0\n",
                encoding="utf-8",
            )
            with self.assertRaisesRegex(ValueError, "non-finite accuracy"):
                _load_rows(path)

    def test_fixture_only_result_cannot_satisfy_evidence_gate(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            fixture_dir = root / "fl_fixture_smoke"
            fixture_dir.mkdir()
            (fixture_dir / "fl_results.json").write_text(
                json.dumps({
                    "status": "computed_from_fl_csv",
                    "dataset_required": False,
                    "statistical_significance": False,
                    "rows": [{
                        "attack_type": "sign-flip",
                        "count": 30,
                        "statistical_significance": False,
                        "inference_status": "not_performed",
                    }],
                }),
                encoding="utf-8",
            )
            output = root / "report.md"
            build_summary(root, output)
            report = output.read_text(encoding="utf-8")
            self.assertIn("fixture/smoke only", report)
            self.assertIn("only fixture/smoke evidence located", report)
            self.assertIn("Sample count (including 30 rows)", report)


if __name__ == "__main__":
    unittest.main()
