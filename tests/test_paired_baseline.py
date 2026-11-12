"""Synthetic-fixture contract tests only; never real empirical evidence."""
import csv
import hashlib
import json
import math
import tempfile
import unittest
from pathlib import Path

from experiments.statistics.paired_baseline import (
    analyze, bootstrap_paired_mean_ci, read_trials, run, sign_flip_p_value,
)

HEADER = (
    "experiment_id,dataset_id,dataset_version,split_id,attack_type,node_count,"
    "adversarial_fraction,seed,method,run_id,metric,value"
)


def trial(seed, method, value, *, attack="replay", metric="f1", run_id=None):
    return f"ev1,veremi,1.0,heldout,{attack},10,0.1,{seed},{method},{run_id or (method + str(seed))},{metric},{value}"


def fixture(path, rows):
    path.write_text(HEADER + "\n" + "\n".join(rows) + "\n", encoding="utf-8")


class PairedBaselineTests(unittest.TestCase):
    def test_exact_sign_flip_and_paired_bootstrap_are_deterministic(self):
        differences = [0.04, 0.02, 0.03, 0.05, 0.01]
        p, mode = sign_flip_p_value(differences, draws=500, seed=99)
        self.assertEqual(mode, "exact_sign_flip")
        self.assertAlmostEqual(p, 2 / 32)
        ci1 = bootstrap_paired_mean_ci(differences, draws=400, seed=7)
        ci2 = bootstrap_paired_mean_ci(differences, draws=400, seed=7)
        self.assertEqual(ci1, ci2)
        self.assertLessEqual(ci1[0], sum(differences) / len(differences))
        self.assertGreaterEqual(ci1[1], sum(differences) / len(differences))

    def test_report_keeps_exploratory_claims_and_hashes(self):
        with tempfile.TemporaryDirectory() as tmp:
            inp = Path(tmp) / "trials.csv"
            rows = [trial(i, "baseline", 0.6 + i * 0.01) for i in range(10)]
            rows += [trial(i, "candidate", 0.67 + i * 0.01) for i in range(10)]
            fixture(inp, rows)
            summary = run(inp, Path(tmp) / "out", candidate="candidate", baseline="baseline",
                          metric="f1", direction="higher", bootstrap_draws=300, permutations=500)
            row = summary["rows"][0]
            self.assertEqual(row["pair_count"], 10)
            self.assertAlmostEqual(row["mean_improvement"], 0.07)
            self.assertFalse(row["publication_ready"])
            self.assertFalse(row["statistical_significance"])
            self.assertEqual(row["inference_status"], "exploratory_unadjusted")
            self.assertEqual(summary["provenance_status"], "missing")
            manifest = json.loads((Path(tmp) / "out/paired_manifest.json").read_text(encoding="utf-8"))
            self.assertEqual(manifest["raw_input_sha256"], hashlib.sha256(inp.read_bytes()).hexdigest())
            self.assertTrue(manifest["analysis_output_sha256"])
            self.assertIn("Not publication-ready", (Path(tmp) / "out/paired_report.md").read_text())

    def test_insufficient_pairs_omit_inference(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "trials.csv"
            fixture(path, [trial(i, m, 0.4 + i / 100) for i in range(3) for m in ("baseline", "candidate")])
            result = analyze(read_trials(path), candidate="candidate", baseline="baseline",
                             metric="f1", direction="higher", min_pairs=10)
            self.assertEqual(result[0]["inference_status"], "insufficient_pairs")
            self.assertIsNone(result[0]["p_value_two_sided"])
            self.assertIsNone(result[0]["bootstrap_ci95_lower"])

    def test_missing_pairs_fail_closed_instead_of_selective_dropping(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "trials.csv"
            fixture(path, [trial(0, "baseline", 0.6), trial(1, "baseline", 0.7), trial(0, "candidate", 0.8)])
            with self.assertRaisesRegex(ValueError, "unmatched paired trials"):
                analyze(read_trials(path), candidate="candidate", baseline="baseline", metric="f1", direction="higher")

    def test_duplicate_trials_are_not_independent(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "trials.csv"
            fixture(path, [trial(0, "baseline", 0.5), trial(0, "baseline", 0.6, run_id="renamed")])
            with self.assertRaisesRegex(ValueError, "duplicate scenario/method/seed"):
                read_trials(path)

    def test_nonfinite_and_invalid_group_fields_fail_closed(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "trials.csv"
            for value in ("nan", "inf", "-inf"):
                fixture(path, [trial(0, "baseline", value)])
                with self.subTest(metric=value), self.assertRaisesRegex(ValueError, "non-finite"):
                    read_trials(path)
            fixture(path, [trial(0, "baseline", 0.2).replace(",10,0.1,", ",0,0.1,")])
            with self.assertRaisesRegex(ValueError, "invalid or non-finite"):
                read_trials(path)

    def test_lower_is_better_direction_and_holm_adjustment(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "trials.csv"
            rows = []
            for attack in ("replay", "spoofing"):
                for seed in range(6):
                    rows.extend([trial(seed, "baseline", 15.0, attack=attack, metric="latency_ms"),
                                 trial(seed, "candidate", 10.0, attack=attack, metric="latency_ms")])
            fixture(path, rows)
            values = analyze(read_trials(path), candidate="candidate", baseline="baseline",
                             metric="latency_ms", direction="lower", min_pairs=2, bootstrap_draws=300, permutations=500)
            self.assertEqual(len(values), 2)
            for row in values:
                self.assertAlmostEqual(row["mean_improvement"], 5)
                self.assertGreaterEqual(row["holm_adjusted_p"], row["p_value_two_sided"])
                self.assertIsNone(row["paired_effect_dz"])  # zero delta variance

    def test_manifest_hash_mismatch_is_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            inp = Path(tmp) / "trials.csv"
            fixture(inp, [trial(1, "baseline", 0.5), trial(1, "candidate", 0.6)])
            manifest = Path(tmp) / "provenance.json"
            payload = {
                "raw_csv_sha256": "0" * 64, "dataset_source": "https://example.org/placeholder",
                "dataset_version": "v1", "license": "unknown", "split_protocol": "fixed",
                "experiment_protocol": "fixed", "source_commit": "abc123",
            }
            manifest.write_text(json.dumps(payload), encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "does not match"):
                run(inp, Path(tmp) / "out", candidate="candidate", baseline="baseline",
                    metric="f1", direction="higher", provenance=manifest)
            payload["raw_csv_sha256"] = hashlib.sha256(inp.read_bytes()).hexdigest()
            manifest.write_text(json.dumps(payload), encoding="utf-8")
            summary = run(inp, Path(tmp) / "out", candidate="candidate", baseline="baseline",
                          metric="f1", direction="higher", provenance=manifest, min_pairs=2,
                          bootstrap_draws=300, permutations=500)
            self.assertEqual(summary["provenance_status"], "hash_checked_self_reported")
            self.assertFalse(summary["publication_ready"])


if __name__ == "__main__":
    unittest.main()
