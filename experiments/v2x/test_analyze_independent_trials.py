"""Synthetic contract tests, not independent physical trial data."""
import hashlib
import json
import unittest

from analyze_independent_trials import parse_trials, paired_cluster_analysis


def record(i, b=None, c=None):
    return {
        "trial_id": f"trial-{i}", "independent_cluster_id": f"site-{i}",
        "scenario_id": "urban", "split": "test",
        "source_sha256": hashlib.sha256(str(i).encode()).hexdigest(),
        "baseline": b or {"tp": 3, "fp": 2, "tn": 3, "fn": 2},
        "candidate": c or {"tp": 4, "fp": 1, "tn": 4, "fn": 1},
    }


def raw(*rows):
    return ("\n".join(json.dumps(r, sort_keys=True) for r in rows) + "\n").encode()


class TrialAnalysisTests(unittest.TestCase):
    def setUp(self):
        self.data = raw(record(1), record(2), record(3))

    def test_identical_runs_are_deterministic(self):
        a = paired_cluster_analysis(self.data, bootstrap_draws=200)
        b = paired_cluster_analysis(self.data, bootstrap_draws=200)
        self.assertEqual(a, b)
        self.assertAlmostEqual(a["mean_difference_pp"], 20)
        self.assertEqual(a["claimed_independent_clusters"], 3)
        self.assertFalse(a["publication_ready"])

    def test_no_automatic_significance_at_thirty_clusters(self):
        same = {"tp": 4, "fp": 1, "tn": 4, "fn": 1}
        d = raw(*(record(i, same, same) for i in range(30)))
        report = paired_cluster_analysis(d, bootstrap_draws=200)
        self.assertEqual(report["mean_difference_pp"], 0)
        self.assertEqual(report["exploratory_sign_flip_p_two_sided"], 1)

    def test_unequal_denominators(self):
        x = record(1)
        x["candidate"]["tp"] += 1
        with self.assertRaisesRegex(ValueError, "denominators"):
            parse_trials(raw(x, record(2)))

    def test_unequal_world_truth(self):
        x = record(1)
        x["candidate"]["tp"] += 1
        x["candidate"]["tn"] -= 1
        with self.assertRaisesRegex(ValueError, "world labels"):
            parse_trials(raw(x, record(2)))

    def test_duplicate_clusters(self):
        x, y = record(1), record(2)
        y["independent_cluster_id"] = x["independent_cluster_id"]
        with self.assertRaisesRegex(ValueError, "duplicate independent_cluster_id"):
            parse_trials(raw(x, y))

    def test_duplicate_source_hash(self):
        x, y = record(1), record(2)
        y["source_sha256"] = x["source_sha256"]
        with self.assertRaisesRegex(ValueError, "duplicate source_sha256"):
            parse_trials(raw(x, y))

    def test_duplicate_trial_id(self):
        x, y = record(1), record(2)
        y["trial_id"] = x["trial_id"]
        with self.assertRaisesRegex(ValueError, "duplicate trial_id"):
            parse_trials(raw(x, y))

    def test_duplicate_json_keys(self):
        malformed = self.data.decode().replace('"trial_id":', '"trial_id":"fake","trial_id":', 1)
        with self.assertRaisesRegex(ValueError, "duplicate JSON key"):
            parse_trials(malformed.encode())

    def test_reject_train_split(self):
        x = record(1)
        x["split"] = "train"
        with self.assertRaisesRegex(ValueError, "test split"):
            parse_trials(raw(x, record(2)))

    def test_reject_boolean_counts(self):
        x = record(1)
        x["baseline"]["tp"] = True
        with self.assertRaisesRegex(ValueError, "confusion counts"):
            parse_trials(raw(x, record(2)))

    def test_reject_negative_counts(self):
        x = record(1)
        x["baseline"]["fp"] = -1
        with self.assertRaisesRegex(ValueError, "confusion counts"):
            parse_trials(raw(x, record(2)))

    def test_reject_single_cluster(self):
        with self.assertRaisesRegex(ValueError, "at least two"):
            paired_cluster_analysis(raw(record(1)), bootstrap_draws=200)

    def test_reject_blank_line(self):
        with self.assertRaisesRegex(ValueError, "nonempty"):
            parse_trials(self.data + b"\n")

    def test_reject_unknown_fields(self):
        x = record(1)
        x["p_value"] = 0.00001
        with self.assertRaisesRegex(ValueError, "schema mismatch"):
            parse_trials(raw(x, record(2)))

    def test_reject_invalid_bootstrap_configuration(self):
        with self.assertRaisesRegex(ValueError, "bootstrap"):
            paired_cluster_analysis(self.data, bootstrap_draws=20)

    def test_reject_zero_incident_universe(self):
        z = {"tp": 0, "fp": 0, "tn": 0, "fn": 0}
        with self.assertRaisesRegex(ValueError, "zero incident"):
            parse_trials(raw(record(1, z, z), record(2)))

    def test_per_cluster_effects_are_not_incident_replicates(self):
        x = record(1, {"tp": 0, "fp": 0, "tn": 9, "fn": 1},
                   {"tp": 1, "fp": 0, "tn": 9, "fn": 0})
        y = record(2, {"tp": 1, "fp": 0, "tn": 0, "fn": 0},
                   {"tp": 0, "fp": 0, "tn": 0, "fn": 1})
        r = paired_cluster_analysis(raw(x, y), bootstrap_draws=200)
        self.assertAlmostEqual(r["mean_difference_pp"], -45)
        self.assertEqual(r["claimed_independent_clusters"], 2)


if __name__ == "__main__":
    unittest.main()
