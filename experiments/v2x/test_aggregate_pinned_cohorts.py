"""Synthetic contract checks only; not publishable incident observations."""
import csv
import io
import json
import unittest
from aggregate_pinned_cohorts import aggregate, sha


def trial(cluster, rows):
    output = io.StringIO(newline="")
    writer = csv.writer(output, lineterminator="\n")
    writer.writerow(["incident_id", "cluster_id", "truth", "baseline", "candidate"])
    for row in rows:
        writer.writerow((row[0], cluster, *row[1:]))
    return output.getvalue().encode()


class CohortTests(unittest.TestCase):
    def setUp(self):
        self.files = {"t1": trial("c1", [("a", 1, 0, 1), ("b", 0, 0, 0)]),
                      "t2": trial("c2", [("a", 1, 1, 1), ("b", 0, 1, 0)])}
        self.entries = [dict(trial_id=t, cluster_id="c" + str(i),
                             source_group_id="g" + str(i), paired_csv_sha256=sha(raw))
                        for i, (t, raw) in enumerate(self.files.items(), 1)]

    def call(self, entries=None, files=None, pin=None):
        raw = json.dumps({"schema_version": 1,
                          "trials": self.entries if entries is None else entries}).encode()
        return aggregate(raw, self.files if files is None else files,
                         external_pin=sha(raw) if pin is None else pin,
                         repetitions=200, seed=5)

    def test_effect_counts(self):
        result = self.call()
        self.assertEqual((result["clusters"], result["incidents"]), (2, 4))
        self.assertEqual(result["candidate_minus_baseline_accuracy_pp"], 50)
        self.assertEqual(result["candidate_only_correct"], 2)
        self.assertEqual(result["confusion_counts"]["baseline"], {"tp": 1, "tn": 1, "fp": 1, "fn": 1})
        self.assertEqual(result["confusion_counts"]["candidate"], {"tp": 2, "tn": 2, "fp": 0, "fn": 0})
        self.assertFalse(result["publication_ready"])

    def test_reproducible(self):
        self.assertEqual(self.call(), self.call())

    def test_manifest_pin(self):
        with self.assertRaises(ValueError):
            self.call(pin="0" * 64)

    def test_tampered_csv(self):
        with self.assertRaises(ValueError):
            self.call(files={**self.files, "t1": self.files["t1"] + b"\n"})

    def test_reused_cluster(self):
        entries = [dict(x) for x in self.entries]
        entries[1]["cluster_id"] = "c1"
        with self.assertRaises(ValueError):
            self.call(entries=entries)

    def test_reused_source_group(self):
        entries = [dict(x) for x in self.entries]
        entries[1]["source_group_id"] = "g1"
        with self.assertRaises(ValueError):
            self.call(entries=entries)

    def test_missing_trial(self):
        with self.assertRaises(ValueError):
            self.call(files={"t1": self.files["t1"]})

    def test_wrong_cluster_in_csv(self):
        altered = trial("other", [("a", 1, 0, 1), ("b", 0, 0, 0)])
        entries = [dict(x) for x in self.entries]
        entries[0]["paired_csv_sha256"] = sha(altered)
        with self.assertRaises(ValueError):
            self.call(entries=entries, files={**self.files, "t1": altered})

    def test_duplicate_incident(self):
        altered = trial("c1", [("a", 1, 0, 1), ("a", 0, 0, 0)])
        entries = [dict(x) for x in self.entries]
        entries[0]["paired_csv_sha256"] = sha(altered)
        with self.assertRaises(ValueError):
            self.call(entries=entries, files={**self.files, "t1": altered})

    def test_nonbinary_label(self):
        altered = trial("c1", [("a", 2, 0, 1)])
        entries = [dict(x) for x in self.entries]
        entries[0]["paired_csv_sha256"] = sha(altered)
        with self.assertRaises(ValueError):
            self.call(entries=entries, files={**self.files, "t1": altered})

    def test_single_cluster_rejected(self):
        with self.assertRaises(ValueError):
            self.call(entries=self.entries[:1], files={"t1": self.files["t1"]})

    def test_duplicate_manifest_json_key(self):
        raw = b'{"schema_version":1,"schema_version":1,"trials":[]}'
        with self.assertRaises(ValueError):
            aggregate(raw, {}, external_pin=sha(raw))


if __name__ == "__main__":
    unittest.main()
