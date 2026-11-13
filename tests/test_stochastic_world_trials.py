"""Regression tests for synthetic-world V2X study, never physical HIL tests."""
from __future__ import annotations
import csv
import hashlib
import json
import tempfile
import unittest
from pathlib import Path

from experiments.v2x.stochastic_world_trials import (
    POLICIES, _accepted_point, _within_world, make_deliveries,
    make_opportunity, run, summarize, trial,
)

class StochasticWorldTrialsTests(unittest.TestCase):
    def test_zero_report_true_incidents_are_false_negatives(self):
        worlds, delivered, results = trial(2, 2)
        target = [r for r in results if r["scenario"] == "true_zero_capture"]
        self.assertEqual(len(target), 2 * len(POLICIES))
        self.assertTrue(all(r["outcome"] == "FN" for r in target))
        self.assertFalse(any(r["relayed"] for r in target))
        self.assertFalse(any(p["scenario"] == "true_zero_capture" for p in delivered))

    def test_zero_report_negative_opportunities_are_true_negatives(self):
        _, delivered, results = trial(2, 2)
        target = [r for r in results if r["scenario"] == "false_zero_capture"]
        self.assertEqual(len(target), 2 * len(POLICIES))
        self.assertTrue(all(r["outcome"] == "TN" for r in target))
        self.assertFalse(any(p["scenario"] == "false_zero_capture" for p in delivered))

    def test_colluding_enrolled_sources_bypass_quorum(self):
        world = make_opportunity(4, "false_collusion", 0)
        reports = make_deliveries(world)
        self.assertEqual(len(reports), 2)
        for policy in POLICIES:
            self.assertIsNotNone(_accepted_point(policy, reports), policy)

    def test_single_enrolled_attacker_is_not_quorum(self):
        world = make_opportunity(4, "false_single", 0)
        reports = make_deliveries(world)
        self.assertIsNotNone(_accepted_point("authenticated_only", reports))
        self.assertIsNone(_accepted_point("anchor_quorum2", reports))
        self.assertIsNone(_accepted_point("subset_quorum2", reports))

    def test_first_writer_poison_does_not_pin_consistent_subset(self):
        for seed in range(100):
            world = make_opportunity(seed, "true_first_writer", 0)
            reports = make_deliveries(world)
            if sum(x["source_role"] == "honest" for x in reports) >= 2:
                break
        else:
            self.fail("No eligible synthetic first-writer scenario")
        self.assertEqual(reports[0]["source_role"], "malicious")
        self.assertIsNone(_accepted_point("anchor_quorum2", reports))
        accepted = _accepted_point("subset_quorum2", reports)
        self.assertIsNotNone(accepted)
        self.assertTrue(_within_world(accepted, world))

    def test_only_world_rows_have_truth_labels(self):
        worlds, packets, _ = trial(5, 3)
        self.assertTrue(worlds)
        self.assertTrue(packets)
        self.assertTrue(all("world_hazard" in w for w in worlds))
        self.assertTrue(all("world_hazard" not in d for d in packets))
        self.assertTrue(all(d["session_mac_validated"] == "ASSUMED_NOT_EXECUTED" for d in packets))

    def test_reproducibility_and_artifact_digests(self):
        with tempfile.TemporaryDirectory() as left, tempfile.TemporaryDirectory() as right:
            a = run(Path(left), seeds=3, each=3)
            b = run(Path(right), seeds=3, each=3)
            self.assertEqual(a, b)
            self.assertFalse(a["publication_ready"])
            self.assertFalse(a["physical_hardware_validated"])
            self.assertFalse(a["independent_external_incident_labels"])
            m = json.loads((Path(left) / "manifest.json").read_text())
            self.assertFalse(m["publication_ready"])
            for name, expected in m["output_sha256"].items():
                self.assertEqual(
                    hashlib.sha256((Path(left) / name).read_bytes()).hexdigest(), expected
                )
            for name in ("world.csv", "deliveries.csv", "decisions.csv", "summary.json"):
                self.assertEqual((Path(left) / name).read_bytes(), (Path(right) / name).read_bytes())

    def test_disallowed_campaign_sizes(self):
        with tempfile.TemporaryDirectory() as tmp:
            for seeds, each in ((1, 3), (1000, 1), (3, 0), (3, 300)):
                with self.assertRaises(ValueError):
                    run(Path(tmp), seeds=seeds, each=each)

if __name__ == "__main__":
    unittest.main()
