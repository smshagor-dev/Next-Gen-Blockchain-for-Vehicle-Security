"""Methodology guards for paired synthetic admission baselines."""
import unittest
from research_contracts.bench_evidence_baselines import experiment


class PairedEvidenceBaselineTests(unittest.TestCase):
    def test_same_incidents_and_truth_for_every_policy(self):
        rows = experiment(seed=17, trials=100, witnesses=4, compromised_devices=1)
        self.assertEqual(len(rows), 300)
        for incident in range(100):
            paired = [r for r in rows if r["incident"] == incident]
            self.assertEqual(len(paired), 3)
            self.assertEqual(len({r["truth_hazard"] for r in paired}), 1)
            self.assertEqual(len({r["policy"] for r in paired}), 3)

    def test_reproducibility_and_no_actuation(self):
        self.assertEqual(experiment(seed=2, trials=10), experiment(seed=2, trials=10))

    def test_invalid_parameters(self):
        for params in ({"trials": 1}, {"witnesses": 1},
                       {"compromised_devices": -1},
                       {"witnesses": 2, "compromised_devices": 3}):
            with self.subTest(params=params):
                with self.assertRaises(ValueError):
                    experiment(**params)


if __name__ == "__main__":
    unittest.main()
