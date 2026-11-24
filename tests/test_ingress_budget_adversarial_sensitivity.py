"""Synthetic controls for the post-authentication admission sensitivity model."""
import unittest
from research_contracts.ingress_budget_adversarial_sensitivity import simulate


class BudgetSensitivityTests(unittest.TestCase):
    def test_repeatable_seed(self):
        self.assertEqual(simulate(seed=19), simulate(seed=19))

    def test_global_capacity_bound(self):
        for seed in range(10):
            result = simulate(seed=seed, policy="global", seconds=7, capacity=5)
            self.assertLessEqual(result["admitted_total"], 35)

    def test_per_identity_capacity_bound(self):
        for seed in range(10):
            result = simulate(seed=seed, policy="per_identity", seconds=7, capacity=5)
            self.assertLessEqual(result["admitted_total"], 35)

    def test_no_adversaries(self):
        result = simulate(adversaries=0, honest=2, honest_rate=2,
                          capacity=8, policy="global")
        self.assertEqual(result["honest_admission_fraction"], 1.0)

    def test_zero_honest_offers_explicit_null(self):
        result = simulate(honest_rate=0)
        self.assertIsNone(result["honest_admission_fraction"])

    def test_invalid_configuration(self):
        with self.assertRaises(ValueError):
            simulate(capacity=0)
        with self.assertRaises(ValueError):
            simulate(policy="bogus")

    def test_unlimited_is_not_a_capacity_baseline(self):
        result = simulate(policy="unlimited", capacity=1)
        self.assertGreater(result["admitted_total"], result["seconds"])


if __name__ == "__main__":
    unittest.main()
