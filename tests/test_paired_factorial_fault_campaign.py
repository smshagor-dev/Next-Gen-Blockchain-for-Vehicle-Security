"""Regression contracts for paired factorial admission experiment."""
import unittest
from research_contracts.paired_factorial_fault_campaign import decide, run, simulate

class CampaignTests(unittest.TestCase):
    def test_reproducible(self):
        self.assertEqual(simulate(17, 8, 1, .1, .2), simulate(17, 8, 1, .1, .2))

    def test_paired_ground_truth(self):
        rows = run([17, 23], 5, [0, 1, 2], .1, .2)
        self.assertEqual(len(rows), 120)
        for key in {(r["seed"], r["incident"], r["compromised_groups"]) for r in rows}:
            subset = [r for r in rows if (r["seed"], r["incident"], r["compromised_groups"]) == key]
            self.assertEqual(len(subset), 4)
            self.assertEqual(len({r["policy"] for r in subset}), 4)
            self.assertEqual(len({r["truth"] for r in subset}), 1)

    def test_same_group_is_not_independent(self):
        self.assertEqual(decide([("a","A",True),("b","A",True),("c","B",False)]),
                         (True, True, False, False))

    def test_dissent_tolerance(self):
        self.assertEqual(decide([("a","A",True),("b","B",True),("c","C",False)]),
                         (True, True, False, True))

    def test_invalid_parameters(self):
        with self.assertRaises(ValueError):
            simulate(1, 10, 1, float("nan"), .1)
        with self.assertRaises(ValueError):
            run([1, 1], 10, [0], .1, .1)

if __name__ == "__main__":
    unittest.main()
