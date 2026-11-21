"""Paired incident design and threat-boundary regression tests."""
import sys
import unittest
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "research_contracts"))
from bench_correlated_group_threats import run, POLICIES


class PairedThreatTests(unittest.TestCase):
    def test_repeatable_complete_pairing(self):
        a = run(17, 40, compromised_groups=1)
        self.assertEqual(a, run(17, 40, compromised_groups=1))
        for i in range(40):
            block = a[4*i:4*i+4]
            self.assertEqual(tuple(r["policy"] for r in block), POLICIES)
            self.assertEqual(len({r["observed_bits"] for r in block}), 1)
            self.assertEqual(len({r["truth_hazard"] for r in block}), 1)

    def test_authentication_primary_is_recorded_and_matches_observation(self):
        rows = run(21, 200, compromised_groups=1)
        primaries = set()
        for i in range(200):
            block = rows[4*i:4*i+4]
            sender = block[0]["auth_primary_sender"]
            self.assertTrue(all(r["auth_primary_sender"] == sender for r in block))
            index = int(sender.removeprefix("device-"))
            self.assertIn(index, range(4))
            primaries.add(index)
            auth = block[0]
            self.assertEqual(auth["policy"], "authentication_only")
            self.assertEqual(auth["admitted"], int(auth["observed_bits"][index]))
        self.assertEqual(primaries, set(range(4)))

    def test_fixed_first_group_no_longer_forced_as_primary(self):
        rows = run(9, 80, compromised_groups=0)
        self.assertTrue(any(r["auth_primary_sender"] != "device-0"
                            for r in rows if r["policy"] == "authentication_only"))

    def test_two_compromised_groups_can_forge_hazard(self):
        rows = run(5, 100, compromised_groups=3, honest_error=0,
                   correlated_error=0)
        robust = [r for r in rows if r["policy"] == "dissent_tolerant_groups"]
        self.assertTrue(any(r["false_admission"] for r in robust))

    def test_no_error_no_compromise(self):
        rows = run(5, 100, compromised_groups=0, honest_error=0,
                   correlated_error=0)
        self.assertTrue(all(not r["false_admission"] and not r["missed_hazard"]
                            for r in rows))

    def test_invalid_nonfinite_probability(self):
        for value in (float("nan"), float("inf"), -0.01, 1.01):
            with self.assertRaises(ValueError):
                run(1, 1, honest_error=value)


if __name__ == "__main__":
    unittest.main()
