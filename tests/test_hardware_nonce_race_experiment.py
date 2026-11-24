"""Process-level concurrency regression; deliberately no physical hardware."""
import unittest
from research_contracts.hardware_nonce_race_experiment import run_round


class NonceRaceExperimentTests(unittest.TestCase):
    def test_single_winner_across_independent_processes(self):
        result = run_round(4)
        self.assertEqual(result["accepted"], 1)
        self.assertEqual(result["replayed"], 3)
        self.assertEqual(result["errors"], [])
        self.assertTrue(result["restart_rejected"])
        self.assertTrue(all(code == 0 for code in result["exitcodes"]))


if __name__ == "__main__":
    unittest.main()
