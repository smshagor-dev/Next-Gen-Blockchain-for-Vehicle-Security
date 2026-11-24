import unittest
from research_contracts.tcp_contention_campaign import campaign, run_trial


class TestTCPContentionCampaign(unittest.TestCase):
    def test_saturation_and_recovery(self):
        result = run_trial(max_clients=2, attempts=9, hold_ms=1)
        self.assertEqual(result["initial_accepted"], 2)
        self.assertEqual(result["rejected_at_saturation"], 7)
        self.assertTrue(result["recovered"])
        self.assertTrue(result["slots_released"])

    def test_repeated_trials(self):
        result = campaign(trials=3, max_clients=1, attempts=4, hold_ms=1)
        self.assertEqual(len(result["trials"]), 3)
        self.assertFalse(result["publication_effectiveness_evidence"])

    def test_invalid_parameters(self):
        with self.assertRaises(ValueError):
            run_trial(max_clients=0)
        with self.assertRaises(ValueError):
            campaign(trials=0)


if __name__ == "__main__":
    unittest.main()
