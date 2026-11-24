"""Real loopback, non-actuating admission campaign smoke and boundary tests."""
import unittest

from research_contracts.tcp_loopback_saturation import campaign


class LoopbackCampaignTests(unittest.TestCase):
    def test_saturation_and_recovery(self):
        result = campaign(peers=5, slots=2, hold_seconds=0.01)
        self.assertEqual(result["rejected"], 5)
        self.assertEqual(result["held_connections"], 2)
        self.assertTrue(result["recovered"])
        self.assertGreaterEqual(result["median_dispatch_ms"], 0)

    def test_single_slot(self):
        result = campaign(peers=3, slots=1, hold_seconds=0.01)
        self.assertEqual(result["rejected"], 3)
        self.assertTrue(result["recovered"])

    def test_invalid_bounds(self):
        for peers, slots in ((0, 2), (3, 0), (1025, 1), (2, 65)):
            with self.subTest(peers=peers, slots=slots):
                with self.assertRaises(ValueError):
                    campaign(peers=peers, slots=slots)


if __name__ == "__main__":
    unittest.main()
