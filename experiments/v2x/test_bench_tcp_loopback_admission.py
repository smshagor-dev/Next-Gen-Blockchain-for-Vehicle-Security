"""Real localhost socket regressions for admission capacity and recovery."""
import unittest
from bench_tcp_loopback_admission import trial


class LoopbackSaturationTests(unittest.TestCase):
    def test_one_worker_saturation_and_recovery(self):
        report = trial(clients=1, overload=12, hold_seconds=0.005)
        self.assertEqual(report["rejected"], 12)
        self.assertEqual(report["peak_active_handlers"], 1)
        self.assertTrue(report["recovered_after_release"])
        self.assertGreater(report["rejection_roundtrip_median_ms"], 0)

    def test_four_workers_saturation_and_recovery(self):
        report = trial(clients=4, overload=20, hold_seconds=0.005)
        self.assertEqual(report["rejected"], 20)
        self.assertEqual(report["peak_active_handlers"], 4)
        self.assertTrue(report["recovered_after_release"])

    def test_parameter_limits(self):
        for kwargs in ({"clients": 0}, {"clients": 33}, {"clients": True},
                       {"overload": 0}, {"overload": 10001}, {"hold_seconds": -1},
                       {"timeout": 0}):
            with self.subTest(kwargs=kwargs), self.assertRaises(ValueError):
                trial(**kwargs)


if __name__ == "__main__":
    unittest.main()
