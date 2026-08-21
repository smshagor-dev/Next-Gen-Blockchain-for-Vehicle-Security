import unittest

from hil_security_validation import run_validation


class HILSecurityValidationTests(unittest.TestCase):
    def test_all_bounded_hil_scenarios_pass(self):
        report = run_validation()
        self.assertTrue(report.passed)
        self.assertFalse(report.external_hardware_touched)
        self.assertFalse(report.external_network_touched)
        self.assertGreaterEqual(len(report.scenarios), 6)

    def test_safety_critical_scenarios_request_safe_mode(self):
        report = run_validation()
        by_name = {item.name: item for item in report.scenarios}
        for name in ("ledger_tamper", "authenticated_service_spoof", "sensor_integrity_attack"):
            self.assertTrue(by_name[name].safe_mode_requested)
            self.assertEqual(by_name[name].final_action, "SAFE_MODE_REQUEST")
            self.assertEqual(by_name[name].stop_command_count, 1)

    def test_network_attacks_do_not_directly_command_vehicle_stop(self):
        report = run_validation()
        by_name = {item.name: item for item in report.scenarios}
        for name in ("replay_burst", "cross_layer_auth_attack"):
            self.assertTrue(by_name[name].network_isolated)
            self.assertFalse(by_name[name].safe_mode_requested)
            self.assertEqual(by_name[name].final_action, "ISOLATE_NETWORK")
            self.assertEqual(by_name[name].stop_command_count, 0)

    def test_clean_baseline_never_contains(self):
        report = run_validation()
        clean = {item.name: item for item in report.scenarios}["clean_baseline"]
        self.assertTrue(clean.passed)
        self.assertFalse(clean.network_isolated)
        self.assertFalse(clean.safe_mode_requested)
        self.assertEqual(clean.final_action, "NONE")


if __name__ == "__main__":
    unittest.main()
