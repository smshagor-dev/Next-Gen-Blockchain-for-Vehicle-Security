"""Non-actuating protocol-model tests, not vehicle experiments."""
import unittest
from research_contracts.paired_anchor_analysis import incident_rows, paired_comparison

class PairedAnchorTests(unittest.TestCase):
    def test_same_incident_faults_for_all_protocols(self):
        rows = list(incident_rows(2, 9, .2, .3, .4))
        self.assertEqual(rows, list(incident_rows(2, 9, .2, .3, .4)))
        self.assertEqual(len(rows), 54)
        for i in range(0, len(rows), 3):
            self.assertEqual(len({(r["local_failure"], r["anchor_failure"],
                                   r["snapshot_restored"]) for r in rows[i:i+3]}), 1)

    def test_rollback_negative_control(self):
        rows = list(incident_rows(2, 4, 0, 0, 1))
        d = paired_comparison(rows, "sqlite_only", "reserve_first",
                              "rollback_replay_accepted")
        self.assertEqual((d["pairs"], d["a_only"], d["b_only"],
                          d["paired_risk_difference"]), (8, 8, 0, 1.0))

    def test_retry_availability_tradeoff(self):
        rows = list(incident_rows(1, 5, 1, 0, 0))
        d = paired_comparison(rows, "reserve_first", "sqlite_only",
                              "valid_retry_rejected")
        self.assertEqual((d["a_only"], d["b_only"]), (5, 0))

    def test_missing_duplicate_and_invalid_rate_fail_closed(self):
        rows = list(incident_rows(1, 1, 0, 0, 0))
        with self.assertRaises(ValueError):
            paired_comparison(rows[:1], "sqlite_only", "reserve_first", "first_accepted")
        with self.assertRaises(ValueError):
            paired_comparison(rows + [rows[0]], "sqlite_only", "reserve_first", "first_accepted")
        with self.assertRaises(ValueError):
            list(incident_rows(1, 1, float("nan"), 0, 0))

if __name__ == "__main__":
    unittest.main()
