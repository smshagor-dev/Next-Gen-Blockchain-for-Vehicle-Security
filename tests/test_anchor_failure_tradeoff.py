"""Protocol-model invariants; not production receiver validation."""
import unittest
from research_contracts.anchor_failure_tradeoff import trial, experiment


class AnchorTradeoffTests(unittest.TestCase):
    def test_sqlite_only_accepts_replay_after_snapshot_restore(self):
        result = trial("sqlite_only", local_failure=False,
                       anchor_failure=False, restore_snapshot=True)
        self.assertEqual(result["rollback_replay_accepted"], 1)

    def test_reserve_first_rejects_replay_with_retained_anchor(self):
        result = trial("reserve_first", local_failure=False,
                       anchor_failure=False, restore_snapshot=True)
        self.assertEqual(result["rollback_replay_accepted"], 0)

    def test_reserve_first_local_failure_consumes_valid_retry(self):
        result = trial("reserve_first", local_failure=True,
                       anchor_failure=False, restore_snapshot=False)
        self.assertEqual(result["valid_retry_rejected"], 1)

    def test_local_first_anchor_outage_consumes_valid_retry(self):
        result = trial("local_first", local_failure=False,
                       anchor_failure=True, restore_snapshot=False)
        self.assertEqual(result["valid_retry_rejected"], 1)

    def test_paired_seed_reproducibility_and_bounds(self):
        a = list(experiment(3, 20, 0.2, 0.1, 0.5))
        self.assertEqual(a, list(experiment(3, 20, 0.2, 0.1, 0.5)))
        self.assertEqual(len(a), 9)
        for row in a:
            self.assertLessEqual(row["rollback_replay_accepted"], 20)

    def test_invalid_rates_rejected(self):
        with self.assertRaises(ValueError):
            list(experiment(1, 10, -0.1, 0, 0))


if __name__ == "__main__":
    unittest.main()
