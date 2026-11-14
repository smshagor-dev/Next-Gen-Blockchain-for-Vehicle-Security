"""Synthetic protocol tests; not independent incidents or physical measurements."""
import csv
import hashlib
import hmac
import io
import json
import unittest

from attested_interval_join import evaluate_interval, receipt_payload

WORLD = ("experiment_id", "scenario_id", "seed", "split", "incident_id", "ground_truth")
CAP = ("experiment_id", "scenario_id", "seed", "split", "incident_id", "node_id", "nonce", "received_at", "session_verified", "alert_relayed")


def csv_data(columns, rows):
    out = io.StringIO(newline="")
    writer = csv.writer(out)
    writer.writerow(columns)
    writer.writerows(rows)
    return out.getvalue().encode()


class SignedIntervalTests(unittest.TestCase):
    def setUp(self):
        self.world = csv_data(WORLD, [("exp", "scene", "5", "test", "hazard", "1"),
                                      ("exp", "scene", "5", "test", "quiet", "0")])
        self.capture = csv_data(CAP, [("exp", "scene", "5", "test", "hazard", "A", "nonce-1",
                                       "2026-01-01T00:00:03Z", "1", "1")])
        self.export_key = b"test-export-secret"
        self.interval_key = b"different-test-window-secret"
        self.window = {"experiment_id": "exp", "scenario_id": "scene", "seed": "5", "split": "test",
                       "window_start": "2026-01-01T00:00:00Z", "window_end": "2026-01-01T00:00:10Z"}

    def run_join(self, *, world=None, capture=None, receipt_change=None, planned_change=None,
                 sign=True, pinned_world=None):
        world = self.world if world is None else world
        capture = self.capture if capture is None else capture
        old_receipt = {"capture_sha256": hashlib.sha256(capture).hexdigest(),
                       "hmac_sha256": hmac.new(self.export_key, capture, hashlib.sha256).hexdigest()}
        window = dict(self.window)
        signed = {"schema_version": 1, "capture_sha256": hashlib.sha256(capture).hexdigest(),
                  **window, "capture_complete": True, "hmac_sha256": "0" * 64}
        signed.update(receipt_change or {})
        if sign:
            signed["hmac_sha256"] = hmac.new(self.interval_key, receipt_payload(signed), hashlib.sha256).hexdigest()
        planned = dict(self.window)
        planned.update(planned_change or {})
        return evaluate_interval(world, capture, old_receipt, self.export_key, signed,
                                 self.interval_key, planned,
                                 pinned_world or hashlib.sha256(world).hexdigest(),
                                 hashlib.sha256(capture).hexdigest())

    def test_valid_in_window(self):
        r = self.run_join()
        self.assertEqual((r["tp"], r["fp"], r["tn"], r["fn"]), (1, 0, 1, 0))
        self.assertTrue(r["interval_receipt_authenticated"])
        self.assertFalse(r["publication_ready"])

    def test_zero_capture_counts_missed_hazard(self):
        r = self.run_join(capture=csv_data(CAP, []))
        self.assertEqual((r["tp"], r["fp"], r["tn"], r["fn"]), (0, 0, 1, 1))

    def test_late_alert_is_not_retroactive(self):
        capture = self.capture.replace(b"00:00:03Z", b"00:00:11Z")
        with self.assertRaisesRegex(ValueError, "outside"):
            self.run_join(capture=capture)

    def test_early_alert_rejected(self):
        capture = self.capture.replace(b"2026-01-01T00:00:03Z", b"2025-12-31T23:59:59Z")
        with self.assertRaisesRegex(ValueError, "outside"):
            self.run_join(capture=capture)

    def test_unsigned_window_edit_rejected(self):
        with self.assertRaisesRegex(ValueError, "HMAC"):
            self.run_join(receipt_change={"window_end": "2026-01-01T00:00:15Z"}, sign=False)

    def test_validly_resigned_posthoc_window_mismatch_rejected(self):
        with self.assertRaisesRegex(ValueError, "operator-selected"):
            self.run_join(receipt_change={"window_end": "2026-01-01T00:00:15Z"})

    def test_mismatched_trial_rejected(self):
        with self.assertRaisesRegex(ValueError, "operator-selected"):
            self.run_join(receipt_change={"seed": "6"})

    def test_incomplete_capture_rejected(self):
        with self.assertRaisesRegex(ValueError, "incomplete"):
            self.run_join(receipt_change={"capture_complete": False})

    def test_boolean_schema_version_rejected(self):
        with self.assertRaisesRegex(ValueError, "version"):
            self.run_join(receipt_change={"schema_version": True})

    def test_nonhex_hmac_rejected(self):
        with self.assertRaisesRegex(ValueError, "HMAC encoding"):
            self.run_join(receipt_change={"hmac_sha256": "☃" * 64}, sign=False)

    def test_capture_receipt_binding_rejected(self):
        with self.assertRaisesRegex(ValueError, "bind this capture"):
            self.run_join(receipt_change={"capture_sha256": "0" * 64})

    def test_naive_capture_time_rejected(self):
        capture = self.capture.replace(b"00:00:03Z", b"00:00:03")
        with self.assertRaisesRegex(ValueError, "timezone"):
            self.run_join(capture=capture)

    def test_wrong_world_digest_rejected(self):
        with self.assertRaisesRegex(ValueError, "operator-pinned"):
            self.run_join(pinned_world="0" * 64)

    def test_empty_or_reversed_window_rejected(self):
        with self.assertRaisesRegex(ValueError, "reversed"):
            self.run_join(receipt_change={"window_end": "2026-01-01T00:00:00Z"},
                          planned_change={"window_end": "2026-01-01T00:00:00Z"})

    def test_capture_trial_mismatch_rejected(self):
        capture = self.capture.replace(b"exp,scene,5,test,hazard", b"exp,scene,6,test,hazard")
        with self.assertRaisesRegex(ValueError, "capture rows"):
            self.run_join(capture=capture)


if __name__ == "__main__":
    unittest.main()
