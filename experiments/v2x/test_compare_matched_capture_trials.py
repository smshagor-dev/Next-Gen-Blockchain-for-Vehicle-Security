"""Synthetic fail-closed contract tests. Not independent research evidence."""
import csv
import hashlib
import hmac
import io
import json
import unittest

from attested_interval_join import receipt_payload
from compare_matched_capture_trials import compare, sha256
from join_world_incidents import CAPTURE_COLUMNS, WORLD_COLUMNS


def csv_bytes(fields, rows):
    out = io.StringIO(newline="")
    writer = csv.writer(out, lineterminator="\n")
    writer.writerow(fields)
    writer.writerows(rows)
    return out.getvalue().encode()


class MatchedCaptureTests(unittest.TestCase):
    def setUp(self):
        self.world = csv_bytes(WORLD_COLUMNS, [
            ("exp", "scenario", "seed9", "test", "hazard-a", "1"),
            ("exp", "scenario", "seed9", "test", "hazard-b", "1"),
            ("exp", "scenario", "seed9", "test", "normal", "0"),
        ])
        self.w = {"experiment_id": "exp", "scenario_id": "scenario", "seed": "seed9", "split": "test",
                  "window_start": "2026-11-15T00:00:00Z", "window_end": "2026-11-15T00:05:00Z"}
        self.b_rows = [self.row("hazard-a", "b1")]
        self.c_rows = [self.row("hazard-a", "c1"), self.row("hazard-b", "c2")]
        self.b_capture = csv_bytes(CAPTURE_COLUMNS, self.b_rows)
        self.c_capture = csv_bytes(CAPTURE_COLUMNS, self.c_rows)
        self.keys = (b"baseline-export-secret", b"candidate-export-secret",
                     b"baseline-interval-secret", b"candidate-interval-secret")

    def row(self, incident, nonce, *, stamp="2026-11-15T00:01:00Z", verified="1", relayed="1", scenario="scenario"):
        return ("exp", scenario, "seed9", "test", incident, "node-1", nonce,
                stamp, verified, relayed)

    def receipts(self, capture, export_key, interval_key, window=None, *, complete=True):
        w = self.w if window is None else window
        export = {"capture_sha256": sha256(capture),
                  "hmac_sha256": hmac.new(export_key, capture, hashlib.sha256).hexdigest()}
        interval = {"schema_version": 1, "capture_sha256": sha256(capture),
                    **w, "capture_complete": complete, "hmac_sha256": "0" * 64}
        interval["hmac_sha256"] = hmac.new(interval_key, receipt_payload(interval), hashlib.sha256).hexdigest()
        return json.dumps(export).encode(), json.dumps(interval).encode()

    def invoke(self, *, world=None, b_capture=None, c_capture=None, b_receipts=None,
               c_receipts=None, window=None, window_pin=None, world_pin=None,
               baseline_pin=None, candidate_pin=None):
        world = self.world if world is None else world
        b_capture = self.b_capture if b_capture is None else b_capture
        c_capture = self.c_capture if c_capture is None else c_capture
        b_exp, c_exp, b_interval, c_interval = self.keys
        bx, bi = b_receipts if b_receipts is not None else self.receipts(b_capture, b_exp, b_interval)
        cx, ci = c_receipts if c_receipts is not None else self.receipts(c_capture, c_exp, c_interval)
        wr = json.dumps(self.w, sort_keys=True).encode() if window is None else window
        return compare(world, b_capture, c_capture, bx, cx, bi, ci,
                       b_exp, c_exp, b_interval, c_interval, wr,
                       world_pin=sha256(world) if world_pin is None else world_pin,
                       baseline_pin=sha256(b_capture) if baseline_pin is None else baseline_pin,
                       candidate_pin=sha256(c_capture) if candidate_pin is None else candidate_pin,
                       window_pin=sha256(wr) if window_pin is None else window_pin)

    def test_same_world_universe_and_missing_positive_are_scored(self):
        report, raw = self.invoke()
        self.assertEqual(report["incidents"], 3)
        self.assertEqual(report["baseline"], {"tp": 1, "tn": 1, "fp": 0, "fn": 1, "incidents_not_received": 2})
        self.assertEqual(report["candidate"], {"tp": 2, "tn": 1, "fp": 0, "fn": 0, "incidents_not_received": 1})
        self.assertAlmostEqual(report["candidate_minus_baseline_accuracy_pp"], 100 / 3)
        self.assertEqual(report["independent_clusters_in_this_file"], 1)
        self.assertFalse(report["publication_ready"])
        self.assertEqual(report["paired_csv_sha256"], sha256(raw))
        reader = list(csv.DictReader(io.StringIO(raw.decode())))
        self.assertEqual(len(reader), 3)
        self.assertEqual(len({r["cluster_id"] for r in reader}), 1)
        self.assertEqual(len({r["incident_id"] for r in reader}), 3)

    def test_signed_empty_candidate_capture_keeps_missed_incidents(self):
        empty = csv_bytes(CAPTURE_COLUMNS, [])
        report, _ = self.invoke(c_capture=empty)
        self.assertEqual(report["candidate"]["fn"], 2)
        self.assertEqual(report["candidate"]["tn"], 1)
        self.assertEqual(report["candidate"]["incidents_not_received"], 3)

    def test_false_positive_counted_from_world_negative(self):
        more = csv_bytes(CAPTURE_COLUMNS, self.c_rows + [self.row("normal", "c3")])
        report, _ = self.invoke(c_capture=more)
        self.assertEqual(report["candidate"]["fp"], 1)

    def test_capture_integrity_pin_rejects_mutation(self):
        with self.assertRaisesRegex(ValueError, "baseline SHA-256 pin"):
            self.invoke(baseline_pin="0" * 64)

    def test_window_pin_rejects_mutation(self):
        with self.assertRaisesRegex(ValueError, "expected window SHA-256 pin"):
            self.invoke(window_pin="0" * 64)

    def test_wrong_export_hmac_rejected(self):
        bx, bi = self.receipts(self.b_capture, *self.keys[::2])
        altered = json.loads(bx)
        altered["hmac_sha256"] = "0" * 64
        with self.assertRaises(ValueError):
            self.invoke(b_receipts=(json.dumps(altered).encode(), bi))

    def test_incomplete_signed_capture_fails_closed(self):
        bx, bi = self.receipts(self.b_capture, self.keys[0], self.keys[2], complete=False)
        with self.assertRaisesRegex(ValueError, "incomplete"):
            self.invoke(b_receipts=(bx, bi))

    def test_signed_but_different_capture_window_rejected(self):
        shifted = {**self.w, "window_end": "2026-11-15T00:06:00Z"}
        bx, bi = self.receipts(self.b_capture, self.keys[0], self.keys[2], shifted)
        with self.assertRaisesRegex(ValueError, "differs"):
            self.invoke(b_receipts=(bx, bi))

    def test_relay_outside_window_rejected_not_clipped(self):
        late = csv_bytes(CAPTURE_COLUMNS, [self.row("hazard-a", "b1", stamp="2026-11-15T00:05:00Z")])
        with self.assertRaisesRegex(ValueError, "outside"):
            self.invoke(b_capture=late)

    def test_unverified_relay_rejected(self):
        bad = csv_bytes(CAPTURE_COLUMNS, [self.row("hazard-a", "b1", verified="0")])
        with self.assertRaisesRegex(ValueError, "unverified relay"):
            self.invoke(b_capture=bad)

    def test_replayed_nonce_rejected(self):
        bad = csv_bytes(CAPTURE_COLUMNS, [self.row("hazard-a", "same"), self.row("hazard-b", "same")])
        with self.assertRaisesRegex(ValueError, "nonce"):
            self.invoke(b_capture=bad)

    def test_capture_from_another_trial_is_rejected(self):
        bad = csv_bytes(CAPTURE_COLUMNS, [self.row("hazard-a", "b1", scenario="other")])
        with self.assertRaises(ValueError):
            self.invoke(b_capture=bad)

    def test_duplicate_world_incident_rejected(self):
        dup = csv_bytes(WORLD_COLUMNS, [
            ("exp", "scenario", "seed9", "test", "hazard-a", "1"),
            ("exp", "scenario", "seed9", "test", "hazard-a", "0"),
        ])
        with self.assertRaisesRegex(ValueError, "duplicate"):
            self.invoke(world=dup)

    def test_world_group_mismatch(self):
        other = csv_bytes(WORLD_COLUMNS, [
            ("exp", "other", "seed9", "test", "hazard-a", "1"),
        ])
        with self.assertRaises(ValueError):
            self.invoke(world=other)

    def test_train_split_disallowed_even_with_valid_digest(self):
        raw = json.dumps({**self.w, "split": "train"}).encode()
        with self.assertRaisesRegex(ValueError, "held-out"):
            self.invoke(window=raw)

    def test_duplicate_window_json_key_rejected(self):
        raw = json.dumps(self.w).encode().replace(b'"seed": "seed9"', b'"seed": "seed9", "seed": "overwritten"')
        with self.assertRaisesRegex(ValueError, "duplicate JSON key"):
            self.invoke(window=raw)

    def test_empty_world_denominator_rejected(self):
        with self.assertRaises(ValueError):
            self.invoke(world=csv_bytes(WORLD_COLUMNS, []))

    def test_duplicate_capture_identity_cannot_expand_denominator(self):
        # Different nonces, same incident, both relayed: incident counted once.
        more = csv_bytes(CAPTURE_COLUMNS, self.c_rows + [self.row("hazard-a", "c3")])
        report, raw = self.invoke(c_capture=more)
        self.assertEqual(report["candidate"]["tp"], 2)
        self.assertEqual(len(list(csv.DictReader(io.StringIO(raw.decode())))), 3)


if __name__ == "__main__":
    unittest.main()
