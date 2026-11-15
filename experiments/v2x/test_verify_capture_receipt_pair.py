"""Adversarial signed-pair verification tests; synthetic data only."""
import hashlib
import json
import unittest

from capture_export_producer import make_manifest, seal_capture, canonical
from verify_capture_receipt_pair import verify_pair
from test_capture_export_producer import ProducerContractTests, EXPORT_KEY, INTERVAL_KEY


class ReceiptPairTests(unittest.TestCase):
    def setUp(self):
        fixture = ProducerContractTests()
        fixture.setUp()
        self.world, self.capture = fixture.world, fixture.capture
        self.manifest = make_manifest(fixture.plan, self.world)
        self.pin = hashlib.sha256(self.manifest).hexdigest()
        self.export, self.interval = seal_capture(
            self.manifest, self.pin, self.world, self.capture,
            EXPORT_KEY, INTERVAL_KEY, capture_complete=True)

    def check(self, export=None, interval=None, pin=None):
        return verify_pair(
            self.world, self.capture, self.manifest, pin or self.pin,
            canonical(self.export) if export is None else export,
            canonical(self.interval) if interval is None else interval,
            EXPORT_KEY, INTERVAL_KEY)

    def test_valid_pair_scored(self):
        report = self.check()
        self.assertTrue(report["receipt_pair_verified"])
        self.assertFalse(report["publication_ready"])
        self.assertEqual((report["tp"], report["fn"]), (1, 1))

    def test_missing_export_fails(self):
        with self.assertRaises(ValueError):
            self.check(export=b"")

    def test_missing_interval_fails(self):
        with self.assertRaises(ValueError):
            self.check(interval=b"")

    def test_duplicate_json_keys_fail(self):
        raw = canonical(self.export).replace(b'"capture_sha256":',
                                             b'"capture_sha256":"forged","capture_sha256":')
        with self.assertRaisesRegex(ValueError, "duplicate"):
            self.check(export=raw)

    def test_mismatched_capture_hash_fails(self):
        bad = dict(self.interval, capture_sha256="0" * 64)
        with self.assertRaisesRegex(ValueError, "different captures"):
            self.check(interval=canonical(bad))

    def test_wrong_external_manifest_pin_fails(self):
        with self.assertRaisesRegex(ValueError, "operator-pinned"):
            self.check(pin="0" * 64)

    def test_unsigned_extra_receipt_field_fails(self):
        bad = dict(self.export, untrusted_field=True)
        with self.assertRaisesRegex(ValueError, "schema"):
            self.check(export=canonical(bad))

    def test_incomplete_receipt_fails_even_if_signed(self):
        export, interval = seal_capture(
            self.manifest, self.pin, self.world, self.capture,
            EXPORT_KEY, INTERVAL_KEY, capture_complete=False)
        with self.assertRaisesRegex(ValueError, "incomplete"):
            self.check(export=canonical(export), interval=canonical(interval))

    def test_tampered_export_hmac_fails(self):
        bad = dict(self.export, hmac_sha256="0" * 64)
        with self.assertRaisesRegex(ValueError, "HMAC"):
            self.check(export=canonical(bad))

    def test_tampered_interval_hmac_fails(self):
        bad = dict(self.interval, hmac_sha256="0" * 64)
        with self.assertRaisesRegex(ValueError, "HMAC"):
            self.check(interval=canonical(bad))


if __name__ == "__main__":
    unittest.main()
