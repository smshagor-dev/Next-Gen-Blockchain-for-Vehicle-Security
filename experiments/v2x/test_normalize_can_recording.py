"""Synthetic CAN normalization tests: not genuine vehicle or attack evidence."""
import hashlib
import unittest
from normalize_can_recording import normalize

HEADER = b"timestamp_us,can_id,dlc,data_hex\n"
GOOD = HEADER + b"0,7DF,2,0102\n100,1ABCDE,0,\n100,7DF,12,000102030405060708090A0B\n"

class CANNormalizerTests(unittest.TestCase):
    def run_source(self, raw=GOOD, **changes):
        opts = dict(expected_sha256=hashlib.sha256(raw).hexdigest(),
                    recording_id="source-recording-1")
        opts.update(changes)
        return normalize(raw, **opts)

    def test_normalizes_actual_bytes_not_labels(self):
        output, report = self.run_source()
        self.assertIn(b"source-recording-1,2,100,7DF,12,000102030405060708090A0B", output)
        self.assertEqual(report["frame_count"], 3)
        self.assertEqual(report["fd_payload_frames"], 1)
        self.assertFalse(report["publication_ready"])
        self.assertFalse(report["capture_complete"])
        self.assertFalse(report["label_provenance_verified"])

    def test_reproducible_digest(self):
        a, r1 = self.run_source()
        b, r2 = self.run_source()
        self.assertEqual(a, b)
        self.assertEqual(r1["normalized_sha256"], hashlib.sha256(b).hexdigest())
        self.assertEqual(r1, r2)

    def test_raw_tampering_rejected(self):
        with self.assertRaisesRegex(ValueError, "external pin"):
            self.run_source(expected_sha256="0" * 64)

    def test_extra_attack_label_column_rejected(self):
        with self.assertRaisesRegex(ValueError, "unlabeled"):
            self.run_source(HEADER.replace(b"data_hex", b"data_hex,attack_label") +
                            b"0,7DF,1,00,1\n")

    def test_empty_source_rejected(self):
        with self.assertRaisesRegex(ValueError, "empty recording"):
            self.run_source(HEADER)

    def test_decreasing_timestamp_rejected(self):
        with self.assertRaisesRegex(ValueError, "nonmonotonic"):
            self.run_source(HEADER + b"10,123,1,00\n9,123,1,00\n")

    def test_equal_timestamps_permitted(self):
        _, report = self.run_source(HEADER + b"10,123,1,00\n10,124,1,01\n")
        self.assertEqual(report["frame_count"], 2)

    def test_out_of_range_can_identifier(self):
        with self.assertRaisesRegex(ValueError, "identifier"):
            self.run_source(HEADER + b"0,20000000,1,00\n")

    def test_invalid_can_id(self):
        with self.assertRaisesRegex(ValueError, "identifier"):
            self.run_source(HEADER + b"0,nothex,1,00\n")

    def test_invalid_payload_hex(self):
        with self.assertRaisesRegex(ValueError, "payload"):
            self.run_source(HEADER + b"0,123,1,ZZ\n")

    def test_payload_length_mismatch(self):
        with self.assertRaisesRegex(ValueError, "payload"):
            self.run_source(HEADER + b"0,123,2,00\n")

    def test_noncanonical_timestamp(self):
        with self.assertRaisesRegex(ValueError, "timestamp"):
            self.run_source(HEADER + b"00,123,1,00\n")

    def test_invalid_fd_byte_count(self):
        with self.assertRaisesRegex(ValueError, "byte length"):
            self.run_source(HEADER + b"0,123,10,00000000000000000000\n")

    def test_rejects_ragged_csv(self):
        with self.assertRaisesRegex(ValueError, "malformed"):
            self.run_source(HEADER + b"0,123,1,00,unexpected\n")

    def test_bound_rejects_excess_frames(self):
        with self.assertRaisesRegex(ValueError, "frame count"):
            self.run_source(GOOD, frame_limit=2)

    def test_invalid_recording_id(self):
        with self.assertRaisesRegex(ValueError, "recording identifier"):
            self.run_source(recording_id="../bad")

    def test_bom_utf8_supported(self):
        _, report = self.run_source(b"\xef\xbb\xbf" + GOOD)
        self.assertEqual(report["frame_count"], 3)

if __name__ == "__main__":
    unittest.main()
