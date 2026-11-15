"""Synthetic parser contract tests, not authentic in-vehicle dataset results."""
import csv
import hashlib
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

from ingest_socketcan_log import convert


def pin(data):
    return hashlib.sha256(data).hexdigest()


GOOD = (b"(1700000000.000001) can0 123#DEADBEEF\n"
        b"(1700000000.000002) can0 1ABCDEF0#\n")


class SocketCanIngestTests(unittest.TestCase):
    def parse(self, raw=GOOD, **kwargs):
        return convert(raw, pinned_sha256=pin(raw), recording_id="vehicle-001", **kwargs)

    def test_normalizes_classic_and_extended_ids(self):
        output, report = self.parse(expected_interface="can0")
        rows = list(csv.DictReader(io.StringIO(output.decode())))
        self.assertEqual(len(rows), 2)
        self.assertEqual(rows[0]["timestamp_ns"], "1700000000000001000")
        self.assertEqual(rows[0]["dlc"], "4")
        self.assertEqual(rows[1]["extended"], "1")
        self.assertEqual(rows[1]["dlc"], "0")
        self.assertEqual(report["frames"], 2)
        self.assertFalse(report["publication_ready"])
        self.assertEqual(report["normalized_sha256"], pin(output))

    def test_source_pin_mismatch(self):
        with self.assertRaisesRegex(ValueError, "does not match"):
            convert(GOOD, pinned_sha256="0"*64, recording_id="vehicle-001")

    def test_invalid_pin_format(self):
        with self.assertRaisesRegex(ValueError, "external source"):
            convert(GOOD, pinned_sha256="bogus", recording_id="vehicle-001")

    def test_reject_empty(self):
        with self.assertRaisesRegex(ValueError, "empty recording"):
            self.parse(b"")

    def test_reject_rtr(self):
        with self.assertRaisesRegex(ValueError, "unsupported"):
            self.parse(b"(1700000000.1) can0 123#R8\n")

    def test_reject_can_fd(self):
        with self.assertRaisesRegex(ValueError, "unsupported"):
            self.parse(b"(1700000000.1) can0 123##1DEADBEEF\n")

    def test_reject_bad_payload(self):
        with self.assertRaisesRegex(ValueError, "unsupported"):
            self.parse(b"(1700000000.1) can0 123#ABC\n")

    def test_reject_id_out_of_range(self):
        with self.assertRaisesRegex(ValueError, "out-of-range"):
            self.parse(b"(1700000000.1) can0 FFFFFFFF#00\n")

    def test_reject_nonchronological(self):
        raw = (b"(1700000000.2) can0 123#00\n"
               b"(1700000000.1) can0 123#01\n")
        with self.assertRaisesRegex(ValueError, "nonchronological"):
            self.parse(raw)

    def test_reject_mixed_interface(self):
        with self.assertRaisesRegex(ValueError, "unexpected interface"):
            self.parse(GOOD.replace(b"can0", b"can1", 1), expected_interface="can0")

    def test_reject_non_ascii(self):
        with self.assertRaisesRegex(ValueError, "ASCII"):
            self.parse(GOOD + b"\xff")

    def test_reject_extra_untrusted_line(self):
        with self.assertRaisesRegex(ValueError, "unsupported"):
            self.parse(GOOD + b"exec arbitrary command\n")

    def test_reject_recording_id_injection(self):
        with self.assertRaisesRegex(ValueError, "recording ID"):
            convert(GOOD, pinned_sha256=pin(GOOD), recording_id="=HYPERLINK(1)")

    def test_reject_oversized_input(self):
        with self.assertRaisesRegex(ValueError, "64 MiB"):
            self.parse(b"x" * (64*1024*1024+1))

    def test_reject_more_than_million_frames(self):
        # A bounded input can still contain too many short valid lines.
        raw = b"(1.0) c 123#\n" * 1000001
        with self.assertRaisesRegex(ValueError, "frame count"):
            self.parse(raw)

    def test_deterministic_bytes(self):
        self.assertEqual(self.parse()[0], self.parse()[0])

    def test_cli_end_to_end(self):
        with tempfile.TemporaryDirectory() as tmp:
            d = Path(tmp)
            source, out, report = d/"input.log", d/"out.csv", d/"report.json"
            source.write_bytes(GOOD)
            command = [sys.executable, str(Path(__file__).with_name("ingest_socketcan_log.py")),
                       "--input", str(source), "--raw-sha256", pin(GOOD),
                       "--recording-id", "vehicle-001", "--interface", "can0",
                       "--output-csv", str(out), "--output-report", str(report)]
            subprocess.run(command, check=True, capture_output=True, text=True)
            self.assertEqual(json.loads(report.read_text())["frames"], 2)
            self.assertEqual(list(csv.DictReader(out.open()))[0]["data_hex"], "DEADBEEF")
            failed = subprocess.run(command, capture_output=True, text=True)
            self.assertNotEqual(failed.returncode, 0)
            self.assertIn("refuse to overwrite", failed.stderr)


if __name__ == "__main__":
    unittest.main()
