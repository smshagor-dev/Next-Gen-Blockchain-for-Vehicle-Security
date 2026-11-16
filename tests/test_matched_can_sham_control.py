"""Synthetic contract tests for equal-horizon offline sham, not efficacy evidence."""
import csv
import hashlib
import io
import unittest

from experiments.v2x.generate_matched_can_sham_control import matched_sham_control

HEADER = "recording_id,frame_index,timestamp_us,can_id,dlc,data_hex\n"
SOURCE = (HEADER + "source,0,100,1A,1,AB\nsource,1,200,1A,1,CD\n").encode()
DONOR = (HEADER + "donor,0,300,2B,1,EF\ndonor,1,400,2B,1,12\n").encode()


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def run(source=SOURCE, donor=DONOR, donor_sha=None, donor_start=0):
    return matched_sham_control(
        source, digest(SOURCE), donor, donor_sha or digest(DONOR),
        "trial1", 0, 1, 10, donor_start)


class MatchedShamTests(unittest.TestCase):
    def test_exact_frame_and_timestamp_match(self):
        attack, control, manifest = run()
        a = list(csv.DictReader(io.StringIO(attack.decode())))
        c = list(csv.DictReader(io.StringIO(control.decode())))
        self.assertEqual(len(a), len(c))
        self.assertEqual([x["timestamp_us"] for x in a],
                         [x["timestamp_us"] for x in c])
        self.assertEqual([x["synthetic_replay"] for x in a], ["0", "0", "1"])
        self.assertEqual([x["synthetic_replay"] for x in c], ["0", "0", "0"])
        self.assertEqual(c[-1]["data_hex"], "EF")
        self.assertEqual(manifest["total_frames_each"], 3)
        self.assertEqual(manifest["donor_benign_status"], "NOT_VERIFIED_BY_THIS_TOOL")

    def test_deterministic(self):
        self.assertEqual(run(), run())

    def test_donor_tamper_rejected(self):
        with self.assertRaises(ValueError):
            run(donor=DONOR.replace(b"EF", b"AA"))

    def test_same_source_rejected(self):
        with self.assertRaises(ValueError):
            run(donor=SOURCE, donor_sha=digest(SOURCE))

    def test_same_recording_id_rejected(self):
        renamed = DONOR.replace(b"donor", b"source")
        with self.assertRaises(ValueError):
            run(donor=renamed, donor_sha=digest(renamed))

    def test_donor_window_overflow_rejected(self):
        with self.assertRaises(ValueError):
            run(donor_start=2)

    def test_non_integer_donor_index_rejected(self):
        with self.assertRaises(ValueError):
            run(donor_start=True)


if __name__ == "__main__":
    unittest.main()
