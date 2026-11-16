"""Synthetic contract checks; not research efficacy observations."""
import csv
import hashlib
import io
import unittest

try:
    from experiments.v2x.generate_paired_can_replay_control import paired_control
except ImportError:
    from generate_paired_can_replay_control import paired_control

HEADER = "recording_id,frame_index,timestamp_us,can_id,dlc,data_hex\n"
SOURCE = (HEADER + "r1,0,100,1A,1,AB\nr1,1,200,1A,1,CD\n").encode()


class PairedReplayControlTests(unittest.TestCase):
    def generate(self, raw=SOURCE, digest=None):
        return paired_control(raw, digest or hashlib.sha256(SOURCE).hexdigest(), "trial1", 0, 1, 10)

    def test_paired_source_and_counts(self):
        attack, control, m = self.generate()
        a = list(csv.DictReader(io.StringIO(attack.decode())))
        c = list(csv.DictReader(io.StringIO(control.decode())))
        self.assertEqual((len(a), len(c)), (3, 2))
        self.assertEqual([r["synthetic_replay"] for r in a], ["0", "0", "1"])
        self.assertTrue(all(r["synthetic_replay"] == "0" for r in c))
        self.assertEqual(m["control_injected_frames"], 0)
        self.assertEqual(m["attack_injected_frames"], 1)
        self.assertEqual(hashlib.sha256(attack).hexdigest(), m["attack_sha256"])
        self.assertEqual(hashlib.sha256(control).hexdigest(), m["control_sha256"])

    def test_determinism(self):
        self.assertEqual(self.generate(), self.generate())

    def test_tampered_source_fails(self):
        with self.assertRaises(ValueError):
            self.generate(raw=SOURCE.replace(b"AB", b"AA"))

    def test_out_of_range_replay_fails(self):
        with self.assertRaises(ValueError):
            paired_control(SOURCE, hashlib.sha256(SOURCE).hexdigest(), "trial1", 2, 1, 10)

    def test_bad_scenario_id_fails(self):
        with self.assertRaises(ValueError):
            paired_control(SOURCE, hashlib.sha256(SOURCE).hexdigest(), "../bad", 0, 1, 10)


if __name__ == "__main__":
    unittest.main()
