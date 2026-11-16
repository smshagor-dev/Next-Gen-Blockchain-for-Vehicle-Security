import hashlib
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "experiments" / "v2x"))
from generate_can_replay_scenario import replay_scenario

RAW = (b"recording_id,frame_index,timestamp_us,can_id,dlc,data_hex\n"
       b"rec1,0,100,123,2,AABB\nrec1,1,110,124,0,\nrec1,2,120,123,2,CCDD\n")
PIN = hashlib.sha256(RAW).hexdigest()


class ReplayScenarioTests(unittest.TestCase):
    def test_replay_is_deterministic_and_pinned(self):
        first, meta = replay_scenario(RAW, PIN, "trial-1", 0, 2, 100)
        second, again = replay_scenario(RAW, PIN, "trial-1", 0, 2, 100)
        self.assertEqual((first, meta), (second, again))
        self.assertEqual(meta["synthetic_replay_frames"], 2)
        self.assertEqual(meta["original_frames"], 3)
        self.assertEqual(first.count(b",1\n"), 2)
        self.assertIn(b"trial-1,3,220,123,2,AABB,0,1", first)
        self.assertIn(b"trial-1,4,230,124,0,,1", first)

    def test_reject_tampered_source(self):
        with self.assertRaises(ValueError):
            replay_scenario(RAW.replace(b"AABB", b"ABAB"), PIN, "x", 0, 1, 1)

    def test_reject_out_of_range(self):
        with self.assertRaises(ValueError):
            replay_scenario(RAW, PIN, "x", 2, 2, 1)

    def test_reject_nonpositive_offset(self):
        with self.assertRaises(ValueError):
            replay_scenario(RAW, PIN, "x", 0, 1, 0)

    def test_reject_duplicate_index(self):
        bad = RAW.replace(b"rec1,1,110", b"rec1,0,110")
        with self.assertRaises(ValueError):
            replay_scenario(bad, hashlib.sha256(bad).hexdigest(), "x", 0, 1, 1)

    def test_reject_mixed_recordings(self):
        bad = RAW.replace(b"rec1,2,120", b"rec2,2,120")
        with self.assertRaises(ValueError):
            replay_scenario(bad, hashlib.sha256(bad).hexdigest(), "x", 0, 1, 1)

    def test_reject_ragged_csv(self):
        bad = RAW + b"rec1,3,130,123,2,AABB,EXTRA\n"
        with self.assertRaises(ValueError):
            replay_scenario(bad, hashlib.sha256(bad).hexdigest(), "x", 0, 1, 1)


if __name__ == "__main__":
    unittest.main()
