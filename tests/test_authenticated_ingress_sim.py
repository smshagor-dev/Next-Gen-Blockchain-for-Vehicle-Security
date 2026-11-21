"""Simulation-only protocol regression tests. Run: python -m unittest discover -s tests -p 'test_authenticated_ingress_sim.py' -v"""
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "experiments" / "v2x"))
from authenticated_ingress_sim import Admission, Reject, encode

KEY = b"simulation-only-key"


class AdmissionTests(unittest.TestCase):
    def setUp(self):
        self.admit = Admission({"car1": KEY})

    def test_fragmented_authentic(self):
        frame = encode("car1", 1, 1000, {"event": "hazard"}, KEY)
        self.assertIsNone(self.admit.feed(frame[:2], 1000))
        self.assertIsNone(self.admit.feed(frame[2:7], 1000))
        self.assertEqual(self.admit.feed(frame[7:], 1000)["sequence"], 1)

    def test_replay(self):
        frame = encode("car1", 1, 1000, {}, KEY)
        self.admit.feed(frame, 1000)
        with self.assertRaisesRegex(Reject, "replay"):
            self.admit.feed(frame, 1000)

    def test_tamper(self):
        frame = encode("car1", 1, 1000, {"x": "safe"}, KEY)
        with self.assertRaisesRegex(Reject, "authentication"):
            self.admit.feed(frame.replace(b"safe", b"evil"), 1000)

    def test_unknown_node(self):
        with self.assertRaises(Reject):
            self.admit.feed(encode("car2", 1, 1000, {}, KEY), 1000)

    def test_stale(self):
        with self.assertRaisesRegex(Reject, "stale"):
            self.admit.feed(encode("car1", 1, 1000, {}, KEY), 7000)

    def test_oversized_length(self):
        with self.assertRaisesRegex(Reject, "frame length"):
            self.admit.feed(b"\\xff\\xff\\xff\\xff", 1000)

    def test_bounded_buffer(self):
        with self.assertRaisesRegex(Reject, "buffer limit"):
            self.admit.feed(b"0" * 4101, 1000)

    def test_sequence_is_node_scoped(self):
        self.admit.keys["car2"] = KEY
        self.admit.feed(encode("car1", 1, 1000, {}, KEY), 1000)
        self.assertEqual(self.admit.feed(encode("car2", 1, 1000, {}, KEY), 1000)["node_id"], "car2")

    def test_trailing_frame_rejected(self):
        f = encode("car1", 1, 1000, {}, KEY)
        with self.assertRaisesRegex(Reject, "multiple"):
            self.admit.feed(f + f, 1000)


if __name__ == "__main__":
    unittest.main()
