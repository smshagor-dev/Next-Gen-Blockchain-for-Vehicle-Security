"""Frame-size and per-recv work controls: safe simulation, no actuation."""
import unittest

from hardware_transport_security import AuthenticatedLineFramer, HardwareTransportError


class StreamingFrameAdmissionTests(unittest.TestCase):
    def test_valid_batch_larger_than_single_frame_limit(self):
        framer = AuthenticatedLineFramer(1024)
        payload = b"v" * 500 + b"\n"
        self.assertEqual(framer.feed(payload * 4), [b"v" * 500] * 4)

    def test_fragmented_frame_and_following_complete_frames(self):
        framer = AuthenticatedLineFramer(1024)
        self.assertEqual(framer.feed(b"a" * 900), [])
        self.assertEqual(framer.feed(b"a" * 100 + b"\nnext\n"), [b"a" * 1000, b"next"])

    def test_partial_overflow_fails_closed_and_resets(self):
        framer = AuthenticatedLineFramer(1024)
        framer.feed(b"a" * 1000)
        with self.assertRaises(HardwareTransportError) as caught:
            framer.feed(b"b" * 25 + b"\n")
        self.assertEqual(caught.exception.reason, "HW_FRAME_TOO_LARGE")
        self.assertEqual(framer.feed(b"ok\n"), [b"ok"])

    def test_many_tiny_frames_have_bounded_output(self):
        framer = AuthenticatedLineFramer(1024)
        with self.assertRaises(HardwareTransportError) as caught:
            framer.feed(b"x\n" * 257)
        self.assertEqual(caught.exception.reason, "HW_FRAME_BATCH_LIMIT_EXCEEDED")
        self.assertEqual(framer.feed(b"ok\n"), [b"ok"])

    def test_oversized_undelimited_recv_never_retained(self):
        framer = AuthenticatedLineFramer(1024)
        with self.assertRaises(HardwareTransportError):
            framer.feed(b"x" * 4096)
        self.assertEqual(framer.feed(b"safe\n"), [b"safe"])


if __name__ == "__main__":
    unittest.main()
