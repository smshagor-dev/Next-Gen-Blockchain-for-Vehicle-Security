"""Bounded-ingress negative controls; no vehicle actuation or network access."""
import unittest

from hardware_transport_security import AuthenticatedLineFramer, HardwareTransportError


class BoundedIngressAllocationTests(unittest.TestCase):
    def test_oversized_single_recv_rejected_before_buffer_copy(self):
        framer = AuthenticatedLineFramer(max_frame_bytes=1024)
        with self.assertRaises(HardwareTransportError) as caught:
            framer.feed(b"x" * (1024 * 1024))
        self.assertEqual(caught.exception.reason, "HW_FRAME_TOO_LARGE")
        self.assertEqual(len(framer._buffer), 0)

    def test_partial_frame_then_oversized_chunk_clears_state(self):
        framer = AuthenticatedLineFramer(max_frame_bytes=1024)
        self.assertEqual(framer.feed(b"x" * 800), [])
        with self.assertRaises(HardwareTransportError):
            framer.feed(b"y" * 300)
        self.assertEqual(len(framer._buffer), 0)

    def test_fragmented_valid_frame_still_accepted(self):
        framer = AuthenticatedLineFramer(max_frame_bytes=1024)
        self.assertEqual(framer.feed(b'{"ok":'), [])
        self.assertEqual(framer.feed(b'true}\n'), [b'{"ok":true}'])

    def test_many_frames_in_single_oversized_recv_fail_closed(self):
        framer = AuthenticatedLineFramer(max_frame_bytes=1024)
        with self.assertRaises(HardwareTransportError):
            framer.feed(b'{}\n' * 400)
        self.assertEqual(len(framer._buffer), 0)


if __name__ == "__main__":
    unittest.main()
