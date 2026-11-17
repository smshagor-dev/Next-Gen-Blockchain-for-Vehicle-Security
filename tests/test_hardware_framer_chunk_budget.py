"""Bounded chunk admission for authenticated hardware framing.

This is a resource-bound regression, not V2X detection evidence.
"""
import unittest

from hardware_transport_security import AuthenticatedLineFramer, HardwareTransportError


class TestFramerChunkBudget(unittest.TestCase):
    def test_oversized_chunk_fails_before_buffering(self):
        framer = AuthenticatedLineFramer(1024)
        with self.assertRaises(HardwareTransportError) as ctx:
            framer.feed(b"x" * 1025)
        self.assertEqual(ctx.exception.reason, "HW_FRAME_TOO_LARGE")
        self.assertEqual(len(framer._buffer), 0)

    def test_oversized_chunk_discards_prior_partial_frame(self):
        framer = AuthenticatedLineFramer(1024)
        self.assertEqual(framer.feed(b"partial"), [])
        with self.assertRaises(HardwareTransportError):
            framer.feed(b"x" * 1025)
        self.assertEqual(framer.feed(b"ok\n"), [b"ok\n".strip()])

    def test_exact_budget_chunk_can_contain_complete_frames(self):
        framer = AuthenticatedLineFramer(1024)
        data = b"a\n" * 512
        self.assertEqual(framer.feed(data), [b"a"] * 512)
        self.assertEqual(len(framer._buffer), 0)


if __name__ == "__main__":
    unittest.main()
