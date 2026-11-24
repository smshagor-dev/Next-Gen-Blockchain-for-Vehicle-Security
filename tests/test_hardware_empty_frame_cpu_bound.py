"""Adversarial CPU-work bounds for newline-only TCP receive batches.

These tests exercise protocol framing only; they do not establish network-level
DoS resistance, actuator safety, or publication-ready attack effectiveness.
"""
import unittest

from hardware_transport_security import AuthenticatedLineFramer, HardwareTransportError


class EmptyLineAdmissionTests(unittest.TestCase):
    def test_256_empty_delimiters_are_bounded_and_accepted(self):
        framer = AuthenticatedLineFramer(1024)
        self.assertEqual(framer.feed(b"\n" * 256), [])
        self.assertEqual(framer.feed(b'{"x":1}\n'), [b'{"x":1}'])

    def test_257_empty_delimiters_rejected_and_state_cleared(self):
        framer = AuthenticatedLineFramer(1024)
        with self.assertRaises(HardwareTransportError) as error:
            framer.feed(b"\n" * 257)
        self.assertEqual(error.exception.reason, "HW_FRAME_BATCH_LIMIT_EXCEEDED")
        self.assertEqual(framer.feed(b"ok\n"), [b"ok"])

    def test_mixed_empty_and_nonempty_delimiters_share_budget(self):
        framer = AuthenticatedLineFramer(1024)
        with self.assertRaises(HardwareTransportError) as error:
            framer.feed(b"\n" * 255 + b"a\n" + b"b\n")
        self.assertEqual(error.exception.reason, "HW_FRAME_BATCH_LIMIT_EXCEEDED")
        self.assertEqual(framer.feed(b"valid\n"), [b"valid"])

    def test_fragmented_incomplete_frame_preserved(self):
        framer = AuthenticatedLineFramer(1024)
        self.assertEqual(framer.feed(b"abc"), [])
        self.assertEqual(framer.feed(b"def\n"), [b"abcdef"])


if __name__ == "__main__":
    unittest.main()
