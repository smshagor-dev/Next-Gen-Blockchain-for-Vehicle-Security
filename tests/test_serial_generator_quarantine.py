"""Regression: serial MAC/framing errors arise when a lazy iterator advances.

Run: python -m unittest discover -s tests -p 'test_serial_generator_quarantine.py' -v
No physical serial device or actuator is accessed.
"""
import contextlib
import io
import unittest
from types import SimpleNamespace
from unittest.mock import patch

from hardware_bridge import _quarantined_serial_frames
from hardware_transport_security import HardwareTransportError


class SerialGeneratorQuarantineTests(unittest.TestCase):
    def test_lazy_bad_mac_is_quarantined_not_leaked(self):
        class BadSession:
            def receive_iter(self, chunk):
                self.assertion = chunk
                if False:
                    yield None
                raise HardwareTransportError("HW_BAD_MAC")
        session = BadSession()
        stream = _quarantined_serial_frames(session, b"invalid\\n")
        # The exception is raised on iteration, not at generator creation.
        with self.assertRaisesRegex(RuntimeError, "serial authentication/framing failure") as caught:
            list(stream)
        self.assertIsInstance(caught.exception.__cause__, HardwareTransportError)

    def test_valid_frame_then_invalid_frame_preserves_streaming(self):
        first = SimpleNamespace(device_id="enrolled-a", payload={"event": "OBS"})
        class MixedSession:
            def receive_iter(self, chunk):
                yield first
                raise HardwareTransportError("HW_BAD_MAC")
        stream = _quarantined_serial_frames(MixedSession(), b"two-frames")
        self.assertIs(next(stream), first)
        with self.assertRaises(RuntimeError):
            next(stream)

    def test_clean_frames_are_delivered_in_order(self):
        a, b = object(), object()
        class GoodSession:
            def receive_iter(self, chunk):
                yield a
                yield b
        self.assertEqual(list(_quarantined_serial_frames(GoodSession(), b"ok")), [a, b])

    def test_unrelated_programming_error_is_not_masked(self):
        class BrokenSession:
            def receive_iter(self, chunk):
                yield None
                raise AssertionError("internal bug")
        stream = _quarantined_serial_frames(BrokenSession(), b"test")
        next(stream)
        with self.assertRaisesRegex(AssertionError, "internal bug"):
            next(stream)


if __name__ == "__main__":
    unittest.main()
