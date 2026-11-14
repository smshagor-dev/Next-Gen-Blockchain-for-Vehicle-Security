"""Regression: serial ingress must not reintroduce unsigned JSON fallback.

These are source-level invariants; transport MAC/replay behavior is covered by
tests/test_arduino_authenticated_ingress.py. No hardware is accessed.
"""
import inspect
import unittest

from hardware_bridge import run_arduino_mode


class SerialAuthenticatedOnlyTests(unittest.TestCase):
    def test_arduino_ingress_uses_authenticated_session(self):
        source = inspect.getsource(run_arduino_mode)
        self.assertIn("AuthenticatedPiTelemetrySession(verifier)", source)
        self.assertIn("session.receive(chunk)", source)
        self.assertIn("except HardwareTransportError", source)
        self.assertNotIn("read_bounded_serial_json", source)
        self.assertNotIn("json.loads(", source)

    def test_arduino_ingress_is_bounded_and_quarantines(self):
        source = inspect.getsource(run_arduino_mode)
        self.assertIn("ser.read(1024)", source)
        self.assertIn("max_session_sec", source)
        self.assertIn("idle_timeout", source)
        self.assertIn("ser.close()", source)


if __name__ == "__main__":
    unittest.main()
