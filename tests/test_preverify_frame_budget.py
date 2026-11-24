"""Regression: per-session quotas reject before durable replay nonce claims."""
import unittest
from unittest.mock import Mock

from hardware_bridge import AuthenticatedPiTelemetrySession
from hardware_transport_security import HardwareTransportError


class PreverifyBudgetTests(unittest.TestCase):
    def make_session(self, frames):
        verifier = Mock()
        verifier.max_frame_bytes = 4096
        verifier.verify.side_effect = lambda frame, **kwargs: Mock(device_id="node-a", payload={})
        session = AuthenticatedPiTelemetrySession(verifier)
        session.framer = Mock()
        session.framer.feed.return_value = frames
        return session, verifier

    def test_zero_remaining_does_not_verify_or_claim(self):
        session, verifier = self.make_session([b"frame"])
        with self.assertRaisesRegex(HardwareTransportError, "HW_SESSION_FRAME_BUDGET_EXCEEDED"):
            list(session.receive_iter(b"ignored", remaining_frames=0))
        verifier.verify.assert_not_called()

    def test_batched_overflow_verifies_only_allowed_frame(self):
        session, verifier = self.make_session([b"first", b"second"])
        iterator = session.receive_iter(b"ignored", remaining_frames=1)
        self.assertEqual(next(iterator).device_id, "node-a")
        with self.assertRaisesRegex(HardwareTransportError, "HW_SESSION_FRAME_BUDGET_EXCEEDED"):
            next(iterator)
        self.assertEqual(verifier.verify.call_count, 1)

    def test_unlimited_legacy_api_still_verifies_all(self):
        session, verifier = self.make_session([b"first", b"second"])
        self.assertEqual(len(session.receive(b"ignored")), 2)
        self.assertEqual(verifier.verify.call_count, 2)

    def test_partial_frame_has_no_verification(self):
        session, verifier = self.make_session([])
        self.assertEqual(list(session.receive_iter(b"partial", remaining_frames=0)), [])
        verifier.verify.assert_not_called()


if __name__ == "__main__":
    unittest.main()
