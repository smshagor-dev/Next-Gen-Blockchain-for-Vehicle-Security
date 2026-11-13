"""Deterministic deadline boundary checks; synthetic software evidence only."""
import unittest
from hardware_transport_deadlines import deadline_check, DeadlineExpired


class DeadlineBoundaryTests(unittest.TestCase):
    def test_authentication_at_deadline_is_rejected(self):
        with self.assertRaisesRegex(DeadlineExpired, "HW_AUTH_DEADLINE_EXCEEDED"):
            deadline_check(3.0, session_deadline=20.0, auth_deadline=3.0, authenticated=False)

    def test_authenticated_peer_ignores_initial_auth_deadline(self):
        deadline_check(4.0, session_deadline=20.0, auth_deadline=3.0, authenticated=True)

    def test_session_expiry_rejects_authenticated_peer(self):
        with self.assertRaisesRegex(DeadlineExpired, "HW_SESSION_DEADLINE_EXCEEDED"):
            deadline_check(20.0, session_deadline=20.0, auth_deadline=3.0, authenticated=True)

    def test_pre_deadline_is_allowed(self):
        deadline_check(2.99, session_deadline=20.0, auth_deadline=3.0, authenticated=False)


    def test_batched_frames_recheck_session_deadline(self):
        # Each frame must be admitted at processing time, not recv time.
        admitted = []
        for index, now in enumerate((1.0, 1.5, 2.0)):
            try:
                deadline_check(
                    now, session_deadline=2.0, auth_deadline=1.8,
                    authenticated=index > 0,
                )
            except DeadlineExpired:
                break
            admitted.append(index)
        self.assertEqual(admitted, [0, 1])

    def test_batched_first_frame_cannot_authenticate_after_deadline(self):
        # recv may finish before deadline but MAC verification may not.
        with self.assertRaisesRegex(DeadlineExpired, "HW_AUTH_DEADLINE_EXCEEDED"):
            deadline_check(
                3.01, session_deadline=10.0, auth_deadline=3.0,
                authenticated=False,
            )

if __name__ == "__main__":
    unittest.main()
