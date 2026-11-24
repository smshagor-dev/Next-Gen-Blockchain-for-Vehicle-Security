"""Regression tests for monotonic ingress deadline bypass conditions."""
import math
import unittest

from hardware_transport_deadlines import DeadlineExpired, deadline_check


class DeadlineSafetyTests(unittest.TestCase):
    def check(self, now=4.0, session_deadline=10.0, auth_deadline=5.0, authenticated=False):
        return deadline_check(now, session_deadline=session_deadline,
                              auth_deadline=auth_deadline, authenticated=authenticated)

    def test_before_auth_deadline(self):
        self.assertIsNone(self.check())

    def test_auth_deadline_boundary(self):
        with self.assertRaisesRegex(DeadlineExpired, 'AUTH_DEADLINE_EXCEEDED'):
            self.check(now=5)

    def test_authenticated_still_obeys_session_deadline(self):
        self.assertIsNone(self.check(now=6, authenticated=True))
        with self.assertRaisesRegex(DeadlineExpired, 'SESSION_DEADLINE_EXCEEDED'):
            self.check(now=10, authenticated=True)

    def test_nonfinite_clock_inputs_rejected(self):
        for field in ('now', 'session_deadline', 'auth_deadline'):
            for value in (math.nan, math.inf, -math.inf):
                with self.subTest(field=field, value=value):
                    with self.assertRaises(DeadlineExpired):
                        self.check(**{field: value})

    def test_type_confusion_rejected(self):
        for field in ('now', 'session_deadline', 'auth_deadline'):
            for value in (True, '4', None, 4j):
                with self.subTest(field=field, value=value):
                    with self.assertRaises(DeadlineExpired):
                        self.check(**{field: value})

    def test_truthy_auth_state_cannot_skip_auth_deadline(self):
        for value in ('false', 1, None):
            with self.subTest(value=value):
                with self.assertRaisesRegex(DeadlineExpired, 'INVALID_AUTH_STATE'):
                    self.check(now=6, authenticated=value)

    def test_auth_deadline_after_session_rejected(self):
        with self.assertRaisesRegex(DeadlineExpired, 'INVALID_DEADLINE_ORDER'):
            self.check(session_deadline=5, auth_deadline=6)

    def test_large_integer_clock_rejected(self):
        with self.assertRaises(DeadlineExpired):
            self.check(now=10**10000)


if __name__ == '__main__':
    unittest.main()
