"""Non-actuating adversarial admission tests. No vehicle hardware access."""
import threading
import unittest
from unittest.mock import Mock

from bounded_tcp_admission import BoundedTCPAdmission


class RejectedCloseSocket:
    def close(self):
        raise OSError("simulated peer close failure")


class AdmissionRejectionIsolationTests(unittest.TestCase):
    def test_saturated_close_failure_does_not_abort_dispatch(self):
        entered = threading.Event()
        release = threading.Event()
        finished = threading.Event()

        def handler(_conn):
            entered.set()
            release.wait(2)
            finished.set()

        class ActiveSocket:
            def __enter__(self):
                return self
            def __exit__(self, *_):
                return False

        admission = BoundedTCPAdmission(handler, max_clients=1)
        self.assertTrue(admission.dispatch(ActiveSocket()))
        try:
            self.assertTrue(entered.wait(2), "worker did not enter")
            self.assertFalse(admission.dispatch(RejectedCloseSocket()))
            self.assertEqual(admission.rejected, 1)
            self.assertEqual(admission.active, 1)
        finally:
            release.set()
        self.assertTrue(finished.wait(2))
        # A completed worker must return its slot for the next peer.
        for _ in range(100):
            if admission.active == 0:
                break
            threading.Event().wait(.01)
        self.assertEqual(admission.active, 0)
        self.assertTrue(admission.dispatch(ActiveSocket()))

    def test_reject_invalid_client_limits(self):
        for limit in (0, 65, True, 1.5, "4"):
            with self.subTest(limit=limit), self.assertRaises(ValueError):
                BoundedTCPAdmission(lambda conn: None, max_clients=limit)


if __name__ == "__main__":
    unittest.main()
