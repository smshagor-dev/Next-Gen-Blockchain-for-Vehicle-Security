"""Real loopback saturation regression; no hardware or blockchain access."""
import socket
import threading
import time
import unittest
from bounded_tcp_admission import BoundedTCPAdmission


class BoundedAdmissionTests(unittest.TestCase):
    def test_rejects_excess_peer_and_recovers_after_release(self):
        entered = threading.Event()
        release = threading.Event()
        completed = threading.Event()

        def handler(conn):
            entered.set()
            release.wait(3)
            completed.set()

        admission = BoundedTCPAdmission(handler, max_clients=1)
        server = socket.socket()
        server.bind(("127.0.0.1", 0))
        server.listen(4)
        server.settimeout(2)
        try:
            first = socket.create_connection(server.getsockname(), timeout=2)
            conn, _ = server.accept()
            self.assertTrue(admission.dispatch(conn))
            self.assertTrue(entered.wait(2))
            second = socket.create_connection(server.getsockname(), timeout=2)
            conn2, _ = server.accept()
            self.assertFalse(admission.dispatch(conn2))
            self.assertEqual(admission.rejected, 1)
            self.assertEqual(admission.active, 1)
            release.set()
            self.assertTrue(completed.wait(2))
            deadline = time.monotonic() + 2
            while admission.active and time.monotonic() < deadline:
                time.sleep(0.01)
            self.assertEqual(admission.active, 0)
            third = socket.create_connection(server.getsockname(), timeout=2)
            conn3, _ = server.accept()
            self.assertTrue(admission.dispatch(conn3))
            first.close()
            second.close()
            third.close()
        finally:
            release.set()
            server.close()

    def test_invalid_limits_fail_closed(self):
        for value in (0, 65, True, "4", -1):
            with self.subTest(value=value):
                with self.assertRaises(ValueError):
                    BoundedTCPAdmission(lambda conn: None, max_clients=value)


if __name__ == "__main__":
    unittest.main()
