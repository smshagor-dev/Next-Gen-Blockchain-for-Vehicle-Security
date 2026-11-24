"""Non-actuating loopback contention experiment for bounded TCP admission.

Measures capacity rejection and slot recovery under blocked peers. These are
engineering controls, not independent attack-detection research results.
Run: python -m unittest discover -s tests -p 'test_bounded_tcp_slow_peer_recovery.py' -v
"""
import socket
import threading
import time
import unittest

from bounded_tcp_admission import BoundedTCPAdmission


class SlowPeerRecoveryTests(unittest.TestCase):
    def test_saturation_rejects_and_recovers(self):
        entered = threading.Event()
        release = threading.Event()
        finished = threading.Event()

        def handler(conn):
            entered.set()
            release.wait(timeout=3)
            finished.set()

        admission = BoundedTCPAdmission(handler, max_clients=1)
        peer1, server1 = socket.socketpair()
        peer2, server2 = socket.socketpair()
        peer3, server3 = socket.socketpair()
        try:
            self.assertTrue(admission.dispatch(server1))
            self.assertTrue(entered.wait(2), "worker did not start")
            self.assertFalse(admission.dispatch(server2))
            self.assertEqual(admission.rejected, 1)
            self.assertEqual(admission.active, 1)
            release.set()
            self.assertTrue(finished.wait(2))
            deadline = time.monotonic() + 2
            while admission.active and time.monotonic() < deadline:
                time.sleep(0.005)
            self.assertEqual(admission.active, 0)
            self.assertTrue(admission.dispatch(server3))
        finally:
            release.set()
            peer1.close()
            peer2.close()
            peer3.close()

    def test_handler_failure_releases_capacity(self):
        entered = threading.Event()

        def handler(conn):
            entered.set()
            raise RuntimeError("injected handler fault")

        admission = BoundedTCPAdmission(handler, max_clients=1)
        peer, server = socket.socketpair()
        try:
            self.assertTrue(admission.dispatch(server))
            self.assertTrue(entered.wait(2))
            deadline = time.monotonic() + 2
            while admission.active and time.monotonic() < deadline:
                time.sleep(0.005)
            self.assertEqual(admission.active, 0)
        finally:
            peer.close()

    def test_invalid_capacity_rejected(self):
        for capacity in (0, -1, 65, True, 1.5):
            with self.subTest(capacity=capacity):
                with self.assertRaises(ValueError):
                    BoundedTCPAdmission(lambda conn: None, max_clients=capacity)


if __name__ == "__main__":
    unittest.main()
