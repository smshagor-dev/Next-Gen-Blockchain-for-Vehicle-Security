"""Non-actuating worker-start failure controls for bounded TCP ingress."""
import socket
import threading
import time
import unittest
from unittest.mock import patch

from bounded_tcp_admission import BoundedTCPAdmission


class _CloseRaises:
    def __init__(self, sock):
        self.sock = sock
        self.closed = False

    def close(self):
        self.closed = True
        self.sock.close()
        raise OSError("injected close failure")


class WorkerStartFailureTests(unittest.TestCase):
    def test_start_failure_releases_slot_and_rejects_peer(self):
        entered = threading.Event()
        finished = threading.Event()
        def handler(conn):
            entered.set()
            finished.set()
        admission = BoundedTCPAdmission(handler, max_clients=1)
        left, right = socket.socketpair()
        try:
            with patch("bounded_tcp_admission.threading.Thread.start",
                       side_effect=RuntimeError("injected start failure")):
                self.assertFalse(admission.dispatch(left))
            self.assertEqual((admission.active, admission.rejected), (0, 1))
            self.assertEqual(right.recv(1), b"")
            second, peer = socket.socketpair()
            try:
                self.assertTrue(admission.dispatch(second))
                self.assertTrue(entered.wait(2))
                self.assertTrue(finished.wait(2))
                deadline = time.monotonic() + 2
                while admission.active and time.monotonic() < deadline:
                    time.sleep(0.005)
                self.assertEqual(admission.active, 0)
            finally:
                peer.close()
        finally:
            right.close()

    def test_close_failure_does_not_mask_start_failure(self):
        admission = BoundedTCPAdmission(lambda conn: None, max_clients=1)
        left, right = socket.socketpair()
        wrapped = _CloseRaises(left)
        try:
            with patch("bounded_tcp_admission.threading.Thread.start",
                       side_effect=RuntimeError("injected start failure")):
                self.assertFalse(admission.dispatch(wrapped))
            self.assertTrue(wrapped.closed)
            self.assertEqual((admission.active, admission.rejected), (0, 1))
        finally:
            right.close()

    def test_interrupt_propagates_after_releasing_slot(self):
        admission = BoundedTCPAdmission(lambda conn: None, max_clients=1)
        left, right = socket.socketpair()
        try:
            with patch("bounded_tcp_admission.threading.Thread.start",
                       side_effect=KeyboardInterrupt):
                with self.assertRaises(KeyboardInterrupt):
                    admission.dispatch(left)
            self.assertEqual(admission.active, 0)
            another, peer = socket.socketpair()
            try:
                self.assertTrue(admission.dispatch(another))
            finally:
                peer.close()
        finally:
            right.close()


if __name__ == "__main__":
    unittest.main()
