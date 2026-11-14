"""Socket-level partial-frame starvation regression; bench-only, no actuation."""
import socket
import threading
import time
import unittest
from bounded_tcp_admission import BoundedTCPAdmission


class SlowPeerAdmissionTests(unittest.TestCase):
    def test_partial_frame_cannot_block_other_admitted_peer(self):
        slow_entered = threading.Event()
        fast_processed = threading.Event()
        errors = []

        def handler(conn):
            conn.settimeout(0.4)
            try:
                payload = conn.recv(32)
                if payload == b"S":
                    slow_entered.set()
                    # Simulate a peer withholding the rest of its frame.
                    try:
                        conn.recv(32)
                    except socket.timeout:
                        pass
                elif payload == b"FAST":
                    fast_processed.set()
            except Exception as exc:
                errors.append(exc)

        admission = BoundedTCPAdmission(handler, max_clients=2)
        with socket.socket() as listener:
            listener.bind(("127.0.0.1", 0))
            listener.listen(4)
            listener.settimeout(2)
            with socket.create_connection(listener.getsockname(), timeout=2) as slow:
                slow.sendall(b"S")
                accepted, _ = listener.accept()
                self.assertTrue(admission.dispatch(accepted))
                self.assertTrue(slow_entered.wait(1))
                with socket.create_connection(listener.getsockname(), timeout=2) as fast:
                    fast.sendall(b"FAST")
                    accepted, _ = listener.accept()
                    self.assertTrue(admission.dispatch(accepted))
                    self.assertTrue(fast_processed.wait(0.3), "slow peer starved independent worker")
        self.assertEqual(errors, [])

    def test_saturated_slow_peer_is_rejected_without_queue(self):
        entered = threading.Event()
        release = threading.Event()

        def handler(conn):
            entered.set()
            release.wait(1)

        admission = BoundedTCPAdmission(handler, max_clients=1)
        with socket.socket() as listener:
            listener.bind(("127.0.0.1", 0))
            listener.listen(4)
            with socket.create_connection(listener.getsockname(), timeout=2):
                conn, _ = listener.accept()
                self.assertTrue(admission.dispatch(conn))
                self.assertTrue(entered.wait(1))
                with socket.create_connection(listener.getsockname(), timeout=2):
                    conn, _ = listener.accept()
                    self.assertFalse(admission.dispatch(conn))
                    self.assertEqual(admission.rejected, 1)
                    self.assertEqual(admission.active, 1)
                release.set()
                deadline = time.monotonic() + 2
                while admission.active and time.monotonic() < deadline:
                    time.sleep(0.01)
                self.assertEqual(admission.active, 0)


if __name__ == "__main__":
    unittest.main()
