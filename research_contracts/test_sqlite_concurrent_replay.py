"""Concurrent replay transaction regression tests; simulation-only evidence."""
import os
import tempfile
import threading
import unittest
from sqlite_atomic_replay import SQLiteAtomicReplayGate


class ConcurrentReplayTests(unittest.TestCase):
    def test_same_nonce_has_exactly_one_winner(self):
        with tempfile.TemporaryDirectory() as tmp:
            gate = SQLiteAtomicReplayGate(os.path.join(tmp, "replay.db"))
            barrier = threading.Barrier(16)
            outcomes = []
            errors = []
            lock = threading.Lock()

            def worker():
                try:
                    barrier.wait(timeout=10)
                    accepted = gate.admit_authenticated("enrolled-a", 1, authenticated=True)
                    with lock:
                        outcomes.append(accepted)
                except BaseException as exc:
                    with lock:
                        errors.append(repr(exc))

            threads = [threading.Thread(target=worker) for _ in range(16)]
            for thread in threads:
                thread.start()
            for thread in threads:
                thread.join(timeout=15)
            self.assertFalse(any(thread.is_alive() for thread in threads), "worker deadlock")
            self.assertEqual(errors, [])
            self.assertEqual(outcomes.count(True), 1)
            self.assertEqual(outcomes.count(False), 15)
            gate.close()

    def test_two_connections_compete_on_same_database(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "replay.db")
            a = SQLiteAtomicReplayGate(path)
            b = SQLiteAtomicReplayGate(path)
            barrier = threading.Barrier(2)
            outcomes = []
            errors = []

            def worker(gate):
                try:
                    barrier.wait(timeout=10)
                    outcomes.append(gate.admit_authenticated_batch(
                        [("a", 1), ("b", 1)], authenticated=True))
                except BaseException as exc:
                    errors.append(repr(exc))

            t1 = threading.Thread(target=worker, args=(a,))
            t2 = threading.Thread(target=worker, args=(b,))
            t1.start()
            t2.start()
            t1.join(timeout=15)
            t2.join(timeout=15)
            self.assertFalse(t1.is_alive() or t2.is_alive(), "writer deadlock")
            self.assertEqual(errors, [])
            self.assertEqual(sorted(outcomes), [False, True])
            self.assertEqual(a.connection.execute(
                "SELECT node, seq FROM replay_highwater ORDER BY node").fetchall(),
                [("a", 1), ("b", 1)])
            a.close()
            b.close()

    def test_timeout_validation(self):
        with tempfile.TemporaryDirectory() as tmp:
            for invalid in (0, -1, True, 61, "5"):
                with self.subTest(invalid=invalid):
                    with self.assertRaises(ValueError):
                        SQLiteAtomicReplayGate(os.path.join(tmp, "db.sqlite"), timeout=invalid)


if __name__ == "__main__":
    unittest.main()
