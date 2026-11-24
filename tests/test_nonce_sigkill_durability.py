"""Independent-process crash boundary experiment for the production SQLiteNonceStore.

Simulation-only: no vehicle I/O. Acknowledged claims must survive SIGKILL.
Unacknowledged claims may or may not commit; both outcomes are legal.
Run from repository root: python -m unittest tests.test_nonce_sigkill_durability -v
"""
import multiprocessing as mp
import os
import signal
import tempfile
import unittest

from hardware_nonce_store import SQLiteNonceStore

DEVICE = "simulation-node"
NONCE = "a" * 64


def _worker(path, phase, ready, release):
    store = SQLiteNonceStore(path)
    if phase == "before":
        ready.send("before")
        release.recv()
        store.claim(DEVICE, NONCE, ttl_seconds=300)
    elif phase == "after":
        accepted = store.claim(DEVICE, NONCE, ttl_seconds=300)
        ready.send(("after", accepted))
        release.recv()
    else:
        raise ValueError(phase)
    store.close()


class CrashBoundaryExperiment(unittest.TestCase):
    def _run_phase(self, phase):
        with tempfile.TemporaryDirectory() as folder:
            path = os.path.join(folder, "nonces.sqlite3")
            SQLiteNonceStore(path, provision=True).close()
            parent, child = mp.Pipe()
            proc = mp.Process(target=_worker, args=(path, phase, child, child))
            proc.start()
            try:
                self.assertTrue(parent.poll(10), "worker did not reach barrier")
                marker = parent.recv()
                if phase == "after":
                    self.assertEqual(marker, ("after", True))
                else:
                    self.assertEqual(marker, "before")
                if os.name == "posix":
                    os.kill(proc.pid, signal.SIGKILL)
                else:
                    proc.terminate()
                proc.join(10)
                self.assertFalse(proc.is_alive(), "worker failed to terminate")
                reopened = SQLiteNonceStore(path)
                try:
                    observed = reopened.claim(DEVICE, NONCE, ttl_seconds=300)
                    if phase == "after":
                        self.assertFalse(observed, "ACKNOWLEDGED nonce lost across crash")
                    else:
                        self.assertTrue(observed, "uncommitted nonce was unexpectedly reserved")
                    self.assertFalse(reopened.claim(DEVICE, NONCE, ttl_seconds=300))
                finally:
                    reopened.close()
            finally:
                if proc.is_alive():
                    proc.kill()
                    proc.join()
                parent.close()
                child.close()

    def test_kill_before_claim(self):
        self._run_phase("before")

    def test_kill_after_acknowledged_commit(self):
        self._run_phase("after")


if __name__ == "__main__":
    unittest.main()
