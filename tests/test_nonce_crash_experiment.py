"""Process-boundary SQLite nonce crash experiment (not power-loss evidence)."""
import multiprocessing as mp
import tempfile
import unittest
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from hardware_nonce_store import SQLiteNonceStore, NonceStoreError

DEVICE = "pi-bench-01"
NONCE = "a1" * 16

def _claim_then_wait(path, ready):
    store = SQLiteNonceStore(path)
    try:
        ready.send("committed" if store.claim(DEVICE, NONCE, ttl_seconds=60) else "rejected")
        ready.close()
        import time
        time.sleep(30)
    finally:
        store.close()

class NonceCrashExperiment(unittest.TestCase):
    def test_killed_process_cannot_replay_committed_nonce(self):
        with tempfile.TemporaryDirectory() as root:
            path = str(Path(root) / "nonces.db")
            SQLiteNonceStore(path, provision=True).close()
            ctx = mp.get_context("spawn")
            reader, writer = ctx.Pipe(duplex=False)
            child = ctx.Process(target=_claim_then_wait, args=(path, writer))
            child.start()
            writer.close()
            try:
                self.assertTrue(reader.poll(10), "child did not acknowledge commit")
                self.assertEqual(reader.recv(), "committed")
            finally:
                child.terminate()
                child.join(10)
                if child.is_alive():
                    child.kill()
                    child.join(5)
                reader.close()
            self.assertFalse(child.is_alive())
            reopened = SQLiteNonceStore(path)
            try:
                self.assertFalse(reopened.claim(DEVICE, NONCE, ttl_seconds=60))
            finally:
                reopened.close()

    def test_concurrent_same_nonce_has_exactly_one_winner(self):
        with tempfile.TemporaryDirectory() as root:
            store = SQLiteNonceStore(str(Path(root) / "nonces.db"), provision=True)
            try:
                with ThreadPoolExecutor(max_workers=12) as pool:
                    results = list(pool.map(
                        lambda _: store.claim(DEVICE, NONCE, ttl_seconds=60), range(64)
                    ))
                self.assertEqual(sum(results), 1)
            finally:
                store.close()

    def test_capacity_exhaustion_is_fail_closed_after_reopen(self):
        with tempfile.TemporaryDirectory() as root:
            path = str(Path(root) / "nonces.db")
            store = SQLiteNonceStore(path, provision=True, max_claims=1)
            self.assertTrue(store.claim(DEVICE, NONCE, ttl_seconds=60))
            store.close()
            reopened = SQLiteNonceStore(path, max_claims=1)
            try:
                with self.assertRaises(NonceStoreError):
                    reopened.claim(DEVICE, "b2" * 16, ttl_seconds=60)
                self.assertFalse(reopened.claim(DEVICE, NONCE, ttl_seconds=60))
            finally:
                reopened.close()

if __name__ == "__main__":
    unittest.main()
