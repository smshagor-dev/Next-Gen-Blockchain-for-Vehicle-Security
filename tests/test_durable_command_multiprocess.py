"""Deterministic process-level contention checks for the simulated replay store.

No network, CAN, GPIO, serial, or physical actuation occurs.
"""
import multiprocessing
import tempfile
import unittest
from pathlib import Path

from hardware_command_receiver_simulator import DurableCommandNonceStore


def _claim_worker(path, device, nonce, ready, start, results):
    try:
        store = DurableCommandNonceStore(path)
        ready.put(True)
        if not start.wait(10):
            results.put(("error", "start timeout"))
            return
        results.put(("ok", store.claim(device, nonce, "2026-01-01T00:00:00Z")))
    except Exception as exc:
        results.put(("error", type(exc).__name__ + ": " + str(exc)))


class MultiprocessReplayTests(unittest.TestCase):
    def test_competing_processes_only_one_wins_and_restart_rejects(self):
        ctx = multiprocessing.get_context("spawn")
        with tempfile.TemporaryDirectory() as directory:
            path = str(Path(directory) / "replay.sqlite")
            DurableCommandNonceStore(path)
            ready, start, results = ctx.Queue(), ctx.Event(), ctx.Queue()
            workers = [
                ctx.Process(target=_claim_worker, args=(path, "ecu-a", "same-nonce", ready, start, results))
                for _ in range(4)
            ]
            try:
                for worker in workers:
                    worker.start()
                for _ in workers:
                    self.assertTrue(ready.get(timeout=15))
                start.set()
                outcomes = [results.get(timeout=15) for _ in workers]
                self.assertEqual(outcomes.count(("ok", True)), 1, outcomes)
                self.assertEqual(outcomes.count(("ok", False)), 3, outcomes)
                self.assertFalse(DurableCommandNonceStore(path).claim("ecu-a", "same-nonce", "later"))
                self.assertTrue(DurableCommandNonceStore(path).claim("ecu-b", "same-nonce", "later"))
            finally:
                start.set()
                for worker in workers:
                    worker.join(timeout=5)
                    if worker.is_alive():
                        worker.terminate()
                        worker.join(timeout=5)
                for worker in workers:
                    self.assertEqual(worker.exitcode, 0)


if __name__ == "__main__":
    unittest.main()
