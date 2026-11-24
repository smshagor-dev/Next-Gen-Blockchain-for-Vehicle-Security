"""Cold-start transaction integrity controls for durable admission (non-actuating)."""
import multiprocessing as mp
import tempfile
import unittest
from pathlib import Path

from research_contracts.durable_epoch_admission import DurableEpochAdmission
from research_contracts.epoch_admission_controls import Evidence


def _cold_start_worker(path, sender, ready, start, output):
    try:
        ready.put(sender)
        if not start.wait(timeout=15):
            raise TimeoutError("start barrier timed out")
        gate = DurableEpochAdmission(path, quorum=2)
        outcome = gate.admit(Evidence("same-incident", sender, 0,
                                      "nonce-" + sender, "hazard", True))
        output.put(("ok", sender, outcome))
    except Exception as exc:
        output.put(("error", sender, repr(exc)))


class ColdStartIntegrityTests(unittest.TestCase):
    def test_repeated_initialization_does_not_erase_stop_or_replay_pins(self):
        with tempfile.TemporaryDirectory() as folder:
            path = str(Path(folder) / "state.sqlite")
            gate = DurableEpochAdmission(path)
            first = Evidence("incident", "sender-a", 0, "nonce-a", "hazard", True)
            self.assertFalse(gate.admit(first))
            gate.local_emergency_stop()
            DurableEpochAdmission(path)
            self.assertFalse(DurableEpochAdmission(path).admit(
                Evidence("incident", "sender-b", 0, "nonce-b", "hazard", True)))
            self.assertTrue(DurableEpochAdmission(path).local_reset(operator_confirmed=True))
            self.assertFalse(DurableEpochAdmission(path).admit(first))
            self.assertTrue(DurableEpochAdmission(path).admit(
                Evidence("incident", "sender-b", 0, "nonce-b", "hazard", True)))

    def test_simultaneous_cold_start_exactly_one_admission(self):
        with tempfile.TemporaryDirectory() as folder:
            path = str(Path(folder) / "cold.sqlite")
            ctx = mp.get_context("spawn")
            ready, output, start = ctx.Queue(), ctx.Queue(), ctx.Event()
            workers = [ctx.Process(target=_cold_start_worker,
                       args=(path, "peer-%02d" % i, ready, start, output))
                       for i in range(6)]
            try:
                for worker in workers:
                    worker.start()
                for _ in workers:
                    ready.get(timeout=15)
                start.set()
                for worker in workers:
                    worker.join(timeout=25)
                    self.assertFalse(worker.is_alive(), "cold-start worker hung")
                    self.assertEqual(worker.exitcode, 0)
                rows = [output.get(timeout=5) for _ in workers]
                self.assertTrue(all(row[0] == "ok" for row in rows), rows)
                self.assertEqual(sum(row[2] is True for row in rows), 1, rows)
                self.assertFalse(DurableEpochAdmission(path).admit(
                    Evidence("same-incident", "new-peer", 0, "new-nonce", "hazard", True)))
            finally:
                for worker in workers:
                    if worker.is_alive():
                        worker.terminate()
                        worker.join(timeout=5)


if __name__ == "__main__":
    unittest.main()
