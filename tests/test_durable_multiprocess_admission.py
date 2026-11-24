"""Independent-process serialization experiment for durable one-shot admission.

Protocol regression only; not vehicle safety, adversarial effectiveness, or
power-loss durability evidence. All workers share the same SQLite file.
"""
import multiprocessing as mp
import tempfile
import unittest
from pathlib import Path

from research_contracts.durable_epoch_admission import DurableEpochAdmission
from research_contracts.epoch_admission_controls import Evidence


def _worker(db_path, sender, start, output):
    try:
        if not start.wait(timeout=10):
            output.put(("error", sender, "start timeout"))
            return
        gate = DurableEpochAdmission(db_path)
        accepted = gate.admit(Evidence(
            incident="concurrent-incident", sender=sender, epoch=0,
            nonce="nonce-" + sender, event="hazard", verified=True))
        output.put(("ok", sender, accepted))
    except Exception as exc:
        output.put(("error", sender, repr(exc)))


class ConcurrentAdmissionTests(unittest.TestCase):
    def test_one_positive_across_independent_processes(self):
        # Each process opens its own connection. A single shared connection
        # would not exercise SQLite's cross-process BEGIN IMMEDIATE locking.
        with tempfile.TemporaryDirectory() as folder:
            path = str(Path(folder) / "shared.sqlite")
            DurableEpochAdmission(path, quorum=2)
            ctx = mp.get_context("spawn")
            start = ctx.Event()
            output = ctx.Queue()
            senders = ["peer-%02d" % i for i in range(12)]
            processes = [ctx.Process(target=_worker, args=(path, s, start, output))
                         for s in senders]
            for process in processes:
                process.start()
            start.set()
            for process in processes:
                process.join(timeout=20)
                if process.is_alive():
                    process.terminate()
                    process.join(timeout=5)
                    self.fail("worker hung under concurrent admission")
                self.assertEqual(process.exitcode, 0)
            results = [output.get(timeout=5) for _ in processes]
            self.assertTrue(all(row[0] == "ok" for row in results), results)
            self.assertEqual(sum(row[2] is True for row in results), 1, results)
            # Restarted store must not reissue the positive authorization.
            self.assertFalse(DurableEpochAdmission(path).admit(Evidence(
                incident="concurrent-incident", sender="fresh", epoch=0,
                nonce="nonce-fresh", event="hazard", verified=True)))


if __name__ == "__main__":
    unittest.main()
