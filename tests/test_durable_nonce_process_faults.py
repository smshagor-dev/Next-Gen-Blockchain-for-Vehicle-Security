"""Independent-process nonce race and abrupt-exit controls; simulation only.

Run: python -m unittest discover -s tests -p 'test_durable_nonce_process_faults.py' -v
No ECU, actuator, network endpoint, or physical power-loss claim.
"""
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
WORKER = """
import json, os, sys
from durable_hardware_replay import DurableNonceStore
db, gate, nonce, mode = sys.argv[1:]
store = DurableNonceStore(db, max_entries_per_device=32)
# Parent creates a release marker only after all children announce readiness.
Path = __import__('pathlib').Path
Path(gate + '.' + str(os.getpid())).write_text('ready')
import time
deadline = time.monotonic() + 15
while not Path(gate).exists():
    if time.monotonic() > deadline: sys.exit(31)
    time.sleep(0.005)
result = store.claim('enrolled-pi', nonce, window_seconds=120)
print(json.dumps({'result': result}), flush=True)
if mode == 'abrupt': os._exit(0)
store.close()
"""


class DurableNonceProcessFaults(unittest.TestCase):
    def _spawn(self, db, gate, nonce, mode="normal"):
        return subprocess.Popen(
            [sys.executable, "-c", WORKER, str(db), str(gate), nonce, mode],
            cwd=ROOT, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
        )

    def test_simultaneous_processes_admit_nonce_exactly_once(self):
        with tempfile.TemporaryDirectory() as tmp:
            db, gate = Path(tmp) / "claims.db", Path(tmp) / "release"
            workers = [self._spawn(db, gate, "ab" * 16) for _ in range(6)]
            try:
                import time
                deadline = time.monotonic() + 15
                while len(list(Path(tmp).glob("release.*"))) < len(workers):
                    self.assertLess(time.monotonic(), deadline, "worker readiness timeout")
                    self.assertTrue(all(p.poll() is None for p in workers), "worker exited before release")
                    time.sleep(0.01)
                gate.touch()
                outcomes = []
                for worker in workers:
                    out, err = worker.communicate(timeout=20)
                    self.assertEqual(worker.returncode, 0, err)
                    outcomes.append(json.loads(out)["result"])
                self.assertEqual(outcomes.count(None), 1, outcomes)
                self.assertEqual(outcomes.count("HW_REPLAY_DETECTED"), 5, outcomes)
            finally:
                gate.touch(exist_ok=True)
                for worker in workers:
                    if worker.poll() is None:
                        worker.kill()
                    worker.communicate()

    def test_abrupt_exit_after_committed_claim_remains_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            db, gate = Path(tmp) / "claims.db", Path(tmp) / "release"
            gate.touch()
            first = self._spawn(db, gate, "cd" * 16, "abrupt")
            out, err = first.communicate(timeout=20)
            self.assertEqual(first.returncode, 0, err)
            self.assertIsNone(json.loads(out)["result"])
            second = self._spawn(db, gate, "cd" * 16)
            out, err = second.communicate(timeout=20)
            self.assertEqual(second.returncode, 0, err)
            self.assertEqual(json.loads(out)["result"], "HW_REPLAY_DETECTED")


if __name__ == "__main__":
    unittest.main()
