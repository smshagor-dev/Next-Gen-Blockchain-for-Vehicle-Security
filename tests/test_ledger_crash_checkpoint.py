"""Fault-injection contract tests for the *local* ledger checkpoint harness."""
import copy
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from experiments.ledger.crash_checkpoint import CrashCheckpointStore
from ledger_integrity import LedgerIntegrityError
from tests.test_ledger_integrity import LedgerIntegrityTests

VEHICLE = "CAR-LEDGER-1"
GENERATION = "authenticated-generation-1"


def chain():
    genesis = LedgerIntegrityTests._go_block()
    second = LedgerIntegrityTests._go_block(
        index=1, previous_hash=genesis["block_hash"],
        event="TELEMETRY:UPDATE", timestamp="2026-08-21T00:00:01Z"
    )
    return [genesis, second]


class CheckpointCrashTests(unittest.TestCase):
    def test_restart_recovers_exact_committed_chain(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "state" / "checkpoint.json"
            store = CrashCheckpointStore(path, vehicle_id=VEHICLE, generation=GENERATION)
            self.assertIsNone(store.load())
            saved = store.commit(chain())
            restored = CrashCheckpointStore(path, vehicle_id=VEHICLE, generation=GENERATION).load()
            self.assertEqual(saved, restored)
            self.assertEqual(restored["height"], 1)
            self.assertEqual(restored["tip_hash"], chain()[-1]["block_hash"])

    def test_rejects_truncated_and_corrupted_checkpoint(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "checkpoint.json"
            store = CrashCheckpointStore(path, vehicle_id=VEHICLE, generation=GENERATION)
            store.commit(chain())
            path.write_bytes(path.read_bytes()[:-23])
            with self.assertRaises(LedgerIntegrityError):
                store.load()
            path.write_bytes(b'{"schema":"OMNIGUARD_LEDGER_CHECKPOINT_V1"}')
            with self.assertRaises(LedgerIntegrityError):
                store.load()

    def test_rejects_forged_receipt_even_with_recomputed_envelope_hash(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "checkpoint.json"
            store = CrashCheckpointStore(path, vehicle_id=VEHICLE, generation=GENERATION)
            store.commit(chain())
            data = json.loads(path.read_text())
            data["snapshot"][1]["smart_contract_receipts"].append({"action": "FAKE_FINALITY"})
            # Recompute every *unkeyed* envelope hash to demonstrate that
            # hashes alone cannot authenticate receipts or guarantee finality.
            from experiments.ledger.crash_checkpoint import _hash
            data["chain_sha256"] = _hash(data["snapshot"])
            data["envelope_sha256"] = _hash({k: v for k, v in data.items() if k != "envelope_sha256"})
            path.write_text(json.dumps(data))
            # This MUST NOT be described as tamper-proof: existing Go verifier
            # does not cryptographically cover receipt metadata.
            self.assertEqual(store.load()["snapshot"][1]["smart_contract_receipts"][0]["action"], "FAKE_FINALITY")

    def test_rejects_incoming_retroactive_block_change(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "checkpoint.json"
            store = CrashCheckpointStore(path, vehicle_id=VEHICLE, generation=GENERATION)
            store.commit(chain())
            modified = copy.deepcopy(chain())
            modified[0]["smart_contract_receipts"].append({"action": "FORGED"})
            with self.assertRaisesRegex(LedgerIntegrityError, "history changed"):
                store.commit(modified)
            self.assertEqual(store.load()["snapshot"], chain())

    def test_rejects_chain_height_regression(self):
        with tempfile.TemporaryDirectory() as temp:
            store = CrashCheckpointStore(Path(temp) / "checkpoint", vehicle_id=VEHICLE, generation=GENERATION)
            store.commit(chain())
            with self.assertRaisesRegex(LedgerIntegrityError, "height regressed"):
                store.commit(chain()[:1])

    def test_rejects_wrong_authenticated_generation(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "checkpoint"
            CrashCheckpointStore(path, vehicle_id=VEHICLE, generation=GENERATION).commit(chain())
            with self.assertRaisesRegex(LedgerIntegrityError, "generation mismatch"):
                CrashCheckpointStore(path, vehicle_id=VEHICLE, generation="new-generation").load()

    def test_pre_rename_failure_keeps_last_committed_state(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "checkpoint"
            store = CrashCheckpointStore(path, vehicle_id=VEHICLE, generation=GENERATION)
            store.commit(chain()[:1])
            before = path.read_bytes()
            def fail(stage):
                if stage == "after_temp_fsync":
                    raise RuntimeError("injected process interruption")
            with self.assertRaisesRegex(RuntimeError, "interruption"):
                CrashCheckpointStore(
                    path, vehicle_id=VEHICLE, generation=GENERATION, failpoint=fail
                ).commit(chain())
            self.assertEqual(path.read_bytes(), before)
            self.assertFalse(list(path.parent.glob(".checkpoint.*.tmp")))

    def test_post_rename_failure_recovery_sees_complete_old_or_new(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "checkpoint"
            store = CrashCheckpointStore(path, vehicle_id=VEHICLE, generation=GENERATION)
            store.commit(chain()[:1])
            def fail(stage):
                if stage == "after_replace_before_directory_fsync":
                    raise RuntimeError("injected post-rename interruption")
            with self.assertRaises(RuntimeError):
                CrashCheckpointStore(
                    path, vehicle_id=VEHICLE, generation=GENERATION, failpoint=fail
                ).commit(chain())
            recovered = store.load()
            self.assertIn(recovered["height"], (0, 1))
            self.assertEqual(recovered["snapshot"][-1]["block_hash"], recovered["tip_hash"])

    @unittest.skipUnless(os.name == "posix", "POSIX subprocess crash injection only")
    def test_actual_process_exit_at_fault_points(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "checkpoint"
            store = CrashCheckpointStore(path, vehicle_id=VEHICLE, generation=GENERATION)
            store.commit(chain()[:1])
            for stage in ("after_temp_fsync", "after_replace_before_directory_fsync",
                          "after_directory_fsync"):
                script = (
                    "import os,sys,json\n"
                    "from experiments.ledger.crash_checkpoint import CrashCheckpointStore\n"
                    "from tests.test_ledger_integrity import LedgerIntegrityTests\n"
                    "a=LedgerIntegrityTests._go_block()\n"
                    "b=LedgerIntegrityTests._go_block(index=1,previous_hash=a['block_hash'],"
                    "event='TELEMETRY:UPDATE',timestamp='2026-08-21T00:00:01Z')\n"
                    "def die(point):\n"
                    " if point==sys.argv[2]: os._exit(73)\n"
                    "CrashCheckpointStore(sys.argv[1],vehicle_id='CAR-LEDGER-1',"
                    "generation='authenticated-generation-1',failpoint=die).commit([a,b])\n"
                )
                completed = subprocess.run(
                    [sys.executable, "-c", script, str(path), stage],
                    cwd=Path(__file__).resolve().parents[1], capture_output=True,
                    text=True, timeout=15,
                )
                self.assertEqual(completed.returncode, 73, completed.stderr)
                recovered = store.load()
                self.assertIn(recovered["height"], (0, 1))
                self.assertEqual(recovered["snapshot"][-1]["block_hash"], recovered["tip_hash"])

    def test_older_valid_checkpoint_can_be_rolled_back_by_host(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "checkpoint"
            store = CrashCheckpointStore(path, vehicle_id=VEHICLE, generation=GENERATION)
            store.commit(chain()[:1])
            old = path.read_bytes()
            store.commit(chain())
            path.write_bytes(old)
            # Deliberate limitation: a trusted external monotonic anchor is
            # required to detect rollback across process restarts.
            self.assertEqual(store.load()["height"], 0)


if __name__ == "__main__":
    unittest.main()
