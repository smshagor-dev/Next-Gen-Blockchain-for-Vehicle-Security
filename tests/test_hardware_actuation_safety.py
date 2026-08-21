import os
import stat
import tempfile
import unittest
from pathlib import Path

from hardware_actuation_safety import (
    BenchActuationGate,
    HardwareSafetyError,
    INTERLOCK_CONTENT,
)


class HardwareActuationSafetyTests(unittest.TestCase):
    def test_actuation_is_disabled_by_default(self):
        gate = BenchActuationGate(environ={})
        decision = gate.decision()
        self.assertFalse(decision.armed)
        self.assertEqual(decision.reason, "HARDWARE_ACTUATION_DISABLED")
        with self.assertRaisesRegex(HardwareSafetyError, "HARDWARE_ACTUATION_DISABLED"):
            gate.require_armed()

    def test_non_bench_mode_is_rejected(self):
        gate = BenchActuationGate(
            environ={
                "SMARTCAR_HARDWARE_ACTUATION_ENABLED": "1",
                "SMARTCAR_HARDWARE_ACTUATION_MODE": "vehicle",
            }
        )
        self.assertEqual(gate.decision().reason, "HARDWARE_ACTUATION_MODE_NOT_BENCH")

    def test_missing_interlock_file_is_rejected(self):
        gate = BenchActuationGate(
            environ={
                "SMARTCAR_HARDWARE_ACTUATION_ENABLED": "1",
                "SMARTCAR_HARDWARE_ACTUATION_MODE": "bench",
            }
        )
        self.assertEqual(gate.decision().reason, "BENCH_INTERLOCK_FILE_REQUIRED")

    def test_wrong_interlock_content_is_rejected(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "arm.txt"
            path.write_text("wrong", encoding="utf-8")
            os.chmod(path, 0o600)
            gate = BenchActuationGate(
                environ={
                    "SMARTCAR_HARDWARE_ACTUATION_ENABLED": "1",
                    "SMARTCAR_HARDWARE_ACTUATION_MODE": "bench",
                    "SMARTCAR_HARDWARE_BENCH_INTERLOCK_FILE": str(path),
                }
            )
            self.assertEqual(gate.decision().reason, "BENCH_INTERLOCK_CONTENT_INVALID")

    def test_secure_interlock_arms_bench_gate(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "arm.txt"
            path.write_text(INTERLOCK_CONTENT + "\n", encoding="utf-8")
            os.chmod(path, 0o600)
            gate = BenchActuationGate(
                environ={
                    "SMARTCAR_HARDWARE_ACTUATION_ENABLED": "1",
                    "SMARTCAR_HARDWARE_ACTUATION_MODE": "bench",
                    "SMARTCAR_HARDWARE_BENCH_INTERLOCK_FILE": str(path),
                }
            )
            self.assertTrue(gate.is_armed())
            gate.require_armed()
            metadata = gate.metadata()
            self.assertTrue(metadata["armed"])
            self.assertFalse(metadata["safety_certified"])
            self.assertTrue(metadata["requires_physical_estop"])

    @unittest.skipIf(os.name == "nt", "POSIX permission bits are not authoritative on Windows")
    def test_group_writable_interlock_is_rejected_on_posix(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "arm.txt"
            path.write_text(INTERLOCK_CONTENT, encoding="utf-8")
            os.chmod(path, stat.S_IRUSR | stat.S_IWUSR | stat.S_IWGRP)
            gate = BenchActuationGate(
                environ={
                    "SMARTCAR_HARDWARE_ACTUATION_ENABLED": "1",
                    "SMARTCAR_HARDWARE_ACTUATION_MODE": "bench",
                    "SMARTCAR_HARDWARE_BENCH_INTERLOCK_FILE": str(path),
                }
            )
            self.assertEqual(gate.decision().reason, "BENCH_INTERLOCK_PERMISSIONS_INVALID")

    @unittest.skipUnless(hasattr(os, "symlink"), "symlinks unavailable")
    def test_symlink_interlock_is_rejected(self):
        with tempfile.TemporaryDirectory() as temp:
            target = Path(temp) / "target.txt"
            target.write_text(INTERLOCK_CONTENT, encoding="utf-8")
            os.chmod(target, 0o600)
            link = Path(temp) / "arm.txt"
            try:
                os.symlink(target, link)
            except (OSError, NotImplementedError):
                self.skipTest("symlink creation unavailable")
            gate = BenchActuationGate(
                environ={
                    "SMARTCAR_HARDWARE_ACTUATION_ENABLED": "1",
                    "SMARTCAR_HARDWARE_ACTUATION_MODE": "bench",
                    "SMARTCAR_HARDWARE_BENCH_INTERLOCK_FILE": str(link),
                }
            )
            self.assertEqual(gate.decision().reason, "BENCH_INTERLOCK_SYMLINK_REJECTED")


if __name__ == "__main__":
    unittest.main()
