"""Regression tests for descriptor-level bench interlock revalidation.

Run: python -m unittest discover -s tests -p 'test_bench_interlock_fd_race.py' -v
No physical actuation or external network access.
"""
import os
import stat
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from hardware_actuation_safety import BenchActuationGate, INTERLOCK_CONTENT


@unittest.skipIf(os.name == "nt", "POSIX mode and owner assertions")
class BenchInterlockDescriptorTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.path = Path(self.tmp.name) / "arm"
        self.path.write_text(INTERLOCK_CONTENT, encoding="utf-8")
        self.path.chmod(0o600)
        self.gate = BenchActuationGate({
            "SMARTCAR_HARDWARE_ACTUATION_ENABLED": "true",
            "SMARTCAR_HARDWARE_ACTUATION_MODE": "bench",
            "SMARTCAR_HARDWARE_BENCH_INTERLOCK_FILE": str(self.path),
        })

    def test_valid_bench_interlock(self):
        self.assertTrue(self.gate.decision().armed)

    def test_fd_permission_change_after_lstat_rejected(self):
        real_fstat = os.fstat
        def changed(fd):
            info = real_fstat(fd)
            fields = list(info)
            fields[stat.ST_MODE] |= stat.S_IWOTH
            return os.stat_result(fields)
        with patch("hardware_actuation_safety.os.fstat", side_effect=changed):
            decision = self.gate.decision()
        self.assertFalse(decision.armed)
        self.assertEqual(decision.reason, "BENCH_INTERLOCK_PERMISSIONS_INVALID")

    def test_fd_truncation_after_lstat_rejected(self):
        real_fstat = os.fstat
        def changed(fd):
            fields = list(real_fstat(fd))
            fields[stat.ST_SIZE] = 0
            return os.stat_result(fields)
        with patch("hardware_actuation_safety.os.fstat", side_effect=changed):
            decision = self.gate.decision()
        self.assertFalse(decision.armed)
        self.assertEqual(decision.reason, "BENCH_INTERLOCK_FILE_SIZE_INVALID")

    def test_read_error_fails_closed(self):
        with patch("hardware_actuation_safety.os.read", side_effect=OSError("injected I/O failure")):
            decision = self.gate.decision()
        self.assertFalse(decision.armed)
        self.assertEqual(decision.reason, "BENCH_INTERLOCK_READ_FAILED")


if __name__ == "__main__":
    unittest.main()
