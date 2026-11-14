"""Synthetic subprocess contracts, never physical V2X experimental evidence."""
import json
import os
from pathlib import Path
import stat
import tempfile
import unittest

from capture_export_producer import canonical
from pin_policy_artifacts import build_pin, sha
from run_pinned_simulation import execute_local_simulation


class PinnedSimulationTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.manifest = canonical({"baseline_name": "auth-only",
                                   "candidate_name": "evidence-gate"})
        self.binary = b"#!/usr/bin/env python3\nimport pathlib,sys\nprint(pathlib.Path(sys.argv[1]).read_text())\n"
        self.other = b"#!/usr/bin/env python3\nprint('candidate')\n"
        self.config = b"baseline-configuration"
        self.other_config = b"candidate-configuration"
        self.exe = self.root / "runner"
        self.cfg = self.root / "settings"
        self.exe.write_bytes(self.binary)
        self.exe.chmod(self.exe.stat().st_mode | stat.S_IXUSR)
        self.cfg.write_bytes(self.config)
        self.pin = build_pin(self.manifest, self.binary, self.other,
                             self.config, self.other_config,
                             "auth-only", "evidence-gate")
        self.digest = sha(self.pin)

    def run_policy(self, **changes):
        data = dict(pin=self.pin, pinned_sha256=self.digest,
                    manifest=self.manifest, baseline_executable=self.binary,
                    candidate_executable=self.other, baseline_config=self.config,
                    candidate_config=self.other_config, arm="baseline",
                    executable_path=self.exe, config_path=self.cfg)
        data.update(changes)
        return execute_local_simulation(**data)

    def test_real_subprocess_and_output_hash(self):
        r = self.run_policy()
        self.assertEqual(r["returncode"], 0)
        self.assertEqual(r["stdout_sha256"], sha(self.config + b"\n"))
        self.assertEqual(r["stdout_bytes"], len(self.config) + 1)
        self.assertFalse(r["publication_ready"])

    def test_modified_executable_rejected(self):
        self.exe.write_bytes(self.binary + b"# changed\n")
        with self.assertRaisesRegex(ValueError, "differ"):
            self.run_policy()

    def test_modified_configuration_rejected(self):
        self.cfg.write_bytes(b"changed")
        with self.assertRaisesRegex(ValueError, "differ"):
            self.run_policy()

    def test_wrong_external_pin_rejected(self):
        with self.assertRaisesRegex(ValueError, "external executable pin"):
            self.run_policy(pinned_sha256="0" * 64)

    def test_wrong_arm_rejected(self):
        with self.assertRaisesRegex(ValueError, "unknown trial arm"):
            self.run_policy(arm="fake")

    def test_wrong_arm_artifact_rejected(self):
        with self.assertRaisesRegex(ValueError, "differ"):
            self.run_policy(arm="candidate")

    def test_symlink_executable_rejected(self):
        link = self.root / "alias"
        link.symlink_to(self.exe)
        with self.assertRaisesRegex(ValueError, "non-symlink"):
            self.run_policy(executable_path=link)

    def test_symlink_config_rejected(self):
        link = self.root / "alias-config"
        link.symlink_to(self.cfg)
        with self.assertRaisesRegex(ValueError, "non-symlink"):
            self.run_policy(config_path=link)

    def test_output_limit_rejected(self):
        with self.assertRaisesRegex(ValueError, "output bound"):
            self.run_policy(max_output_bytes=1)

    def test_timeout_rejected(self):
        sleeping = b"#!/usr/bin/env python3\nimport time\ntime.sleep(2)\n"
        self.exe.write_bytes(sleeping)
        self.pin = build_pin(self.manifest, sleeping, self.other,
                             self.config, self.other_config, "auth-only", "evidence-gate")
        self.digest = sha(self.pin)
        with self.assertRaisesRegex(ValueError, "timed out"):
            self.run_policy(baseline_executable=sleeping, timeout_seconds=0.1)

    def test_failed_process_rejected(self):
        failing = b"#!/usr/bin/env python3\nimport sys\nsys.exit(7)\n"
        self.exe.write_bytes(failing)
        self.pin = build_pin(self.manifest, failing, self.other,
                             self.config, self.other_config, "auth-only", "evidence-gate")
        self.digest = sha(self.pin)
        with self.assertRaisesRegex(ValueError, "unsuccessfully"):
            self.run_policy(baseline_executable=failing)

    def test_invalid_timeout_rejected(self):
        with self.assertRaisesRegex(ValueError, "timeout"):
            self.run_policy(timeout_seconds=0)

    def test_invalid_max_output_rejected(self):
        with self.assertRaisesRegex(ValueError, "output bound"):
            self.run_policy(max_output_bytes=0)


if __name__ == "__main__":
    unittest.main()
