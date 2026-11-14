"""Synthetic byte-level execution/capture binding regressions, not field evidence."""
import hashlib
import json
import unittest
from capture_export_producer import canonical, seal_capture
from pin_policy_artifacts import build_pin
from paired_signed_capture_analysis import sign_assignment
from verify_execution_capture_binding import verify_execution_capture
from test_paired_signed_capture_analysis import SignedPairedCohortTests, BKEYS


class ExecutionCaptureBindingTests(unittest.TestCase):
    def setUp(self):
        fixture = SignedPairedCohortTests()
        fixture.setUp()
        self.manifest, self.world, self.capture, self.manifest_pin = (
            fixture.manifest, fixture.world, fixture.baseline_capture, fixture.pin)
        self.be, self.ce = b"baseline binary", b"candidate binary"
        self.bc, self.cc = b"baseline config", b"candidate config"
        self.artifact_pin = build_pin(self.manifest, self.be, self.ce, self.bc, self.cc,
                                      fixture.plan["baseline_name"], fixture.plan["candidate_name"])
        self.artifact_digest = hashlib.sha256(self.artifact_pin).hexdigest()
        export, interval = seal_capture(
            self.manifest, self.manifest_pin, self.world, self.capture,
            BKEYS[0], BKEYS[1], capture_complete=True)
        self.export, self.interval = canonical(export), canonical(interval)
        self.assignment = sign_assignment(
            self.manifest, self.world, self.manifest_pin, self.capture, "baseline", BKEYS[2])
        def sha(b):
            return hashlib.sha256(b).hexdigest()
        self.receipt = {
            "schema_version": 1, "arm": "baseline",
            "policy_name": fixture.plan["baseline_name"],
            "trial_manifest_sha256": sha(self.manifest),
            "artifact_pin_sha256": self.artifact_digest,
            "executable_sha256": sha(self.be), "config_sha256": sha(self.bc),
            "command": ["/tmp/baseline", "/tmp/config"], "process_pid_observed": None,
            "started_utc_local_clock": "2026-01-01T00:00:00+00:00",
            "duration_ms_local_clock": 3.0, "returncode": 0,
            "stdout_sha256": sha(self.capture), "stderr_sha256": sha(b""),
            "stdout_bytes": len(self.capture), "stderr_bytes": 0,
            "publication_ready": False, "limitations": ["local operator receipt"],
        }

    def verify(self, **changes):
        args = dict(manifest_bytes=self.manifest, world_bytes=self.world,
                    manifest_pin=self.manifest_pin, artifact_pin_bytes=self.artifact_pin,
                    artifact_pin_sha256=self.artifact_digest,
                    baseline_executable=self.be, candidate_executable=self.ce,
                    baseline_config=self.bc, candidate_config=self.cc,
                    execution_receipt_bytes=canonical(self.receipt),
                    capture_bytes=self.capture, export_receipt_bytes=self.export,
                    interval_receipt_bytes=self.interval,
                    assignment_receipt_bytes=self.assignment,
                    export_key=BKEYS[0], interval_key=BKEYS[1],
                    assignment_key=BKEYS[2], expected_arm="baseline")
        args.update(changes)
        return verify_execution_capture(**args)

    def test_valid_binding(self):
        result = self.verify()
        self.assertTrue(result["capture_rows_integrity_checked"])
        self.assertFalse(result["publication_ready"])
        self.assertEqual(result["incident_counts"]["fn"], 1)

    def test_stdout_hash_mismatch(self):
        self.receipt["stdout_sha256"] = "0" * 64
        with self.assertRaisesRegex(ValueError, "stdout_sha256"):
            self.verify()

    def test_stdout_size_mismatch(self):
        self.receipt["stdout_bytes"] += 1
        with self.assertRaisesRegex(ValueError, "stdout size"):
            self.verify()

    def test_wrong_policy_arm(self):
        with self.assertRaisesRegex(ValueError, "arm/policy"):
            self.verify(expected_arm="candidate")

    def test_wrong_executable(self):
        self.receipt["executable_sha256"] = "0" * 64
        with self.assertRaisesRegex(ValueError, "executable_sha256"):
            self.verify()

    def test_wrong_config(self):
        self.receipt["config_sha256"] = "0" * 64
        with self.assertRaisesRegex(ValueError, "config_sha256"):
            self.verify()

    def test_wrong_external_pin(self):
        with self.assertRaisesRegex(ValueError, "external executable pin"):
            self.verify(artifact_pin_sha256="0" * 64)

    def test_forged_policy_assignment(self):
        with self.assertRaisesRegex(ValueError, "HMAC"):
            self.verify(assignment_receipt_bytes=self.assignment.replace(b'"arm":"baseline"', b'"arm":"candidate"'))

    def test_capture_tamper(self):
        with self.assertRaisesRegex(ValueError, "stdout_sha256"):
            self.verify(capture_bytes=self.capture + b"\n")

    def test_nonzero_exit(self):
        self.receipt["returncode"] = 1
        with self.assertRaisesRegex(ValueError, "did not succeed"):
            self.verify()

    def test_bool_exit_not_accepted(self):
        self.receipt["returncode"] = False
        with self.assertRaisesRegex(ValueError, "did not succeed"):
            self.verify()

    def test_duplicate_json_key(self):
        receipt = canonical(self.receipt).replace(
            b'"arm":', b'"arm":"candidate","arm":', 1)
        with self.assertRaisesRegex(ValueError, "duplicate"):
            self.verify(execution_receipt_bytes=receipt)

    def test_extra_field(self):
        self.receipt["trusted_hardware"] = True
        with self.assertRaisesRegex(ValueError, "schema"):
            self.verify()

    def test_false_publication_ready(self):
        self.receipt["publication_ready"] = True
        with self.assertRaisesRegex(ValueError, "publication readiness"):
            self.verify()

    def test_mismatched_capture_receipt(self):
        with self.assertRaisesRegex(ValueError, "duplicate"):
            self.verify(export_receipt_bytes=self.export.replace(
                b'"capture_sha256":', b'"capture_sha256":"bad","capture_sha256":'))


if __name__ == "__main__":
    unittest.main()
