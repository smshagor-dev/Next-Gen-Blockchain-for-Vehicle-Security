"""Synthetic signed two-arm protocol tests. NOT independent V2X observations."""
from __future__ import annotations

import csv
import hashlib
import hmac
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

from capture_export_producer import canonical, make_manifest, seal_capture
from paired_signed_capture_analysis import (
    compare, sign_assignment, verify_assignment, _mcnemar_exact)

WORLD = ("experiment_id", "scenario_id", "seed", "split", "incident_id", "ground_truth")
CAPTURE = ("experiment_id", "scenario_id", "seed", "split", "incident_id",
           "node_id", "nonce", "received_at", "session_verified", "alert_relayed")
BKEYS = (b"baseline-export-key-9999", b"baseline-interval-key-9999",
         b"baseline-assignment-key-9999")
CKEYS = (b"candidate-export-key-9999", b"candidate-interval-key-9999",
         b"candidate-assignment-key-9999")


def csv_bytes(headers, rows):
    stream = io.StringIO(newline="")
    writer = csv.writer(stream)
    writer.writerow(headers)
    writer.writerows(rows)
    return stream.getvalue().encode()


def event(incident, nonce, time="2026-01-01T00:00:20Z", verified="1", relayed="1"):
    return ("experiment", "urban", "18", "test", incident, "node-" + nonce,
            nonce, time, verified, relayed)


class SignedPairedCohortTests(unittest.TestCase):
    def setUp(self):
        self.plan = {
            "experiment_id": "experiment", "scenario_id": "urban", "seed": "18",
            "split": "test", "window_start": "2026-01-01T00:00:00Z",
            "window_end": "2026-01-01T00:01:00Z", "independent_cluster_id": "drive-A",
            "baseline_name": "authenticated-forwarding",
            "candidate_name": "evidence-gated-forwarding"}
        self.world = csv_bytes(WORLD, [
            ("experiment", "urban", "18", "test", "hazard", "1"),
            ("experiment", "urban", "18", "test", "quiet", "0"),
            ("experiment", "urban", "18", "test", "outage", "1"),
            ("experiment", "urban", "18", "test", "false", "0")])
        self.manifest = make_manifest(self.plan, self.world)
        self.pin = hashlib.sha256(self.manifest).hexdigest()
        self.baseline_capture = csv_bytes(CAPTURE, [
            event("hazard", "b-1"), event("false", "b-2")])
        self.candidate_capture = csv_bytes(CAPTURE, [
            event("hazard", "c-1"), event("outage", "c-2")])

    def arm(self, arm, capture=None):
        if capture is None:
            capture = self.baseline_capture if arm == "baseline" else self.candidate_capture
        keys = BKEYS if arm == "baseline" else CKEYS
        export, interval = seal_capture(
            self.manifest, self.pin, self.world, capture,
            keys[0], keys[1], capture_complete=True)
        assignment = sign_assignment(self.manifest, self.world, self.pin,
                                     capture, arm, keys[2])
        return {"capture": capture, "export": canonical(export),
                "interval": canonical(interval), "assignment": assignment,
                "keys": keys}

    def check(self, baseline=None, candidate=None, *, manifest=None, world=None, pin=None):
        b = baseline or self.arm("baseline")
        c = candidate or self.arm("candidate")
        return compare(
            self.manifest if manifest is None else manifest,
            self.pin if pin is None else pin, self.world if world is None else world,
            b["capture"], c["capture"], b["export"], b["interval"],
            c["export"], c["interval"], b["assignment"], c["assignment"],
            b["keys"], c["keys"])

    def test_same_world_denominator_and_effect(self):
        r = self.check()
        self.assertEqual(r["world_incidents"], 4)
        self.assertEqual((r["baseline"]["tp"], r["baseline"]["fp"],
                          r["baseline"]["tn"], r["baseline"]["fn"]), (1, 1, 1, 1))
        self.assertEqual((r["candidate"]["tp"], r["candidate"]["fp"],
                          r["candidate"]["tn"], r["candidate"]["fn"]), (2, 0, 2, 0))
        self.assertEqual(r["accuracy_difference_pp"], 50)
        self.assertEqual(r["candidate_only_correct"], 2)
        self.assertEqual(r["baseline_only_correct"], 0)
        self.assertEqual(r["mcnemar_exact_two_sided_p_descriptive"], 0.5)
        self.assertEqual([x["incident_id"] for x in r["incident_rows"]],
                         ["hazard", "quiet", "outage", "false"])
        self.assertFalse(r["publication_ready"])

    def test_empty_baseline_capture_retains_missed_incident_denominator(self):
        b = self.arm("baseline", csv_bytes(CAPTURE, []))
        result = self.check(baseline=b)
        self.assertEqual(result["baseline"]["fn"], 2)
        self.assertEqual(result["baseline"]["tn"], 2)
        self.assertEqual(result["world_incidents"], 4)

    def test_two_empty_arms_report_no_fake_availability(self):
        b = self.arm("baseline", csv_bytes(CAPTURE, []))
        c = self.arm("candidate", csv_bytes(CAPTURE, []))
        r = self.check(baseline=b, candidate=c)
        self.assertEqual(r["baseline"]["recall"], 0)
        self.assertEqual(r["candidate"]["recall"], 0)
        self.assertEqual(r["mcnemar_exact_two_sided_p_descriptive"], 1)

    def test_wrong_signed_assignment_arm_fails(self):
        b = self.arm("baseline")
        b["assignment"] = self.arm("candidate")["assignment"]
        with self.assertRaisesRegex(ValueError, "assignment"):
            self.check(baseline=b)

    def test_forged_policy_claim_fails_even_after_valid_receipts(self):
        b = self.arm("baseline")
        obj = json.loads(b["assignment"])
        obj["policy_name"] = "attacker-chosen"
        b["assignment"] = canonical(obj)
        with self.assertRaisesRegex(ValueError, "HMAC"):
            self.check(baseline=b)

    def test_wrong_method_but_validly_signed_rejected(self):
        b = self.arm("baseline")
        obj = json.loads(b["assignment"])
        obj["policy_name"] = "not-the-planned-baseline"
        signed = {k: v for k, v in obj.items() if k != "hmac_sha256"}
        obj["hmac_sha256"] = hmac.new(BKEYS[2], canonical(signed), hashlib.sha256).hexdigest()
        b["assignment"] = canonical(obj)
        with self.assertRaisesRegex(ValueError, "preselected arm"):
            self.check(baseline=b)

    def test_cross_capture_assignment_mismatch(self):
        b = self.arm("baseline")
        obj = json.loads(b["assignment"])
        obj["capture_sha256"] = "0" * 64
        signed = {k: v for k, v in obj.items() if k != "hmac_sha256"}
        obj["hmac_sha256"] = hmac.new(BKEYS[2], canonical(signed), hashlib.sha256).hexdigest()
        b["assignment"] = canonical(obj)
        with self.assertRaisesRegex(ValueError, "bind trial and capture"):
            self.check(baseline=b)

    def test_duplicate_assignment_json_key_rejected(self):
        b = self.arm("baseline")
        b["assignment"] = b["assignment"].replace(
            b'"arm":', b'"arm":"candidate","arm":', 1)
        with self.assertRaisesRegex(ValueError, "duplicate"):
            self.check(baseline=b)

    def test_swapped_capture_and_receipts_rejected(self):
        b, c = self.arm("baseline"), self.arm("candidate")
        b["capture"], c["capture"] = c["capture"], b["capture"]
        with self.assertRaisesRegex(ValueError, "capture"):
            self.check(baseline=b, candidate=c)

    def test_independent_key_rule_rejects_cross_arm_reuse(self):
        c = self.arm("candidate")
        c["keys"] = (BKEYS[0], CKEYS[1], CKEYS[2])
        with self.assertRaisesRegex(ValueError, "independent"):
            self.check(candidate=c)

    def test_independent_manifest_pin_rejected(self):
        with self.assertRaisesRegex(ValueError, "operator-pinned"):
            self.check(pin="0" * 64)

    def test_world_label_tamper_rejected(self):
        with self.assertRaisesRegex(ValueError, "source-mismatched"):
            self.check(world=self.world.replace(b"hazard,1", b"hazard,0"))

    def test_replay_in_one_arm_rejected(self):
        extra = self.baseline_capture.splitlines(keepends=True)[1]
        capture = self.baseline_capture + extra
        with self.assertRaisesRegex(ValueError, "replayed"):
            self.arm("baseline", capture)

    def test_unsigned_relay_in_one_arm_rejected(self):
        capture = self.baseline_capture.replace(b",1,1\r\n", b",0,1\r\n")
        with self.assertRaisesRegex(ValueError, "unverified"):
            self.arm("baseline", capture)

    def test_large_mcnemar_is_finite(self):
        self.assertEqual(_mcnemar_exact(2000, 0), 2 / (1 << 2000))
        self.assertEqual(_mcnemar_exact(200, 200), 1.0)

    def test_real_cli_emits_source_bound_comparison(self):
        b, c = self.arm("baseline"), self.arm("candidate")
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            inputs = {
                "manifest": self.manifest, "world": self.world,
                "baseline-capture": b["capture"], "candidate-capture": c["capture"],
            }
            for arm, obj in (("baseline", b), ("candidate", c)):
                for field in ("export", "interval", "assignment"):
                    inputs[arm + "-" + field + "-receipt"] = obj[field]
                for field, key in zip(("export", "interval", "assignment"), obj["keys"]):
                    inputs[arm + "-" + field + "-key"] = key
            for name, payload in inputs.items():
                (root / name).write_bytes(payload)
            out = root / "comparison.json"
            command = [
                sys.executable, str(Path(__file__).with_name("paired_signed_capture_analysis.py")),
                "--pinned-manifest-sha256", self.pin, "--output", str(out),
            ]
            for name in inputs:
                command += ["--" + name, str(root / name)]
            completed = subprocess.run(
                command, env={**os.environ, "PYTHONPATH": str(Path(__file__).parent)},
                capture_output=True, text=True, check=True)
            summary = json.loads(completed.stdout)
            result = json.loads(out.read_text(encoding="ascii"))
            self.assertFalse(summary["publication_ready"])
            self.assertEqual(result["world_incidents"], 4)
            self.assertEqual(result["accuracy_difference_pp"], 50)
            self.assertEqual(summary["output_sha256"], hashlib.sha256(out.read_bytes()).hexdigest())

    def test_wrong_version_rejected(self):
        b = self.arm("baseline")
        obj = json.loads(b["assignment"])
        obj["schema_version"] = True
        b["assignment"] = canonical(obj)
        with self.assertRaisesRegex(ValueError, "schema version"):
            self.check(baseline=b)


if __name__ == "__main__":
    unittest.main()
