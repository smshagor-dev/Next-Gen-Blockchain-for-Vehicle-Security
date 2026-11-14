"""Synthetic protocol regressions for the capture receipt producer, no HIL data."""
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

from attested_interval_join import evaluate_interval
from capture_export_producer import (
    PLAN_FIELDS, WINDOW_FIELDS, canonical, create_once, make_manifest,
    seal_capture, verify_manifest,
)

WORLD = ("experiment_id", "scenario_id", "seed", "split", "incident_id", "ground_truth")
CAPTURE = ("experiment_id", "scenario_id", "seed", "split", "incident_id",
           "node_id", "nonce", "received_at", "session_verified", "alert_relayed")
EXPORT_KEY = b"synthetic-export-secret-0123456789"
INTERVAL_KEY = b"synthetic-interval-secret-0123456789"


def csv_bytes(columns, rows):
    buf = io.StringIO(newline="")
    w = csv.writer(buf)
    w.writerow(columns)
    w.writerows(rows)
    return buf.getvalue().encode("utf-8")


class ProducerContractTests(unittest.TestCase):
    def setUp(self):
        self.plan = dict(experiment_id="exp", scenario_id="scene-1", seed="42",
                         split="test", window_start="2026-01-01T00:00:00Z",
                         window_end="2026-01-01T00:01:00Z",
                         independent_cluster_id="drive-11",
                         baseline_name="fixed-replay", candidate_name="evidence-admission")
        self.world = csv_bytes(WORLD, [
            ("exp", "scene-1", "42", "test", "positive", "1"),
            ("exp", "scene-1", "42", "test", "quiet", "0"),
            ("exp", "scene-1", "42", "test", "missed", "1")])
        self.capture = csv_bytes(CAPTURE, [
            ("exp", "scene-1", "42", "test", "positive", "receiver-1", "nonce-1",
             "2026-01-01T00:00:20Z", "1", "1")])
        self.manifest = make_manifest(self.plan, self.world)

    def seal(self, *, world=None, capture=None, manifest=None, pin=None,
             complete=True, export_key=EXPORT_KEY, interval_key=INTERVAL_KEY):
        world = self.world if world is None else world
        capture = self.capture if capture is None else capture
        manifest = self.manifest if manifest is None else manifest
        return seal_capture(manifest, pin or hashlib.sha256(self.manifest).hexdigest(),
                            world, capture, export_key, interval_key,
                            capture_complete=complete)

    def test_pinned_manifest_is_canonical_and_roundtrips_with_consumer(self):
        manifest = verify_manifest(self.manifest, self.world,
                                   hashlib.sha256(self.manifest).hexdigest())
        self.assertEqual(manifest["independent_cluster_id"], "drive-11")
        export, interval = self.seal()
        report = evaluate_interval(
            self.world, self.capture, export, EXPORT_KEY, interval, INTERVAL_KEY,
            {k: self.plan[k] for k in WINDOW_FIELDS},
            hashlib.sha256(self.world).hexdigest(),
            hashlib.sha256(self.capture).hexdigest())
        self.assertEqual((report["tp"], report["fp"], report["tn"], report["fn"]),
                         (1, 0, 1, 1))
        self.assertFalse(report["publication_ready"])

    def test_empty_signed_complete_capture_counts_missed_hazards(self):
        capture = csv_bytes(CAPTURE, [])
        export, receipt = self.seal(capture=capture)
        report = evaluate_interval(
            self.world, capture, export, EXPORT_KEY, receipt, INTERVAL_KEY,
            {k: self.plan[k] for k in WINDOW_FIELDS},
            hashlib.sha256(self.world).hexdigest(),
            hashlib.sha256(capture).hexdigest())
        self.assertEqual((report["tp"], report["fp"], report["tn"], report["fn"]),
                         (0, 0, 1, 2))

    def test_incomplete_receipt_is_signed_but_scoring_refused(self):
        export, interval = self.seal(complete=False)
        self.assertFalse(interval["capture_complete"])
        with self.assertRaisesRegex(ValueError, "incomplete interval"):
            evaluate_interval(
                self.world, self.capture, export, EXPORT_KEY, interval, INTERVAL_KEY,
                {k: self.plan[k] for k in WINDOW_FIELDS},
                hashlib.sha256(self.world).hexdigest(),
                hashlib.sha256(self.capture).hexdigest())

    def test_wrong_external_pin_rejected(self):
        with self.assertRaisesRegex(ValueError, "operator-pinned"):
            self.seal(pin="0" * 64)

    def test_tampered_world_rejected(self):
        with self.assertRaisesRegex(ValueError, "source-mismatched"):
            self.seal(world=self.world.replace(b"positive,1", b"positive,0"))

    def test_noncanonical_manifest_rejected_with_fresh_digest(self):
        data = json.dumps(json.loads(self.manifest), indent=4).encode()
        with self.assertRaisesRegex(ValueError, "noncanonical"):
            self.seal(manifest=data, pin=hashlib.sha256(data).hexdigest())

    def test_manifest_header_and_truth_validation(self):
        with self.assertRaisesRegex(ValueError, "binary"):
            make_manifest(self.plan, self.world.replace(b"missed,1", b"missed,2"))
        with self.assertRaisesRegex(ValueError, "duplicate incident"):
            make_manifest(self.plan, csv_bytes(WORLD, [
                ("exp", "scene-1", "42", "test", "same", "1"),
                ("exp", "scene-1", "42", "test", "same", "0")]))

    def test_plan_group_rejected(self):
        changed = dict(self.plan, seed="other-seed")
        with self.assertRaisesRegex(ValueError, "world universe"):
            make_manifest(changed, self.world)

    def test_equal_baseline_rejected(self):
        changed = dict(self.plan, baseline_name="evidence-admission")
        with self.assertRaisesRegex(ValueError, "must differ"):
            make_manifest(changed, self.world)

    def test_wrong_capture_trial_rejected(self):
        bad = self.capture.replace(b"scene-1,42,test", b"scene-1,43,test")
        with self.assertRaisesRegex(ValueError, "trial/seed/split"):
            self.seal(capture=bad)

    def test_early_and_late_receipts_rejected(self):
        for received_at in (b"2025-12-31T23:59:59Z", b"2026-01-01T00:01:00Z"):
            with self.subTest(received_at=received_at):
                bad = self.capture.replace(b"2026-01-01T00:00:20Z", received_at)
                with self.assertRaisesRegex(ValueError, "outside planned window"):
                    self.seal(capture=bad)

    def test_unknown_incident_rejected(self):
        bad = self.capture.replace(b"positive,receiver", b"unknownx,receiver")
        with self.assertRaisesRegex(ValueError, "matching independent world"):
            self.seal(capture=bad)

    def test_unverified_relay_rejected(self):
        bad = self.capture.replace(b",1,1\r\n", b",0,1\r\n")
        with self.assertRaisesRegex(ValueError, "unverified relay"):
            self.seal(capture=bad)

    def test_duplicate_capture_nonce_rejected(self):
        bad = self.capture + self.capture.splitlines(keepends=True)[1]
        with self.assertRaisesRegex(ValueError, "replayed"):
            self.seal(capture=bad)

    def test_secret_separation_and_strength(self):
        with self.assertRaisesRegex(ValueError, "distinct"):
            self.seal(interval_key=EXPORT_KEY)
        with self.assertRaisesRegex(ValueError, "at least 16 bytes"):
            self.seal(interval_key=b"short")

    def test_invalid_completion_type_rejected(self):
        with self.assertRaisesRegex(ValueError, "boolean"):
            seal_capture(self.manifest, hashlib.sha256(self.manifest).hexdigest(),
                         self.world, self.capture, EXPORT_KEY, INTERVAL_KEY,
                         capture_complete=1)

    def test_receipt_tamper_detected_by_consumer(self):
        export, receipt = self.seal()
        receipt["capture_complete"] = False
        with self.assertRaisesRegex(ValueError, "HMAC"):
            evaluate_interval(
                self.world, self.capture, export, EXPORT_KEY, receipt, INTERVAL_KEY,
                {k: self.plan[k] for k in WINDOW_FIELDS},
                hashlib.sha256(self.world).hexdigest(),
                hashlib.sha256(self.capture).hexdigest())

    def test_exclusive_private_output(self):
        with tempfile.TemporaryDirectory() as directory:
            file = Path(directory) / "trial.json"
            create_once(file, self.manifest)
            self.assertEqual(file.read_bytes(), self.manifest)
            with self.assertRaises(FileExistsError):
                create_once(file, b"replace")
            self.assertEqual(file.read_bytes(), self.manifest)
            if os.name == "posix":
                self.assertEqual(file.stat().st_mode & 0o777, 0o600)

    def test_exclusive_publication_never_exposes_partial_target(self):
        from unittest.mock import patch
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / "sealed.json"
            original_link = os.link

            def observe_before_link(src, dst):
                self.assertFalse(target.exists())
                self.assertEqual(Path(src).read_bytes(), self.manifest)
                return original_link(src, dst)

            with patch("capture_export_producer.os.link", side_effect=observe_before_link):
                create_once(target, self.manifest)
            self.assertEqual(target.read_bytes(), self.manifest)
            self.assertEqual(list(Path(directory).glob(".capture-pending-*")), [])

    def test_failed_exclusive_link_does_not_publish_or_leak_staging(self):
        from unittest.mock import patch
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / "sealed.json"
            with patch("capture_export_producer.os.link",
                       side_effect=OSError("simulated publication failure")):
                with self.assertRaisesRegex(OSError, "publication failure"):
                    create_once(target, self.manifest)
            self.assertFalse(target.exists())
            self.assertEqual(list(Path(directory).glob(".capture-pending-*")), [])

    def test_cli_plan_and_seal_roundtrip(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            paths = {n: root / n for n in (
                "plan.json", "world.csv", "capture.csv", "manifest.json",
                "export.key", "interval.key", "export.json", "interval.json")}
            paths["plan.json"].write_text(json.dumps(self.plan), encoding="utf-8")
            paths["world.csv"].write_bytes(self.world)
            paths["capture.csv"].write_bytes(self.capture)
            paths["export.key"].write_bytes(EXPORT_KEY)
            paths["interval.key"].write_bytes(INTERVAL_KEY)
            script = str(Path(__file__).with_name("capture_export_producer.py"))
            env = dict(os.environ)
            env["PYTHONPATH"] = str(Path(__file__).parent)
            plan = subprocess.run([
                sys.executable, script, "plan", "--plan", str(paths["plan.json"]),
                "--world", str(paths["world.csv"]), "--out", str(paths["manifest.json"])
            ], env=env, text=True, capture_output=True, check=True)
            pin = json.loads(plan.stdout)["manifest_sha256"]
            self.assertEqual(pin, hashlib.sha256(paths["manifest.json"].read_bytes()).hexdigest())
            output = subprocess.run([
                sys.executable, script, "seal",
                "--manifest", str(paths["manifest.json"]),
                "--world", str(paths["world.csv"]),
                "--capture", str(paths["capture.csv"]),
                "--export-key-file", str(paths["export.key"]),
                "--interval-key-file", str(paths["interval.key"]),
                "--export-receipt-out", str(paths["export.json"]),
                "--interval-receipt-out", str(paths["interval.json"]),
                "--pinned-manifest-sha256", pin, "--capture-complete"
            ], env=env, text=True, capture_output=True, check=True)
            self.assertFalse(json.loads(output.stdout)["publication_ready"])
            self.assertTrue(json.loads(paths["interval.json"].read_text())["capture_complete"])
            with self.assertRaises(subprocess.CalledProcessError):
                subprocess.run([
                    sys.executable, script, "seal",
                    "--manifest", str(paths["manifest.json"]),
                    "--world", str(paths["world.csv"]),
                    "--capture", str(paths["capture.csv"]),
                    "--export-key-file", str(paths["export.key"]),
                    "--interval-key-file", str(paths["interval.key"]),
                    "--export-receipt-out", str(paths["export.json"]),
                    "--interval-receipt-out", str(paths["interval.json"]),
                    "--pinned-manifest-sha256", pin, "--capture-complete"
                ], env=env, text=True, capture_output=True, check=True)


if __name__ == "__main__":
    unittest.main()
