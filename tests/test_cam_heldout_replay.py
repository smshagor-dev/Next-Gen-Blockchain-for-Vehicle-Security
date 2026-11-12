"""Synthetic contract tests only; no fixture metrics are scientific results."""
from __future__ import annotations

import csv
import hashlib
import json
import tempfile
import unittest
from pathlib import Path

from experiments.cam.heldout_replay_baselines import (
    annotate_motion_consistency, calibrate, deduplicate_labeled_cams, metrics, predictions,
    run, verified_source_manifest,
)

SHA = "08d84f96602c8812be064375b3a57dee2c9f233635eeffaf44c6810609613bea"
FIELDS = [
    "archive_sha256", "source_split", "receiver_log", "sender_id",
    "sender_alias", "message_id", "send_time_raw", "receive_time_raw",
    "sender_acceleration", "sender_pos_x", "sender_pos_y", "sender_speed", "attacker_label",
]


def cam(split, message, label, *, receiver=None, timestamp=1_000_000_000,
        age=100, accel=0.1, vehicle=None, x=0.0, speed=10.0):
    return {
        "archive_sha256": SHA,
        "source_split": split,
        "receiver_log": receiver or f"receiver-{message}.json",
        "sender_id": vehicle or f"car-{message}",
        "sender_alias": "5", "message_id": str(message),
        "send_time_raw": str(timestamp), "receive_time_raw": str(timestamp + age),
        "sender_acceleration": str(accel), "sender_pos_x": str(x),
        "sender_pos_y": "0", "sender_speed": str(speed),
        "attacker_label": str(label),
    }


def study_rows():
    records = [cam("train", 600, 0)]
    records.extend(
        cam("validation", i, 0, age=i, accel=i / 100.0,
            vehicle="validation-source", timestamp=1_000_000_000 + i * 1_000_000_000,
            x=i * 10, speed=10)
        for i in range(1, 22)
    )
    records.extend([
        cam("test", 100, 1, age=60, accel=0.1, vehicle="test-source",
            timestamp=100_000_000_000, x=0),
        cam("test", 101, 1, age=1, accel=0.5, vehicle="test-source",
            timestamp=101_000_000_000, x=200),
        cam("test", 102, 0, age=5, accel=0.1, vehicle="test-source",
            timestamp=102_000_000_000, x=210),
        cam("test", 103, 0, age=90, accel=0.9, vehicle="test-source",
            timestamp=103_000_000_000, x=310),
    ])
    return records


def write_study(root: Path, records):
    input_csv = root / "cam.csv"
    with input_csv.open("w", encoding="utf-8", newline="") as dest:
        writer = csv.DictWriter(dest, fieldnames=FIELDS)
        writer.writeheader()
        writer.writerows(records)
    manifest = root / "source.json"
    manifest.write_text(json.dumps({
        "normalized_csv_sha256": hashlib.sha256(input_csv.read_bytes()).hexdigest(),
        "source_sha256_verified": SHA,
        "evaluation_unit": "per_receiver_CAM_record_not_independent_hazard_incident",
        "attack_subset_declared": "dataReplay",
    }), encoding="utf-8")
    return input_csv, manifest


class HeldoutCAMBaselinesTests(unittest.TestCase):
    def test_validation_thresholds_are_frozen_before_test(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            src, manifest = write_study(root, study_rows())
            split, audit = deduplicate_labeled_cams(src, SHA)
            split = annotate_motion_consistency(split)
            threshold = calibrate(split["validation"])
            self.assertEqual(threshold["age_ns_upper"], 21)
            self.assertAlmostEqual(threshold["acceleration_abs_mps2_upper"], 0.21)
            self.assertEqual(threshold["temporal_validation_eligible_benign"], 20)
            self.assertAlmostEqual(threshold["temporal_motion_residual_mps_upper"], 0.0)
            self.assertEqual(audit["test_distinct_fingerprints"], 4)
            self.assertEqual(predictions(split["test"], threshold, "receive_age_p99"),
                             [True, False, False, True])
            self.assertEqual(predictions(split["test"], threshold, "acceleration_magnitude_p99"),
                             [False, True, False, True])
            self.assertEqual(predictions(split["test"], threshold, "temporal_motion_residual_p99"),
                             [False, True, False, True])
            report = run(src, manifest, root / "output", expected_archive_sha256=SHA)
            age = report["methods"]["receive_age_p99"]
            self.assertEqual((age["tp"], age["fp"], age["tn"], age["fn"]), (1, 1, 1, 1))
            self.assertAlmostEqual(age["f1"], 0.5)
            self.assertEqual(report["methods"]["always_benign"]["tp"], 0)
            self.assertIsNone(report["methods"]["always_benign"]["precision"])
            self.assertFalse(report["publication_ready"])
            self.assertFalse(report["statistical_significance"])
            self.assertTrue((root / "output/cam_heldout_manifest.json").is_file())

    def test_test_labels_cannot_change_validation_calibration(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            rows = study_rows()
            input_a, _ = write_study(root, rows)
            partitions_a, _ = deduplicate_labeled_cams(input_a, SHA)
            calibration_a = calibrate(annotate_motion_consistency(partitions_a)["validation"])
            edited = [dict(row) for row in rows]
            for record in edited:
                if record["source_split"] == "test":
                    record["attacker_label"] = "1" if record["attacker_label"] == "0" else "0"
            input_b, _ = write_study(root, edited)
            partitions_b, _ = deduplicate_labeled_cams(input_b, SHA)
            self.assertEqual(calibration_a, calibrate(annotate_motion_consistency(partitions_b)["validation"]))

    def test_repeated_receiver_receptions_are_one_transmission(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            records = study_rows()
            duplicate = cam("test", 100, 1, receiver="other.json", age=5,
                            vehicle="test-source", timestamp=100_000_000_000, x=0)
            records.append(duplicate)
            src, _ = write_study(root, records)
            splits, audit = deduplicate_labeled_cams(src, SHA)
            self.assertEqual(audit["deduplicated_receiver_receptions"], 1)
            self.assertEqual(audit["test_distinct_fingerprints"], 4)
            selected = [v for v in splits["test"] if v.key[2] == "100"][0]
            self.assertEqual(selected.receiver_log, "other.json")
            self.assertEqual(selected.age_ns, 5)

    def test_cross_source_split_transmission_leakage_fails_closed(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            duplicate = dict(study_rows()[0])
            duplicate["source_split"] = "test"
            duplicate["receiver_log"] = "test-receiver.json"
            src, _ = write_study(root, study_rows() + [duplicate])
            with self.assertRaisesRegex(ValueError, "crosses train/validation/test"):
                deduplicate_labeled_cams(src, SHA)

    def test_conflicting_labels_for_same_transmission_fail_closed(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            duplicate = dict(study_rows()[0])
            duplicate["attacker_label"] = "1"
            src, _ = write_study(root, study_rows() + [duplicate])
            with self.assertRaisesRegex(ValueError, "conflicting attacker labels"):
                deduplicate_labeled_cams(src, SHA)

    def test_unlabeled_negative_or_invalid_split_never_imputed(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            for field, value, expression in (
                ("attacker_label", "", "ground-truth"),
                ("source_split", "unverified", "unknown"),
                ("sender_acceleration", "nan", "nonfinite"),
                ("send_time_raw", "5.0", "invalid sendTime"),
            ):
                with self.subTest(field=field):
                    records = study_rows()
                    records[0][field] = value
                    src, _ = write_study(root, records)
                    with self.assertRaisesRegex(ValueError, expression):
                        deduplicate_labeled_cams(src, SHA)

    def test_parent_provenance_sha256_required(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            src, manifest = write_study(root, study_rows())
            verified_source_manifest(src, manifest, SHA)
            src.write_text(src.read_text(encoding="utf-8") + "\n", encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "input SHA-256 mismatch"):
                verified_source_manifest(src, manifest, SHA)
            src, manifest = write_study(root, study_rows())
            with self.assertRaisesRegex(ValueError, "parent publisher ZIP SHA-256 identity mismatch"):
                verified_source_manifest(src, manifest, "f" * 64)

    def test_negative_validation_reference_is_required(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            records = study_rows()
            for row in records:
                if row["source_split"] == "validation":
                    row["attacker_label"] = "1"
            src, _ = write_study(root, records)
            parts, _ = deduplicate_labeled_cams(src, SHA)
            with self.assertRaisesRegex(ValueError, "20 distinct benign validation"):
                calibrate(annotate_motion_consistency(parts)["validation"])

    def test_exact_integer_source_timestamp_precision(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            records = study_rows()
            records[0]["send_time_raw"] = "1234567890123456789"
            records[0]["receive_time_raw"] = "1234567890123456795"
            src, _ = write_study(root, records)
            parts, _ = deduplicate_labeled_cams(src, SHA)
            self.assertEqual(parts["train"][0].age_ns, 6)

    def test_temporal_feature_does_not_cross_split_or_large_time_gap(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            trials = study_rows()
            # A source reuses its pseudonym between publisher validation and
            # test; no history may carry into Test even when identity matches.
            for row in trials:
                if row["source_split"] == "test":
                    row["sender_id"] = "validation-source"
            trials[-1]["send_time_raw"] = str(200_000_000_000)
            trials[-1]["receive_time_raw"] = str(200_000_000_090)
            src, _ = write_study(root, trials)
            annotated = annotate_motion_consistency(deduplicate_labeled_cams(src, SHA)[0])
            test = sorted(annotated["test"], key=lambda t: t.send_ns)
            self.assertIsNone(test[0].motion_residual_mps)
            self.assertAlmostEqual(test[1].motion_residual_mps, 190.0)
            self.assertIsNone(test[-1].motion_residual_mps)
            self.assertEqual(sum(t.motion_residual_mps is not None for t in test), 2)

    def test_resource_limit_and_missing_schema(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            src, _ = write_study(root, study_rows())
            with self.assertRaisesRegex(ValueError, "resource limit"):
                deduplicate_labeled_cams(src, SHA, max_rows=3)
            src.write_text("archive_sha256,source_split\nx,train\n", encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "missing normalized source fields"):
                deduplicate_labeled_cams(src, SHA)


if __name__ == "__main__":
    unittest.main()
