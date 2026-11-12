"""Synthetic transfer-contract tests only; never publication evidence."""
from __future__ import annotations

import csv
import hashlib
import json
import tempfile
import unittest
from pathlib import Path

from experiments.cam.highway_to_urban_transfer import run_transfer

HW = "a" * 64
URBAN = "b" * 64
FIELDS = [
    "archive_sha256", "source_split", "receiver_log", "sender_id",
    "sender_alias", "message_id", "send_time_raw", "receive_time_raw",
    "sender_acceleration", "sender_pos_x", "sender_pos_y", "sender_speed",
    "attacker_label",
]


def message(archive, split, msgid, label, *, sender, when=1_000_000_000,
            age=100, x=0, speed=10, accel=0.1, receiver=None):
    return {
        "archive_sha256": archive,
        "source_split": split,
        "receiver_log": receiver or f"receiver-{sender}-{msgid}.json",
        "sender_id": sender, "sender_alias": "42",
        "message_id": str(msgid),
        "send_time_raw": str(when),
        "receive_time_raw": str(when + age),
        "sender_acceleration": str(accel), "sender_pos_x": str(x),
        "sender_pos_y": "0", "sender_speed": str(speed),
        "attacker_label": str(label),
    }


def rows(archive, prefix):
    output = [message(archive, "train", 600, 0, sender=prefix + "train")]
    output += [
        message(
            archive, "validation", i, 0, sender=prefix + "validation",
            when=1_000_000_000 + i * 1_000_000_000, x=i * 10, age=i,
            accel=i / 100,
        )
        for i in range(1, 23)
    ]
    output += [
        message(archive, "test", 100, 1, sender=prefix + "test",
                when=100_000_000_000, age=60, x=0),
        message(archive, "test", 101, 1, sender=prefix + "test",
                when=101_000_000_000, age=1, x=200, accel=0.5),
        message(archive, "test", 102, 0, sender=prefix + "test",
                when=102_000_000_000, age=5, x=210),
        message(archive, "test", 103, 0, sender=prefix + "test",
                when=103_000_000_000, age=90, x=310, accel=0.9),
    ]
    return output


def write_rows(root: Path, name: str, archive: str, records):
    file = root / (name + ".csv")
    with file.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=FIELDS)
        writer.writeheader()
        writer.writerows(records)
    manifest = root / (name + ".json")
    manifest.write_text(json.dumps({
        "normalized_csv_sha256": hashlib.sha256(file.read_bytes()).hexdigest(),
        "source_sha256_verified": archive,
        "evaluation_unit": "per_receiver_CAM_record_not_independent_hazard_incident",
        "attack_subset_declared": "dataReplay",
    }), encoding="utf-8")
    return file, manifest


class HighwayToUrbanTransferTests(unittest.TestCase):
    def sources(self, root, *, highway=None, urban=None):
        highway = highway if highway is not None else rows(HW, "h")
        urban = urban if urban is not None else rows(URBAN, "u")
        x, xm = write_rows(root, "highway", HW, highway)
        y, ym = write_rows(root, "urban", URBAN, urban)
        return x, xm, y, ym

    def transfer(self, root, *, highway=None, urban=None):
        args = self.sources(root, highway=highway, urban=urban)
        return run_transfer(*args, root / "output", source_sha256=HW, target_sha256=URBAN)

    def test_external_test_scored_with_frozen_highway_calibration(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            result = self.transfer(root)
            self.assertEqual(result["status"], "exploratory_cross_scenario_cam_transfer")
            self.assertEqual(result["calibration_partition"], "source_highway_2_validation_benign_only")
            self.assertEqual(result["evaluation_partition"], "target_urban_2_test_only")
            self.assertEqual(result["source_frozen_thresholds"]["age_ns_upper"], 22)
            self.assertAlmostEqual(result["source_frozen_thresholds"]["temporal_motion_residual_mps_upper"], 0)
            self.assertEqual(result["target_fingerprint_audit"]["test_distinct_fingerprints"], 4)
            self.assertEqual(result["methods"]["temporal_motion_residual_p99"]["tp"], 1)
            self.assertEqual(result["methods"]["temporal_motion_residual_p99"]["fp"], 1)
            self.assertEqual(result["methods"]["temporal_motion_residual_p99"]["fn"], 1)
            self.assertFalse(result["publication_ready"])
            self.assertFalse(result["confirmatory_study"])
            self.assertFalse(result["statistical_significance"])
            self.assertTrue((root / "output/cam_transfer_provenance.json").is_file())
            self.assertTrue((root / "output/cam_transfer_results.csv").is_file())

    def test_mutating_urban_validation_cannot_change_frozen_thresholds(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            initial = self.transfer(root)
            modified = rows(URBAN, "u")
            for item in modified:
                if item["source_split"] == "validation":
                    item["sender_acceleration"] = "1000000"
                    item["receive_time_raw"] = str(int(item["send_time_raw"]) + 90000000)
                    item["attacker_label"] = "1"
            changed = self.transfer(root, urban=modified)
            self.assertEqual(initial["source_frozen_thresholds"], changed["source_frozen_thresholds"])
            self.assertEqual(initial["methods"], changed["methods"])

    def test_mutating_external_test_labels_does_not_refit_threshold(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            first = self.transfer(root)
            edited = rows(URBAN, "u")
            # Modify one target Test label only. The validation thresholds
            # must remain unchanged, while confusion counts must change.
            edited[-1]["attacker_label"] = "1"
            second = self.transfer(root, urban=edited)
            self.assertEqual(first["source_frozen_thresholds"], second["source_frozen_thresholds"])
            self.assertNotEqual(first["methods"]["receive_age_p99"]["tp"], second["methods"]["receive_age_p99"]["tp"])

    def test_cross_scenario_identical_fingerprint_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            target = rows(URBAN, "u")
            source = rows(HW, "h")
            for field in ("sender_id", "sender_alias", "message_id", "send_time_raw"):
                target[0][field] = source[0][field]
            with self.assertRaisesRegex(ValueError, "source/target fingerprint intersection"):
                self.transfer(root, highway=source, urban=target)

    def test_tampered_source_and_target_hashes_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            x, xm, y, ym = self.sources(root)
            with self.assertRaisesRegex(ValueError, "normalized input SHA-256 mismatch"):
                x.write_text(x.read_text(encoding="utf-8") + "\n", encoding="utf-8")
                run_transfer(x, xm, y, ym, root / "out", source_sha256=HW, target_sha256=URBAN)
            x, xm, y, ym = self.sources(root)
            with self.assertRaisesRegex(ValueError, "normalized input SHA-256 mismatch"):
                y.write_text(y.read_text(encoding="utf-8") + "\n", encoding="utf-8")
                run_transfer(x, xm, y, ym, root / "out", source_sha256=HW, target_sha256=URBAN)

    def test_invalid_or_same_archive_digests_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            args = self.sources(root)
            for sha_a, sha_b in ((HW, HW), ("xyz", URBAN), (HW, "f" * 63)):
                with self.subTest(source=sha_a, target=sha_b), self.assertRaises(ValueError):
                    run_transfer(*args, root / "out", source_sha256=sha_a, target_sha256=sha_b)

    def test_fingerprint_repetition_and_cross_split_guard_remain_active(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source = rows(HW, "h")
            target = rows(URBAN, "u")
            copy = dict(target[0])
            copy["source_split"] = "test"
            copy["receiver_log"] = "test-copy"
            target.append(copy)
            with self.assertRaisesRegex(ValueError, "crosses train/validation/test"):
                self.transfer(root, highway=source, urban=target)

    def test_unlabeled_external_test_not_treated_as_benign(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            modified = rows(URBAN, "u")
            modified[-1]["attacker_label"] = ""
            with self.assertRaisesRegex(ValueError, "missing or ambiguous"):
                self.transfer(root, urban=modified)

    def test_missing_external_class_rejected_instead_of_synthetic_balance(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            target = rows(URBAN, "u")
            for item in target:
                if item["source_split"] == "test":
                    item["attacker_label"] = "0"
            with self.assertRaisesRegex(ValueError, "positive and negative"):
                self.transfer(root, urban=target)


if __name__ == "__main__":
    unittest.main()
