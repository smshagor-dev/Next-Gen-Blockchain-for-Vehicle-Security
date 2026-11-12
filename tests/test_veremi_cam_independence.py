"""Synthetic schema tests only for disk-backed CAM independence audit."""
import csv
import hashlib
import json
import tempfile
import unittest
from pathlib import Path

from experiments.datasets.audit_cam_independence import audit

ARCHIVE_SHA = "a" * 64
HEADER = ["archive_sha256", "source_split", "receiver_log", "sender_id",
          "sender_alias", "message_id", "send_time_raw", "attacker_label"]


def cam(split, receiver, label="", *, sender="car-1", message_id="1", send_time="1000"):
    return {
        "archive_sha256": ARCHIVE_SHA, "source_split": split,
        "receiver_log": receiver, "sender_id": sender, "sender_alias": "alias1",
        "message_id": message_id, "send_time_raw": send_time,
        "attacker_label": label,
    }


def write_case(root, rows):
    root = Path(root)
    inp = root / "normalized.csv"
    with inp.open("w", newline="", encoding="utf-8") as target:
        writer = csv.DictWriter(target, fieldnames=HEADER)
        writer.writeheader()
        writer.writerows(rows)
    digest = hashlib.sha256(inp.read_bytes()).hexdigest()
    manifest = root / "manifest.json"
    manifest.write_text(json.dumps({
        "source_sha256_verified": ARCHIVE_SHA, "normalized_csv_sha256": digest,
        "received_cam_rows": len(rows),
    }), encoding="utf-8")
    return inp, manifest


class AuditIndependenceTests(unittest.TestCase):
    def test_cross_receiver_duplicate_and_cross_split_overlap_are_separate(self):
        with tempfile.TemporaryDirectory() as tmp:
            rows = [
                cam("train", "receiver-a", "0"),
                cam("train", "receiver-b", "0"),
                cam("test", "receiver-c", "1"),  # conflicting label + same fingerprint
                cam("test", "receiver-c", "1", sender="car-2"),
                cam("validation", "receiver-d", "", message_id="2"),
            ]
            inp, manifest = write_case(tmp, rows)
            result = audit(inp, manifest, Path(tmp) / "results/audit.json")
            self.assertEqual(result["counts"]["cam_receptions"], 5)
            self.assertEqual(result["counts"]["unique_message_fingerprints"], 3)
            self.assertEqual(result["counts"]["repeated_receptions"], 2)
            self.assertEqual(result["counts"]["cross_receiver_fingerprint_repeat"], 2)
            self.assertEqual(result["counts"]["cross_split_unique_fingerprints"], 1)
            self.assertEqual(result["counts"]["cross_split_receptions"], 1)
            self.assertEqual(result["counts"]["conflicting_labels_on_same_fingerprint"], 1)
            self.assertEqual(result["per_source_split"]["train"]["cam_receptions"], 2)
            self.assertEqual(result["per_source_split"]["test"]["label_1"], 2)
            self.assertFalse(result["publication_ready"])
            self.assertTrue((Path(tmp) / "results/audit.json").exists())

    def test_repeated_same_receiver_is_not_cross_receiver_independence(self):
        with tempfile.TemporaryDirectory() as tmp:
            inp, manifest = write_case(tmp, [
                cam("train", "r1", "0"),
                cam("train", "r1", "0"),
            ])
            stats = audit(inp, manifest, Path(tmp) / "out.json")["counts"]
            self.assertEqual(stats["same_receiver_fingerprint_repeat"], 1)
            self.assertNotIn("cross_receiver_fingerprint_repeat", stats)

    def test_different_sender_with_same_message_number_not_duplicate(self):
        with tempfile.TemporaryDirectory() as tmp:
            inp, manifest = write_case(tmp, [
                cam("train", "r1", "0", sender="car-1"),
                cam("test", "r2", "0", sender="car-2"),
            ])
            stats = audit(inp, manifest, Path(tmp) / "audit.json")["counts"]
            self.assertEqual(stats["unique_message_fingerprints"], 2)
            self.assertNotIn("cross_split_unique_fingerprints", stats)

    def test_hash_mismatch_rejects_modified_input(self):
        with tempfile.TemporaryDirectory() as tmp:
            inp, manifest = write_case(tmp, [cam("train", "r1")])
            inp.write_text(inp.read_text() + "\n", encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "SHA-256 mismatch"):
                audit(inp, manifest, Path(tmp) / "out.json")

    def test_untrusted_metadata_or_label_fails_closed(self):
        with tempfile.TemporaryDirectory() as tmp:
            for bad in (
                cam("train", "r1", "2"),
                cam("invalid", "r1", "0"),
                cam("test", "", "1"),
                cam("test", "r1", "1", sender=""),
            ):
                inp, manifest = write_case(tmp, [bad])
                with self.subTest(row=bad), self.assertRaisesRegex(ValueError, "invalid|missing"):
                    audit(inp, manifest, Path(tmp) / "out.json")

    def test_empty_csv_not_treated_as_evidence(self):
        with tempfile.TemporaryDirectory() as tmp:
            inp, manifest = write_case(tmp, [])
            with self.assertRaisesRegex(ValueError, "empty normalized"):
                audit(inp, manifest, Path(tmp) / "out.json")


if __name__ == "__main__":
    unittest.main()
