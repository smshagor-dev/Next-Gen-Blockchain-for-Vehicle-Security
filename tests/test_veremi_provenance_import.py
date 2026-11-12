"""Synthetic ZIP contract tests; no real VeReMi data or empirical claims."""
import csv
import hashlib
import json
import tempfile
import unittest
import zipfile
from pathlib import Path

from experiments.datasets.veremi_nextgen_import import import_archive, normalize_cam, sha256_file


def cam(label=0, message_id=1, sender="vehicle-a"):
    return {
        "rcvTime": 1021.25, "sendTime": 1020.75,
        "sender_id": sender, "sender_alias": 7, "messageID": message_id,
        "attacker": label,
        "receiver": {
            "pos": [5.0, 10.0, 0.0], "pos_noise": [0.01, 0.01, 0.0],
            "spd": 12.0, "spd_noise": 0.01,
            "acl": 0.0, "acl_noise": 0.01, "hed": 42.0,
            "hed_noise": 0.0, "driversProfile": "Normal",
        },
        "sender": {
            "pos": [8.0, 11.0, 0.0], "pos_noise": [0.02, 0.02, 0.0],
            "spd": 13.0, "spd_noise": 0.02,
            "acl": 0.1, "acl_noise": 0.01, "hed": 43.0,
            "hed_noise": 0.0, "driversProfile": "Normal",
            "distance_to_road_edge": 1.0,
        },
    }


def archive_with(path, files):
    with zipfile.ZipFile(path, "w") as out:
        for name, rows in files.items():
            out.writestr(name, json.dumps(rows).encode("utf-8"))
    return sha256_file(path)


def imported(path, output_dir, checksum, **kw):
    return import_archive(
        path, output_dir, expected_sha256=checksum, split="test",
        attack_subset="dataReplay", release_tag="synthetic-fixture-only", **kw
    )


class VeremiImportContractTests(unittest.TestCase):
    def test_multiple_receivers_preserve_repeated_cam_not_new_incident(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            archive = root / "fake.zip"
            sha = archive_with(archive, {
                "scenario/receiver-1.json": [cam(0), cam(1, 2)],
                "scenario/receiver-2.json": [cam(0)],
            })
            result = imported(archive, root / "out", sha)
            self.assertEqual(result["received_cam_rows"], 3)
            self.assertEqual(result["cam_attacker_label_one_rows"], 1)
            self.assertEqual(result["receiver_json_files"], 2)
            self.assertFalse(result["publication_ready"])
            self.assertEqual(result["coordinate_system"], "source_planar_xyz_not_geodetic_lat_lon")
            self.assertEqual(result["evaluation_unit"], "per_receiver_CAM_record_not_independent_hazard_incident")
            csv_path = root / "out/veremi_cam_messages.csv"
            self.assertEqual(result["normalized_csv_sha256"], sha256_file(csv_path))
            with csv_path.open(newline="", encoding="utf-8") as src:
                records = list(csv.DictReader(src))
            self.assertEqual(len(records), 3)
            self.assertEqual(records[0]["attacker_label"], "0")
            self.assertEqual(records[0]["sender_id"], "vehicle-a")
            self.assertEqual(records[0]["sender_pos_x"], "8.0")
            self.assertEqual(records[2]["message_id"], "1")
            self.assertNotIn("incident_id", records[0])
            self.assertNotIn("lat", records[0])
            self.assertEqual(records[0]["archive_sha256"], sha)
            metadata = json.loads((root / "out/veremi_cam_manifest.json").read_text())
            self.assertEqual(metadata["source_sha256_verified"], sha)

    def test_archive_hash_mismatch_fail_closed_before_import(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            archive = root / "fake.zip"
            archive_with(archive, {"receiver.json": [cam()]})
            with self.assertRaisesRegex(ValueError, "SHA-256"):
                imported(archive, root / "out", "0" * 64)
            self.assertFalse((root / "out/veremi_cam_messages.csv").exists())

    def test_malformed_attacker_label_must_not_be_silently_cast(self):
        for bad in (True, "1", 2, -1, None):
            with self.subTest(label=bad):
                with self.assertRaisesRegex(ValueError, "attacker label"):
                    normalize_cam(cam(bad), receiver_log="r.json", index=0,
                                  sha="a" * 64, subset="dataReplay")

    def test_invalid_numeric_source_values_rejected(self):
        for field, bad in (("sendTime", float("nan")), ("rcvTime", float("inf")),
                           ("sender_alias", True), ("messageID", -1)):
            with self.subTest(field=field):
                source = cam()
                source[field] = bad
                with self.assertRaises(ValueError):
                    normalize_cam(source, receiver_log="r.json", index=0, sha="a" * 64, subset="subset")

    def test_receiver_and_sender_coordinates_are_planar_not_geodetic(self):
        normalized = normalize_cam(cam(), receiver_log="r", index=0,
                                   sha="a" * 64, subset="constantPositionOffset")
        self.assertEqual(normalized["sender_pos_y"], "11.0")
        self.assertEqual(normalized["receiver_pos_x"], "5.0")
        self.assertNotIn("latitude", normalized)
        self.assertNotIn("longitude", normalized)

    def test_reject_zip_traversal_name_without_extracting(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            archive = root / "bad.zip"
            sha = archive_with(archive, {"../outside.json": [cam()]})
            with self.assertRaisesRegex(ValueError, "unsafe ZIP entry"):
                imported(archive, root / "out", sha)
            self.assertFalse((root / "outside.json").exists())

    def test_resource_caps_do_not_silently_skip_rows(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            archive = root / "big.zip"
            sha = archive_with(archive, {"r1.json": [cam()], "r2.json": [cam()]})
            with self.assertRaisesRegex(ValueError, "file count exceeded"):
                imported(archive, root / "out", sha, max_json_files=1)
            with self.assertRaisesRegex(ValueError, "decompressed size"):
                imported(archive, root / "out2", sha, max_entry_bytes=4)

    def test_no_receiver_json_is_invalid_source_dataset(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            archive = root / "empty.zip"
            with zipfile.ZipFile(archive, "w") as z:
                z.writestr("README.txt", "no JSON")
            with self.assertRaisesRegex(ValueError, "no receiver JSON"):
                imported(archive, root / "out", sha256_file(archive))

    def test_source_label_does_not_define_incident_truth(self):
        observed = normalize_cam(cam(1), receiver_log="r", index=0,
                                 sha="a" * 64, subset="dataReplay")
        self.assertEqual(observed["attacker_label"], 1)
        self.assertNotIn("ground_truth_incident", observed)
        self.assertNotIn("session_verified", observed)

    def test_declared_split_and_release_are_not_inferred(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            archive = root / "fake.zip"
            sha = archive_with(archive, {"r.json": [cam()]})
            with self.assertRaisesRegex(ValueError, "split must"):
                import_archive(archive, root / "out", expected_sha256=sha,
                               split="other", attack_subset="dataReplay", release_tag="v1")
            report = imported(archive, root / "out", sha)
            self.assertEqual(report["split_declared"], "test")
            self.assertEqual(report["source_release_tag_declared"], "synthetic-fixture-only")


if __name__ == "__main__":
    unittest.main()
