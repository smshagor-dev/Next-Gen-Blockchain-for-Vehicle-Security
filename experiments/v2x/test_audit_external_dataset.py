"""Synthetic provenance fixtures only; no real-world dataset claim."""
import csv
import hashlib
import io
import json
import unittest
from audit_external_dataset import audit, sha, SPLIT_COLUMNS


def index(rows):
    out = io.StringIO(newline="")
    w = csv.writer(out)
    w.writerow(SPLIT_COLUMNS)
    w.writerows(rows)
    return out.getvalue().encode()


class ExternalDatasetAuditTests(unittest.TestCase):
    def setUp(self):
        self.archive = b"synthetic archive placeholder"
        self.split = index([
            ("r1", "drive1", "train", "benign"),
            ("r2", "drive1", "train", "attack"),
            ("r3", "drive2", "test", "attack"),
            ("r4", "drive3", "validation", "benign"),
        ])
        self.meta = {
            "schema_version": 1, "dataset_name": "synthetic_fixture",
            "dataset_family": "can_intrusion",
            "source_url": "https://example.org/data",
            "source_release": "synthetic-1",
            "license_id": "TEST-ONLY", "license_url": "https://example.org/license",
            "retrieved_utc": "2026-01-01T00:00:00Z",
            "original_archive_sha256": sha(self.archive),
            "original_archive_bytes": len(self.archive),
            "extractor_commit": "a" * 64,
            "annotation_protocol": "synthetic test labels",
            "split_protocol": "disjoint source drive IDs",
            "split_index_sha256": sha(self.split),
            "split_index_bytes": len(self.split),
        }

    def check(self, *, archive=None, split=None, meta=None, pin=None):
        m = self.meta if meta is None else meta
        raw = json.dumps(m, sort_keys=True).encode()
        return audit(raw, self.archive if archive is None else archive,
                     self.split if split is None else split,
                     pinned_manifest_sha256=sha(raw) if pin is None else pin)

    def test_valid_audit_is_not_publication_evidence(self):
        r = self.check()
        self.assertEqual(r["split_counts"], {"train": 2, "test": 1, "validation": 1})
        self.assertEqual(r["unique_source_groups"], 3)
        self.assertFalse(r["publication_ready"])

    def test_archive_tamper(self):
        with self.assertRaisesRegex(ValueError, "original_archive SHA"):
            self.check(archive=self.archive + b"x")

    def test_manifest_pin_tamper(self):
        with self.assertRaisesRegex(ValueError, "externally pinned"):
            self.check(pin="0" * 64)

    def test_split_tamper(self):
        with self.assertRaisesRegex(ValueError, "split_index byte count"):
            self.check(split=self.split + b"x")

    def test_group_leakage_rejected_even_for_different_records(self):
        split = index([("a", "same-drive", "train", "0"),
                       ("b", "same-drive", "test", "1")])
        m = dict(self.meta, split_index_sha256=sha(split), split_index_bytes=len(split))
        with self.assertRaisesRegex(ValueError, "group leakage"):
            self.check(split=split, meta=m)

    def test_duplicate_record_rejected(self):
        split = index([("a", "train-drive", "train", "0"),
                       ("a", "test-drive", "test", "1")])
        m = dict(self.meta, split_index_sha256=sha(split), split_index_bytes=len(split))
        with self.assertRaisesRegex(ValueError, "duplicate source record"):
            self.check(split=split, meta=m)

    def test_label_free_test_missing_rejected(self):
        split = index([("a", "train-drive", "train", "0")])
        m = dict(self.meta, split_index_sha256=sha(split), split_index_bytes=len(split))
        with self.assertRaisesRegex(ValueError, "nonempty train and test"):
            self.check(split=split, meta=m)

    def test_wrong_dataset_family(self):
        with self.assertRaisesRegex(ValueError, "unsupported dataset family"):
            self.check(meta=dict(self.meta, dataset_family="unverified"))

    def test_extra_metadata_rejected(self):
        with self.assertRaisesRegex(ValueError, "schema mismatch"):
            self.check(meta=dict(self.meta, certified=True))

    def test_wrong_sha_format(self):
        with self.assertRaisesRegex(ValueError, "invalid provenance digest"):
            self.check(meta=dict(self.meta, extractor_commit="not-a-hash"))

    def test_missing_license(self):
        with self.assertRaisesRegex(ValueError, "missing provenance field"):
            self.check(meta=dict(self.meta, license_id=""))

    def test_non_https_source(self):
        with self.assertRaisesRegex(ValueError, "HTTPS"):
            self.check(meta=dict(self.meta, source_url="http://example.org/data"))

    def test_non_utc_retrieval(self):
        with self.assertRaisesRegex(ValueError, "must be UTC"):
            self.check(meta=dict(self.meta, retrieved_utc="2026-01-01T01:00:00+01:00"))

    def test_bool_byte_count_rejected(self):
        with self.assertRaisesRegex(ValueError, "byte count"):
            self.check(meta=dict(self.meta, original_archive_bytes=True))

    def test_duplicate_json_key_rejected(self):
        raw = json.dumps(self.meta).encode()
        raw = raw.replace(b'"schema_version": 1', b'"schema_version": 1, "schema_version": 1')
        with self.assertRaisesRegex(ValueError, "duplicate"):
            audit(raw, self.archive, self.split, pinned_manifest_sha256=sha(raw))

    def test_split_schema_rejects_label_omission(self):
        split = index([("a", "g1", "train", "0"), ("b", "g2", "test", "1")])
        split = split.replace(b"source_record_id,source_group_id,split,label", b"source_record_id,source_group_id,split,ground_truth")
        m = dict(self.meta, split_index_sha256=sha(split), split_index_bytes=len(split))
        with self.assertRaisesRegex(ValueError, "split index schema"):
            self.check(split=split, meta=m)


if __name__ == "__main__":
    unittest.main()
