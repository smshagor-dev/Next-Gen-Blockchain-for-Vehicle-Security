"""Synthetic contracts only; not publishable scientific results."""
import hashlib
import json
import unittest
from experiments.v2x.audit_recording_split_leakage import audit

D = "a" * 64
def row(i, split="train", digest=D, group="recording-1"):
    return {"trial_id": f"t{i}", "split": split, "source_sha256": digest,
            "recording_group": group, "incident_id": f"i{i}"}
def encode(rows):
    return json.dumps({"trials": rows}).encode()

class RecordingSplitAuditTests(unittest.TestCase):
    def test_valid_same_group_same_split(self):
        result = audit(encode([row(1), row(2)]))
        self.assertEqual(result["recording_groups"], 1)
        self.assertEqual(result["split_counts"]["train"], 2)
    def test_recording_leakage(self):
        with self.assertRaisesRegex(ValueError, "leakage"):
            audit(encode([row(1), row(2, split="test")]))
    def test_same_source_different_group_leakage(self):
        with self.assertRaisesRegex(ValueError, "leakage"):
            audit(encode([row(1), row(2, split="test", group="other")]))
    def test_distinct_sources_accepted(self):
        self.assertEqual(audit(encode([row(1), row(2, "test", "b"*64, "other")]))["trial_count"], 2)
    def test_duplicate_incident(self):
        a, b = row(1), row(2)
        b["incident_id"] = a["incident_id"]
        with self.assertRaisesRegex(ValueError, "duplicate"):
            audit(encode([a, b]))
    def test_duplicate_json_keys(self):
        with self.assertRaisesRegex(ValueError, "duplicate JSON"):
            audit(b'{"trials":[],"trials":[]}')
    def test_invalid_digest(self):
        with self.assertRaisesRegex(ValueError, "digest"):
            audit(encode([row(1, digest="invalid")]))
    def test_unknown_field(self):
        a = row(1); a["label"] = "attack"
        with self.assertRaisesRegex(ValueError, "schema"):
            audit(encode([a]))
    def test_empty_rejected(self):
        with self.assertRaisesRegex(ValueError, "nonempty"):
            audit(encode([]))
    def test_digest_is_exact_raw_bytes(self):
        raw = encode([row(1)])
        self.assertEqual(audit(raw)["input_sha256"], hashlib.sha256(raw).hexdigest())

if __name__ == "__main__":
    unittest.main()
