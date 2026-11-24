import hashlib
import json
import tempfile
import unittest
from pathlib import Path
from research_contracts.campaign_provenance import ProvenanceError, verify_manifest

class CampaignProvenanceTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        (self.root / "a.csv").write_bytes(b"synthetic A")
        (self.root / "b.csv").write_bytes(b"synthetic B")
        self.entries = [self.entry("a.csv", "train", "drive-1"), self.entry("b.csv", "test", "drive-2")]

    def entry(self, path, split, campaign):
        return {"path": path, "sha256": hashlib.sha256((self.root / path).read_bytes()).hexdigest(), "split": split, "campaign_id": campaign, "source": "synthetic-test-only"}

    def run_gate(self):
        manifest = self.root / "manifest.json"
        manifest.write_text(json.dumps({"recordings": self.entries}))
        return verify_manifest(manifest, self.root)

    def test_valid(self):
        self.assertEqual(self.run_gate()["verified_recordings"], 2)

    def test_tamper(self):
        (self.root / "a.csv").write_bytes(b"tampered")
        with self.assertRaisesRegex(ProvenanceError, "digest mismatch"):
            self.run_gate()

    def test_campaign_leakage(self):
        self.entries[1]["campaign_id"] = "drive-1"
        with self.assertRaisesRegex(ProvenanceError, "campaign leakage"):
            self.run_gate()

    def test_duplicate_bytes_cross_split(self):
        (self.root / "b.csv").write_bytes((self.root / "a.csv").read_bytes())
        self.entries[1] = self.entry("b.csv", "test", "drive-2")
        with self.assertRaisesRegex(ProvenanceError, "identical bytes"):
            self.run_gate()

    def test_path_traversal(self):
        self.entries[0]["path"] = "../outside.csv"
        with self.assertRaisesRegex(ProvenanceError, "unsafe"):
            self.run_gate()

    def test_duplicate_path(self):
        self.entries.append(self.entries[0].copy())
        with self.assertRaisesRegex(ProvenanceError, "duplicate path"):
            self.run_gate()

    def test_bad_digest(self):
        self.entries[0]["sha256"] = "bad"
        with self.assertRaisesRegex(ProvenanceError, "invalid sha256"):
            self.run_gate()

    def test_symlink(self):
        (self.root / "link.csv").symlink_to(self.root / "a.csv")
        self.entries[0]["path"] = "link.csv"
        with self.assertRaisesRegex(ProvenanceError, "symlinked"):
            self.run_gate()

if __name__ == "__main__":
    unittest.main()
