"""Synthetic protocol checks only; not publishable V2X effectiveness evidence."""
import hashlib
import tempfile
import unittest
from pathlib import Path
from research_contracts.heldout_campaign_descriptive_gate import evaluate

HEADER = "campaign_id,incident_id,label,baseline_score,candidate_score,split\n"

class CampaignGateTests(unittest.TestCase):
    def check(self, rows, digest=None):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "records.csv"
            path.write_text(HEADER + rows, encoding="utf-8")
            return evaluate(path, digest or hashlib.sha256(path.read_bytes()).hexdigest())

    def test_paired_improvement(self):
        result = self.check("a,1,0,1,0,test\na,2,1,0,1,test\n")
        self.assertEqual(result["campaign_equal_mean_difference"], 1.0)

    def test_digest_mismatch(self):
        with self.assertRaisesRegex(ValueError, "digest"):
            self.check("a,1,0,1,0,test\n", "0" * 64)

    def test_duplicate_incident(self):
        with self.assertRaisesRegex(ValueError, "duplicate"):
            self.check("a,1,0,1,0,test\na,1,1,0,1,test\n")

    def test_campaign_leakage(self):
        with self.assertRaisesRegex(ValueError, "leakage"):
            self.check("a,1,0,1,0,train\na,2,1,0,1,test\n")

    def test_single_class_is_not_scored(self):
        self.assertIsNone(self.check("a,1,0,1,0,test\n")["campaign_equal_mean_difference"])

    def test_invalid_decision(self):
        with self.assertRaisesRegex(ValueError, "nonbinary"):
            self.check("a,1,0,2,0,test\n")

if __name__ == "__main__":
    unittest.main()
