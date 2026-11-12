import tempfile
import unittest
from pathlib import Path
from experiments.v2x.audit_incident_splits import audit

HEADER = "source_id,incident_id,group_id,split,label,label_provenance\n"


class IncidentAuditTests(unittest.TestCase):
    def check(self, lines, error=None):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "manifest.csv"
            path.write_text(HEADER + lines, encoding="utf-8")
            if error:
                with self.assertRaisesRegex(ValueError, error):
                    audit(path)
            else:
                return audit(path)

    def test_valid_structure_not_publication_evidence(self):
        report = self.check("v,1,driveA,train,1,manual_annotation\nv,2,driveB,test,0,manual_annotation\n")
        self.assertEqual(report["rows"], 2)
        self.assertFalse(report["publication_ready"])
        self.assertFalse(report["independent_ground_truth_verified"])

    def test_group_leakage(self):
        self.check("v,1,driveA,train,1,manual_annotation\nv,2,driveA,test,0,manual_annotation\n", "group leakage")

    def test_duplicate(self):
        self.check("v,1,driveA,train,1,manual_annotation\nv,1,driveA,train,1,manual_annotation\n", "duplicate")

    def test_self_reported_label(self):
        self.check("v,1,driveA,train,1,cam_attacker\n", "unsupported")

    def test_missing_provenance(self):
        self.check("v,1,driveA,train,1,\n", "empty")

    def test_invalid_label(self):
        self.check("v,1,driveA,train,maybe,manual_annotation\n", "invalid")

    def test_invalid_split(self):
        self.check("v,1,driveA,holdout,1,manual_annotation\n", "invalid")

    def test_missing_column(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "manifest.csv"
            path.write_text("incident_id,split\n1,train\n")
            with self.assertRaisesRegex(ValueError, "missing required"):
                audit(path)


if __name__ == "__main__":
    unittest.main()
