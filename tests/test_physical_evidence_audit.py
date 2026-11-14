"""Synthetic audit fixtures. These are NOT physical HIL safety tests."""
import hashlib
import json
import tempfile
import unittest
from pathlib import Path

from experiments.hardware.audit_physical_evidence import audit, CASES, SCHEMA


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()

def pinned(path):
    return {"path": path.name, "sha256": digest(path)}

GOOD = (
    "elapsed_sec,hardwired_estop_asserted,dummy_load_enabled,network_link_available\n"
    "0.000,0,1,1\n"
    "0.010,1,1,0\n"
    "0.020,1,0,0\n"
    "0.030,1,0,0\n"
)

class HILEvidenceAuditTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.calibration = self.root / "calibration.txt"
        self.calibration.write_text("FIXTURE NOT REAL CALIBRATION", encoding="utf-8")
        cases = []
        for name in CASES:
            path = self.root / f"{name}.csv"
            path.write_text(GOOD, encoding="utf-8")
            cases.append({"id":name,"capture":pinned(path),"witness_id":"witness_2"})
        self.manifest = self.root / "manifest.json"
        self.output = self.root / "report.json"
        self.data = {
            "schema": SCHEMA, "session_id":"synthetic_fixture_1",
            "apparatus_id":"dummy_load_fixture_1", "operator_id":"operator_1",
            "witness_id":"witness_2", "firmware_sha256":"a"*64,
            "bench_configuration":"isolated_dummy_load_no_vehicle",
            "instrument":"fake_CSV_generator_not_physical",
            "calibration":pinned(self.calibration), "cases":cases,
        }
        self.save()

    def save(self):
        self.manifest.write_text(json.dumps(self.data), encoding="utf-8")

    def test_digital_audit_never_proves_physical_hardware(self):
        result = audit(self.root, self.manifest, self.output)
        self.assertEqual(result["required_case_count"], 10)
        self.assertTrue(result["all_cases_structurally_audited"])
        for name in ("physical_hil_validated","publication_ready",
                     "vehicle_safety_certified",
                     "external_hardwired_estop_physically_verified",
                     "instrument_capture_authenticity_independently_verified"):
            self.assertFalse(result[name], name)
        self.assertTrue(self.output.exists())

    def test_changed_trace_cannot_pass_pinned_digest(self):
        path = self.root / "HIL-01.csv"
        path.write_text(GOOD + "0.040,1,0,0\n", encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "digest mismatch"):
            audit(self.root, self.manifest, self.output)

    def test_missing_case_refused(self):
        self.data["cases"].pop()
        self.save()
        with self.assertRaisesRegex(ValueError, "every required"):
            audit(self.root, self.manifest, self.output)

    def test_duplicate_case_refused(self):
        self.data["cases"][-1] = self.data["cases"][0]
        self.save()
        with self.assertRaisesRegex(ValueError, "every required"):
            audit(self.root, self.manifest, self.output)

    def test_same_operator_and_witness_refused(self):
        self.data["witness_id"] = "operator_1"
        self.save()
        with self.assertRaisesRegex(ValueError, "distinct"):
            audit(self.root, self.manifest, self.output)

    def test_invalid_live_vehicle_bench_refused(self):
        self.data["bench_configuration"] = "live_vehicle"
        self.save()
        with self.assertRaisesRegex(ValueError, "live vehicle"):
            audit(self.root, self.manifest, self.output)

    def test_missing_network_outage_refused(self):
        path = self.root / "HIL-03.csv"
        # Explicitly replace last binary column only, preserving valid transitions.
        path.write_text(GOOD.replace(",1,0\n", ",1,1\n").replace(",0,0\n", ",0,1\n"), encoding="utf-8")
        self.data["cases"][2]["capture"] = pinned(path)
        self.save()
        with self.assertRaisesRegex(ValueError, "network loss"):
            audit(self.root, self.manifest, self.output)

    def test_stop_that_never_disables_dummy_load_refused(self):
        path = self.root / "HIL-02.csv"
        path.write_text(
            GOOD.replace("0.020,1,0,0","0.020,1,1,0")
                .replace("0.030,1,0,0","0.030,1,1,0"), encoding="utf-8"
        )
        self.data["cases"][1]["capture"] = pinned(path)
        self.save()
        with self.assertRaisesRegex(ValueError, "no sampled"):
            audit(self.root, self.manifest, self.output)

    def test_reenergizing_under_stop_refused(self):
        path = self.root / "HIL-02.csv"
        path.write_text(GOOD+"0.040,1,1,0\n", encoding="utf-8")
        self.data["cases"][1]["capture"] = pinned(path)
        self.save()
        with self.assertRaisesRegex(ValueError, "re-energized"):
            audit(self.root, self.manifest, self.output)

    def test_backwards_instrument_time_refused(self):
        path = self.root / "HIL-02.csv"
        path.write_text(GOOD+"0.015,1,0,0\n", encoding="utf-8")
        self.data["cases"][1]["capture"] = pinned(path)
        self.save()
        with self.assertRaisesRegex(ValueError, "time not"):
            audit(self.root, self.manifest, self.output)

    def test_path_traversal_refused(self):
        self.data["cases"][0]["capture"]["path"] = "../HIL-01.csv"
        self.save()
        with self.assertRaisesRegex(ValueError, "traversal"):
            audit(self.root, self.manifest, self.output)

    def test_bad_calibration_digest_refused(self):
        self.data["calibration"]["sha256"] = "0"*64
        self.save()
        with self.assertRaisesRegex(ValueError, "digest mismatch"):
            audit(self.root, self.manifest, self.output)


if __name__ == "__main__":
    unittest.main()
