"""Fixture tests of external source ingest; fixtures are NOT real CAM research."""
import csv
import hashlib
import json
import tempfile
import unittest
from pathlib import Path

from experiments.datasets.external_negative_control import describe


class ExternalNegativeControlTests(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.TemporaryDirectory()
        self.addCleanup(self.dir.cleanup)
        self.path = Path(self.dir.name) / "source.csv"
        self.output = Path(self.dir.name) / "out.json"

    def write(self, data: str):
        self.path.write_text(data, encoding="utf-8")
        return hashlib.md5(self.path.read_bytes()).hexdigest()

    def test_descriptive_only_no_claims(self):
        md5 = self.write("device_id,ts,message\nnode1,2026-06-02T15:44:22Z,CAM\n")
        result = describe(self.path, self.output, expected_md5=md5)
        self.assertEqual(result["observed_cam_rows"], 1)
        self.assertEqual(result["source_md5"], md5)
        self.assertFalse(result["v2x_incident_accuracy_measurable"])
        self.assertFalse(result["publication_ready"])
        self.assertFalse(result["live_authenticated_hub_capture_verified"])
        self.assertFalse(result["direct_independent_collision_truth_verified"])
        self.assertEqual(json.loads(self.output.read_text()), result)

    def test_tab_delimited_provider_format(self):
        md5 = self.write("device_id\tts\tmessage\nnode1\t0\tCAM\nnode2\t1\tCAM\n")
        result = describe(self.path, self.output, expected_md5=md5)
        self.assertEqual(result["observed_cam_rows"], 2)

    def test_semicolon_delimiter(self):
        md5 = self.write("device_id;time;payload\nnode1;0;CAM\n")
        self.assertEqual(describe(self.path, self.output, expected_md5=md5)["observed_cam_rows"], 1)

    def test_wrong_digest_fails_closed_without_output(self):
        self.write("id,time\n1,0\n")
        with self.assertRaisesRegex(ValueError, "digest mismatch"):
            describe(self.path, self.output, expected_md5="0" * 32)
        self.assertFalse(self.output.exists())

    def test_duplicate_headers_refused(self):
        md5 = self.write("id,id\n1,2\n")
        with self.assertRaisesRegex(ValueError, "schema"):
            describe(self.path, self.output, expected_md5=md5)

    def test_malformed_record_refused(self):
        md5 = self.write("id,time,kind\n1,0,CAM\n2,0\n")
        with self.assertRaisesRegex(ValueError, "irregular"):
            describe(self.path, self.output, expected_md5=md5)

    def test_no_data_rows_refused(self):
        md5 = self.write("id,time\n")
        with self.assertRaisesRegex(ValueError, "no data"):
            describe(self.path, self.output, expected_md5=md5)

    def test_no_delimiter_refused(self):
        md5 = self.write("singlefield\nbadrow\n")
        with self.assertRaisesRegex(ValueError, "delimiters"):
            describe(self.path, self.output, expected_md5=md5)


    def test_descriptive_sender_warning_flags_are_not_hazard_ground_truth(self):
        md5 = self.write(
            "stationId,receiverID,collisionWarningEngaged,emergencyBrakeEngaged\n"
            "node1,rsu1,true,false\n"
            "node1,rsu1,false,true\n"
            "node2,rsu2,,false\n"
        )
        result = describe(self.path, self.output, expected_md5=md5)
        self.assertEqual(
            result["reported_CAM_flag_counts_not_incident_truth"]["collisionWarningEngaged"],
            {"MISSING": 1, "false": 1, "true": 1},
        )
        self.assertEqual(
            result["distinct_sender_station_ids_not_physical_identity"], 2
        )
        self.assertEqual(
            result["distinct_reported_receiver_ids_not_physical_identity"], 2
        )
        self.assertFalse(result["v2x_incident_accuracy_measurable"])

    def test_invalid_md5_pin_refused(self):
        self.write("id,time\n1,0\n")
        with self.assertRaisesRegex(ValueError, "invalid externally pinned"):
            describe(self.path, self.output, expected_md5="invalid")


if __name__ == "__main__":
    unittest.main()
