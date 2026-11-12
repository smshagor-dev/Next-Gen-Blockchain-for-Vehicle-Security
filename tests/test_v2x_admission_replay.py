"""Offline-replay evaluator contract tests using fabricated fixture rows only."""
import csv
import hashlib
import json
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

from experiments.v2x.evaluate_admission import COLUMNS, read_trace, run

START = datetime(2026, 11, 12, 15, 0, tzinfo=timezone.utc)


def record(seq, incident, node, *, truth=True, verified=True, diff=0,
           lat=51.5, lon=-0.1, observed=None, sensor=None):
    received = START + timedelta(milliseconds=diff)
    return {
        "experiment_id": "synthetic-contract-only", "scenario_id": "unit-test",
        "seed": "0", "seq": str(seq), "received_at": received.isoformat(),
        "session_verified": "1" if verified else "0",
        "node_id": node, "ground_truth_incident": "1" if truth else "0",
        "incident_id": incident, "event_class": "ROAD_HAZARD",
        "observed_at": (observed or received).isoformat(), "lat": str(lat),
        "lon": str(lon),
        "sensor_sha256": hashlib.sha256((sensor or f"{node}-{seq}").encode()).hexdigest(),
    }


def write_fixture(path, rows):
    with path.open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=COLUMNS)
        writer.writeheader()
        writer.writerows(rows)


class EventReplayTests(unittest.TestCase):
    def test_matched_baseline_exposes_security_availability_tradeoff(self):
        with tempfile.TemporaryDirectory() as tmp:
            src = Path(tmp) / "fake.csv"
            # One true report never gets corroborated; two false colluding
            # sources can defeat quorum, demonstrating an explicit limitation.
            data = [
                record(1, "true-two", "CAR1", diff=0),
                record(2, "false-one", "BAD1", truth=False, diff=100),
                record(3, "true-two", "CAR2", diff=200),
                record(4, "true-one", "CAR3", diff=300),
                record(5, "false-two", "BAD1", truth=False, diff=400),
                record(6, "false-two", "BAD2", truth=False, diff=500),
            ]
            write_fixture(src, data)
            report = run(src, Path(tmp) / "out")
            self.assertFalse(report["publication_ready"])
            self.assertEqual(report["incident_count"], 4)
            auth = report["methods"]["authenticated_only"]
            gate = report["methods"]["evidence_quorum_2"]
            strict = report["methods"]["ablation_quorum_3"]
            self.assertEqual(auth["tp_incidents"], 2)
            self.assertEqual(auth["fp_incidents"], 2)
            self.assertEqual(gate["tp_incidents"], 1)
            self.assertEqual(gate["fp_incidents"], 1)
            self.assertEqual(gate["fn_incidents"], 1)
            self.assertEqual(strict["tp_incidents"], 0)
            self.assertEqual(gate["mean_time_to_alert_ms"], 200.0)
            self.assertTrue((Path(tmp) / "out/admission_decisions.csv").exists())
            self.assertTrue((Path(tmp) / "out/admission_manifest.json").exists())
            self.assertNotIn("statistical_significance", str(report))

    def test_unverified_source_cannot_contribute_to_independent_votes(self):
        with tempfile.TemporaryDirectory() as tmp:
            src = Path(tmp) / "fake.csv"
            write_fixture(src, [
                record(1, "hazard", "CAR1", diff=0, verified=False),
                record(2, "hazard", "CAR2", diff=100, verified=True),
            ])
            report = run(src, Path(tmp) / "out")
            self.assertEqual(report["methods"]["authenticated_only"]["tp_incidents"], 1)
            self.assertEqual(report["methods"]["evidence_quorum_2"]["fn_incidents"], 1)

    def test_spatial_ablation_has_expected_direction_on_large_distance(self):
        with tempfile.TemporaryDirectory() as tmp:
            src = Path(tmp) / "fake.csv"
            write_fixture(src, [
                record(1, "hazard", "CAR1", lat=51.5, diff=0),
                record(2, "hazard", "CAR2", lat=51.5015, diff=100),  # ~167m
            ])
            report = run(src, Path(tmp) / "out")
            self.assertEqual(report["methods"]["evidence_quorum_2"]["fn_incidents"], 1)
            self.assertEqual(report["methods"]["ablation_wide_radius_10km"]["tp_incidents"], 1)

    def test_contradictory_incident_truth_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            src = Path(tmp) / "fake.csv"
            write_fixture(src, [record(1, "hazard", "CAR1", truth=True),
                                record(2, "hazard", "CAR2", truth=False, diff=100)])
            with self.assertRaisesRegex(ValueError, "contradictory ground truth"):
                read_trace(src)

    def test_nonchronological_and_duplicate_sequences_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            src = Path(tmp) / "fake.csv"
            for rows in (
                [record(1, "a", "CAR1", diff=100), record(1, "a", "CAR2", diff=200)],
                [record(1, "a", "CAR1", diff=200), record(2, "a", "CAR2", diff=100)],
            ):
                write_fixture(src, rows)
                with self.assertRaisesRegex(ValueError, "ordering|nonchronological"):
                    read_trace(src)

    def test_digest_manifest_does_not_automatically_prove_data_origin(self):
        with tempfile.TemporaryDirectory() as tmp:
            src = Path(tmp) / "fake.csv"
            write_fixture(src, [record(1, "a", "CAR1")])
            manifest = Path(tmp) / "source.json"
            body = {
                "raw_csv_sha256": "0" * 64,
                "dataset_source": "fixture-only", "license": "test fixture",
                "split_protocol": "mock", "capture_protocol": "fake",
                "source_commit": "test-only",
            }
            manifest.write_text(json.dumps(body))
            with self.assertRaisesRegex(ValueError, "hash mismatch"):
                run(src, Path(tmp) / "out", provenance_manifest=manifest)
            body["raw_csv_sha256"] = hashlib.sha256(src.read_bytes()).hexdigest()
            manifest.write_text(json.dumps(body))
            report = run(src, Path(tmp) / "out", provenance_manifest=manifest)
            self.assertEqual(report["provenance"], "self_reported_hash_checked")
            self.assertFalse(report["publication_ready"])

    def test_missing_input_schema_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            src = Path(tmp) / "incomplete.csv"
            src.write_text("seq,incident_id\n1,hazard\n", encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "missing trace columns"):
                read_trace(src)

    def test_empty_trace_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            src = Path(tmp) / "empty.csv"
            write_fixture(src, [])
            with self.assertRaisesRegex(ValueError, "empty trace"):
                read_trace(src)


if __name__ == "__main__":
    unittest.main()
