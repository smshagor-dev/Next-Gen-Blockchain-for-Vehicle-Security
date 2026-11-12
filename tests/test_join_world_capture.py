"""Contract tests with constructed records only. No source label is real-world truth."""
from __future__ import annotations

import csv
import hashlib
import hmac
import json
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

from experiments.v2x.join_world_capture import run

T0 = datetime(2026, 11, 12, 12, 0, 0, tzinfo=timezone.utc)
KEY = b"fixture exporter integrity key not for production 123456789"
WORLD_COLUMNS = (
    "source_id", "scenario_id", "seed", "group_id", "split", "incident_id",
    "label", "label_provenance", "world_event_at",
)


def canon(data):
    return json.dumps(data, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False, allow_nan=False).encode("utf-8")


def digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def incident(name, positive, *, label_provenance="simulator_world_state_fixture"):
    return {
        "source_id": "fixture-source", "scenario_id": "fake-session", "seed": "7",
        "group_id": "independent-group-" + name, "split": "test", "incident_id": name,
        "label": "1" if positive else "0",
        "label_provenance": label_provenance,
        "world_event_at": T0.isoformat(),
    }


def packet(seq, incident_id, sender, delay_ms, *, verified=True, nonce=None):
    received = T0 + timedelta(milliseconds=delay_ms)
    payload = {"evidence": {
        "incident_id": incident_id, "event_class": "ROAD_HAZARD",
        "observed_at": received.isoformat(),
        "lat": 51.5, "lon": -0.1,
        "sensor_sha256": hashlib.sha256(
            f"frame:{seq}:{sender}".encode()
        ).hexdigest(),
    }}
    message = {
        "type": "ALERT", "sender_id": sender, "sender_type": "vehicle",
        "timestamp": received.isoformat(),
        "nonce": nonce or f"{seq:032x}",
        "payload": payload,
        # This is a DUMMY envelope used only to test export integrity.
        # The original V2X session MAC is not reverified by this adapter.
        "security": {
            "session_id": "fixture-session", "signature": "not-a-real-session-mac",
            "scheme": "HMAC-SHA3-256",
        },
    }
    return {
        "capture_id": f"capture-{seq}",
        "source_id": "fixture-source", "scenario_id": "fake-session", "seed": 7,
        "seq": seq, "received_at": received.isoformat(),
        "session_verified": verified, "bound_sender_id": sender,
        "message": message,
    }


def fixture(root, *, events=None, packets=None, key=KEY):
    root = Path(root)
    events = events if events is not None else [
        incident("true-quorum", True), incident("true-missing", True),
        incident("true-single", True), incident("false-assertion", False),
        incident("negative-opportunity", False),
    ]
    packets = packets if packets is not None else [
        packet(1, "true-quorum", "CAR1", 100),
        packet(2, "true-quorum", "CAR2", 300),
        packet(3, "false-assertion", "BAD1", 400),
        packet(4, "true-single", "CAR3", 500),
    ]
    world = root / "annotated_world.csv"
    with world.open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=WORLD_COLUMNS)
        writer.writeheader()
        writer.writerows(events)
    capture = root / "hub_export.jsonl"
    with capture.open("wb") as stream:
        for packet_record in packets:
            record = dict(packet_record)
            bare = dict(record)
            record["export_mac"] = hmac.new(key, canon(bare), hashlib.sha256).hexdigest()
            stream.write(canon(record) + b"\n")
    metadata = root / "source_metadata.json"
    metadata.write_text(json.dumps({
        "source_id": "fixture-source", "scenario_id": "fake-session", "seed": 7,
        "world_sha256": digest(world), "capture_sha256": digest(capture),
        "world_source": "constructed-fixture-world-not-externally-verified",
        "world_label_protocol": "contract-fixture-world-state",
        "world_label_reviewer": "fake-independent-reviewer-name",
        "hub_export_origin": "fixture-test-external-key-possession-only",
        "capture_verifier_version": "fixture",
        "source_commit": "not-a-real-simulation-commit",
        "license": "synthetic unit-test fixture",
    }), encoding="utf-8")
    keyfile = root / "exporter_secret.bin"
    keyfile.write_bytes(key)
    return world, capture, metadata, keyfile


def verified_run(root, *, events=None, packets=None, key=KEY):
    world, capture, metadata, keyfile = fixture(root, events=events, packets=packets, key=key)
    return run(
        world, capture, metadata, keyfile, Path(root) / "output",
        expected_world_sha256=digest(world), expected_capture_sha256=digest(capture),
    )


class JoinedWorldCaptureTests(unittest.TestCase):
    def test_unobserved_positive_incident_is_false_negative_not_omitted(self):
        with tempfile.TemporaryDirectory() as tmp:
            result = verified_run(tmp)
            self.assertEqual(result["universe"]["world_incidents"], 5)
            self.assertEqual(result["universe"]["world_positive"], 3)
            self.assertEqual(result["universe"]["world_negative_opportunities"], 2)
            self.assertEqual(result["universe"]["zero_capture_incidents"], 2)
            auth = result["methods"]["authenticated_only"]
            quorum = result["methods"]["evidence_quorum_2"]
            self.assertEqual((auth["tp_incidents"], auth["fp_incidents"], auth["tn_incidents"], auth["fn_incidents"]),
                             (2, 1, 1, 1))
            self.assertEqual((quorum["tp_incidents"], quorum["fp_incidents"], quorum["tn_incidents"], quorum["fn_incidents"]),
                             (1, 0, 2, 2))
            self.assertEqual(auth["unreceived_world_positive_incidents"], 1)
            self.assertEqual(quorum["unreceived_world_positive_incidents"], 1)
            self.assertEqual(quorum["mean_world_to_forward_ms"], 300)
            self.assertFalse(result["publication_ready"])
            self.assertFalse(result["independent_world_truth_verified"])
            self.assertFalse(result["original_v2x_session_mac_independently_reverified"])
            self.assertTrue(result["hub_export_receipt_hmac_checked"])
            self.assertNotIn("signature", str(result))
            self.assertNotIn(KEY.decode(), str(result))
            for name in ("joined_incident_capture.csv", "joined_incident_policy_decisions.csv",
                         "joined_incident_world_results.json", "joined_incident_evidence_manifest.json"):
                self.assertTrue((Path(tmp) / "output" / name).exists())

    def test_full_world_universe_with_zero_captures_still_counts_failures(self):
        with tempfile.TemporaryDirectory() as tmp:
            result = verified_run(tmp, packets=[])
            self.assertEqual(result["universe"]["zero_capture_incidents"], 5)
            self.assertEqual(result["capture_counts"]["captured_records"], 0)
            for scores in result["methods"].values():
                self.assertEqual((scores["tp_incidents"], scores["fp_incidents"],
                                  scores["tn_incidents"], scores["fn_incidents"]), (0, 0, 2, 3))

    def test_negative_world_control_without_capture_is_true_negative(self):
        with tempfile.TemporaryDirectory() as tmp:
            result = verified_run(tmp, events=[incident("never-asserted", False)], packets=[])
            self.assertEqual(result["methods"]["authenticated_only"]["tn_incidents"], 1)
            self.assertEqual(result["methods"]["evidence_quorum_2"]["tn_incidents"], 1)

    def test_missing_world_incident_label_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            packets = [packet(1, "not-annotated", "BAD1", 100)]
            with self.assertRaisesRegex(ValueError, "no independently supplied world entry"):
                verified_run(tmp, packets=packets)

    def test_capture_export_tampering_rejected_even_if_manifest_rehashed(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            world, capture, metadata, keyfile = fixture(root)
            raw = capture.read_text(encoding="utf-8")
            self.assertIn("true-quorum", raw)
            capture.write_text(raw.replace("true-quorum", "false-assertion", 1), encoding="utf-8")
            body = json.loads(metadata.read_text())
            body["capture_sha256"] = digest(capture)
            metadata.write_text(json.dumps(body))
            with self.assertRaisesRegex(ValueError, "receipt HMAC mismatch"):
                run(world, capture, metadata, keyfile, root / "out",
                    expected_world_sha256=digest(world), expected_capture_sha256=digest(capture))

    def test_externally_pinned_world_sha_mismatch_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            world, capture, metadata, keyfile = fixture(root)
            with self.assertRaisesRegex(ValueError, "world CSV: pinned SHA-256 mismatch"):
                run(world, capture, metadata, keyfile, root / "out",
                    expected_world_sha256="f" * 64, expected_capture_sha256=digest(capture))

    def test_wrong_hub_export_hmac_key_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            world, capture, metadata, keyfile = fixture(root)
            keyfile.write_bytes(b"a" * 48)
            with self.assertRaisesRegex(ValueError, "receipt HMAC mismatch"):
                run(world, capture, metadata, keyfile, root / "out",
                    expected_world_sha256=digest(world), expected_capture_sha256=digest(capture))

    def test_duplicate_verified_nonce_cannot_be_counted_as_second_vehicle(self):
        with tempfile.TemporaryDirectory() as tmp:
            bad = [
                packet(1, "true-quorum", "CAR1", 100, nonce="a" * 32),
                packet(2, "true-quorum", "CAR1", 200, nonce="a" * 32),
            ]
            with self.assertRaisesRegex(ValueError, "duplicate hub-verified sender nonce"):
                verified_run(tmp, packets=bad)

    def test_unverified_capture_row_never_contributes_to_quorum(self):
        with tempfile.TemporaryDirectory() as tmp:
            bad = [
                packet(1, "true-quorum", "CAR1", 100, verified=False),
                packet(2, "true-quorum", "CAR2", 200),
            ]
            result = verified_run(tmp, packets=bad)
            self.assertEqual(result["capture_counts"]["hub_claims_session_rejected"], 1)
            self.assertEqual(result["methods"]["authenticated_only"]["tp_incidents"], 1)
            self.assertEqual(result["methods"]["evidence_quorum_2"]["tp_incidents"], 0)

    def test_record_signature_cannot_substitute_for_bound_sender_identity(self):
        with tempfile.TemporaryDirectory() as tmp:
            bad = [packet(1, "true-quorum", "CAR1", 100)]
            bad[0]["bound_sender_id"] = "CAR2"
            with self.assertRaisesRegex(ValueError, "sender identity not bound"):
                verified_run(tmp, packets=bad)

    def test_world_truth_cannot_be_cam_attacker_flag(self):
        with tempfile.TemporaryDirectory() as tmp:
            events = [incident("true-quorum", True, label_provenance="cam_attacker")]
            with self.assertRaisesRegex(ValueError, "unsupported incident ground truth provenance"):
                verified_run(tmp, events=events, packets=[])

    def test_cross_split_group_leakage_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            events = [incident("a", True), incident("b", False)]
            events[1]["group_id"] = events[0]["group_id"]
            events[1]["split"] = "validation"
            with self.assertRaisesRegex(ValueError, "group leakage across splits"):
                verified_run(tmp, events=events, packets=[])

    def test_duplicate_export_capture_id_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            bad = [packet(1, "true-quorum", "CAR1", 100), packet(2, "true-quorum", "CAR2", 200)]
            bad[1]["capture_id"] = bad[0]["capture_id"]
            with self.assertRaisesRegex(ValueError, "missing or repeated"):
                verified_run(tmp, packets=bad)

    def test_future_message_and_stale_sensor_evidence_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            bad = [packet(1, "true-quorum", "CAR1", 100)]
            bad[0]["message"]["timestamp"] = (T0 + timedelta(hours=1)).isoformat()
            with self.assertRaisesRegex(ValueError, "outside exporter receipt bound"):
                verified_run(tmp, packets=bad)
        with tempfile.TemporaryDirectory() as tmp:
            bad = [packet(1, "true-quorum", "CAR1", 100)]
            bad[0]["message"]["payload"]["evidence"]["observed_at"] = (T0 - timedelta(minutes=1)).isoformat()
            with self.assertRaisesRegex(ValueError, "OBSERVATION_STALE"):
                verified_run(tmp, packets=bad)

    def test_reproducible_result_and_manifest_hashes_without_export_key_exposure(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            world, capture, metadata, key = fixture(root)
            args = (world, capture, metadata, key)
            kwargs = {"expected_world_sha256": digest(world),
                      "expected_capture_sha256": digest(capture)}
            first = run(*args, root / "first", **kwargs)
            second = run(*args, root / "second", **kwargs)
            self.assertEqual(first, second)
            for name in ("joined_incident_capture.csv", "joined_incident_policy_decisions.csv",
                         "joined_incident_world_results.json", "joined_incident_evidence_manifest.json"):
                self.assertEqual((root / "first" / name).read_bytes(), (root / "second" / name).read_bytes())
            manifest = json.loads((root / "first/joined_incident_evidence_manifest.json").read_text())
            self.assertEqual(manifest["world_csv_sha256"], digest(world))
            self.assertEqual(manifest["capture_jsonl_sha256"], digest(capture))
            self.assertNotIn(KEY.decode(), json.dumps(first))


if __name__ == "__main__":
    unittest.main()
