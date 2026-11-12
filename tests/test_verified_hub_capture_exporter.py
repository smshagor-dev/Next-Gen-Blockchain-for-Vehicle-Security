"""Real session-verification-to-export plumbing tests, with constructed alerts."""
from __future__ import annotations

import csv
import hashlib
import json
import os
import stat
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest import mock

import v2x_protocol as v2x
from experiments.v2x.verified_hub_capture_exporter import VerifiedHubCaptureExporter
from experiments.v2x.join_world_capture import run

NODE_SECRET = "q" * 48
CAPTURE_KEY = b"independent research exporter key - fixture only - 12345678"


def incident_payload(incident_id="incident1"):
    return {"evidence": {
        "incident_id": incident_id,
        "event_class": "ROAD_HAZARD",
        "observed_at": datetime.now(timezone.utc).isoformat(),
        "lat": 51.5, "lon": -0.1,
        "sensor_sha256": hashlib.sha256(f"sensor:{incident_id}".encode()).hexdigest(),
    }}


def paired_session(node="CAR1"):
    client = v2x.DynamicCryptoAgilityLayer(node, shared_secret=NODE_SECRET)
    server = v2x.DynamicCryptoAgilityLayer("hub-peer:" + node, shared_secret=NODE_SECRET)
    hello = client.handshake_hello_payload()
    if not server.pin_peer_identity(hello):
        raise RuntimeError("fixture could not pin cryptographic signing identity")
    nonce = v2x._make_nonce()
    ack = server.accept_handshake_as_server(hello, session_context=nonce)
    if not client.complete_handshake_as_client(ack, session_context=nonce):
        raise RuntimeError("fixture session handshake incomplete")
    return client, server


def authenticated_alert(client, incident="incident1"):
    message = v2x._new_message(
        v2x.V2XMessageType.ALERT, "CAR1", "vehicle", incident_payload(incident)
    )
    message["security"] = client.sign_message(message)
    return message


class VerifiedHubResearchExporterTests(unittest.TestCase):
    def setUp(self):
        self.prev_oqs = v2x.oqs
        v2x.oqs = None
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.secret = self.root / "export_key"
        self.secret.write_bytes(CAPTURE_KEY)
        os.chmod(self.secret, 0o600)
        self.capture = self.root / "verified_alerts.jsonl"

    def tearDown(self):
        v2x.oqs = self.prev_oqs

    def exporter(self):
        return VerifiedHubCaptureExporter(
            capture_path=self.capture,
            exporter_key_file=self.secret,
            source_id="capture-research-source", scenario_id="hub-fixture", seed=1,
        )

    def hub(self, exporter):
        client, server = paired_session("CAR1")
        hub = v2x.V2XHub(node_key_registry={"CAR1": NODE_SECRET},
                         evidence_policy="off", capture_exporter=exporter)
        conn = object()
        hub._clients[conn] = {
            "node_id": "CAR1", "node_type": "vehicle",
            "authenticated": True, "crypto": server, "replay_cache": {},
        }
        return hub, conn, client

    def captured(self):
        text = self.capture.read_text(encoding="utf-8").strip()
        return [json.loads(line) for line in text.splitlines()] if text else []

    def test_only_accepted_signed_alert_is_written_with_private_file(self):
        with self.exporter() as exporter:
            hub, conn, client = self.hub(exporter)
            with mock.patch.object(hub, "_broadcast") as broadcast:
                hub._handle_msg(conn, authenticated_alert(client))
                broadcast.assert_called_once()
        records = self.captured()
        self.assertEqual(len(records), 1)
        self.assertEqual(records[0]["seq"], 1)
        self.assertTrue(records[0]["session_verified"])
        self.assertEqual(records[0]["bound_sender_id"], "CAR1")
        self.assertEqual(records[0]["message"]["payload"]["evidence"]["incident_id"], "incident1")
        self.assertEqual(records[0]["source_id"], "capture-research-source")
        self.assertEqual(len(records[0]["export_mac"]), 64)
        if os.name == "posix":
            self.assertEqual(stat.S_IMODE(self.capture.stat().st_mode), 0o600)
        self.assertNotIn(CAPTURE_KEY.decode(), self.capture.read_text())

    def test_bad_mac_and_replayed_verified_alerts_never_exported(self):
        with self.exporter() as exporter:
            hub, conn, client = self.hub(exporter)
            good = authenticated_alert(client)
            bad = dict(good)
            bad["payload"] = incident_payload("malicious-change")
            with mock.patch.object(hub, "_broadcast") as broadcast:
                hub._handle_msg(conn, bad)
                broadcast.assert_not_called()
                hub._handle_msg(conn, good)
                broadcast.assert_called_once()
                hub._handle_msg(conn, good)  # nonce replay, invalid by hub
                broadcast.assert_called_once()
        self.assertEqual(len(self.captured()), 1)

    def test_sender_mismatch_never_enters_research_capture(self):
        with self.exporter() as exporter:
            hub, conn, client = self.hub(exporter)
            bad = authenticated_alert(client)
            bad["sender_id"] = "OTHER"
            with mock.patch.object(hub, "_broadcast") as broadcast:
                hub._handle_msg(conn, bad)
                broadcast.assert_not_called()
        self.assertEqual(self.captured(), [])

    def test_nonconforming_alert_fails_export_but_not_live_forwarding(self):
        with self.exporter() as exporter:
            hub, conn, client = self.hub(exporter)
            message = authenticated_alert(client)
            message["payload"]["remote_brake_pressure"] = 200
            message.pop("security")
            message["security"] = client.sign_message(message)
            with mock.patch.object(hub, "_broadcast") as broadcast:
                with self.assertLogs("SmartCarV2X", level="ERROR"):
                    hub._handle_msg(conn, message)
                # With policy OFF, authenticated legacy forwarding remains;
                # the opt-in research exporter rejects unsupported schema.
                broadcast.assert_called_once()
        self.assertEqual(self.captured(), [])

    def test_export_failure_does_not_interrupt_authenticated_transport(self):
        class BrokenExporter:
            def record_verified(self, message, *, bound_sender_id):
                raise OSError("fake disk failure")

        hub, conn, client = self.hub(BrokenExporter())
        with mock.patch.object(hub, "_broadcast") as broadcast:
            with self.assertLogs("SmartCarV2X", level="ERROR"):
                hub._handle_msg(conn, authenticated_alert(client))
            broadcast.assert_called_once()

    def test_exclusive_file_creation_and_rejected_unsafe_key_permissions(self):
        with self.exporter():
            with self.assertRaises(FileExistsError):
                self.exporter()
        if os.name == "posix":
            self.capture.unlink()
            os.chmod(self.secret, 0o644)
            with self.assertRaisesRegex(ValueError, "private to file owner"):
                self.exporter()

    def test_integrity_export_import_roundtrip_counts_unreceived_world_hazard(self):
        with self.exporter() as exporter:
            hub, conn, client = self.hub(exporter)
            with mock.patch.object(hub, "_broadcast"):
                hub._handle_msg(conn, authenticated_alert(client, "incident1"))
        world = self.root / "world.csv"
        metadata = self.root / "metadata.json"
        now = datetime.now(timezone.utc) - timedelta(minutes=1)
        with world.open("w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=[
                "source_id", "scenario_id", "seed", "group_id", "split",
                "incident_id", "label", "label_provenance", "world_event_at",
            ])
            writer.writeheader()
            for name in ("incident1", "never_received"):
                writer.writerow({
                    "source_id": "capture-research-source",
                    "scenario_id": "hub-fixture", "seed": 1,
                    "group_id": "drive-" + name, "split": "test",
                    "incident_id": name, "label": 1,
                    "label_provenance": "fixture-world-catalogue-not-externally-verified",
                    "world_event_at": now.isoformat(),
                })
        source_hash = hashlib.sha256(world.read_bytes()).hexdigest()
        capture_hash = hashlib.sha256(self.capture.read_bytes()).hexdigest()
        metadata.write_text(json.dumps({
            "source_id": "capture-research-source", "scenario_id": "hub-fixture",
            "seed": 1, "world_sha256": source_hash,
            "capture_sha256": capture_hash,
            "world_source": "constructed-unit-test",
            "world_label_protocol": "constructed-fixture",
            "world_label_reviewer": "simulated-reviewer",
            "hub_export_origin": "real-code-verification-under-fixture-keys",
            "capture_verifier_version": "test-double",
            "source_commit": "fixture-only", "license": "fictional-test-data",
        }))
        result = run(
            world, self.capture, metadata, self.secret, self.root / "out",
            expected_world_sha256=source_hash, expected_capture_sha256=capture_hash,
        )
        self.assertEqual(result["capture_counts"]["hub_claims_session_verified"], 1)
        self.assertEqual(result["methods"]["authenticated_only"]["tp_incidents"], 1)
        self.assertEqual(result["methods"]["authenticated_only"]["fn_incidents"], 1)
        self.assertEqual(result["methods"]["evidence_quorum_2"]["tp_incidents"], 0)
        self.assertEqual(result["methods"]["evidence_quorum_2"]["fn_incidents"], 2)
        self.assertEqual(result["universe"]["zero_capture_incidents"], 1)
        self.assertFalse(result["independent_world_truth_verified"])
        self.assertFalse(result["original_v2x_session_mac_independently_reverified"])


if __name__ == "__main__":
    unittest.main()
