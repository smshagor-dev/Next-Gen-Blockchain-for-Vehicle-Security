"""Deterministic protocol tests, NOT evidence for empirical V2X effectiveness."""
import hashlib
import os
import threading
import unittest
from datetime import datetime, timedelta, timezone
from unittest import mock

import v2x_evidence_admission as adm
import v2x_protocol as v2x

KEY_A = "a" * 48
KEY_B = "b" * 48
UTC = datetime(2026, 11, 12, 16, 0, 0, tzinfo=timezone.utc)


class TestClock:
    def __init__(self):
        self.monotonic_seconds = 0.0
        self.wall_time = UTC

    def monotonic(self):
        return self.monotonic_seconds

    def utc(self):
        return self.wall_time


def evidence(name="incident1", kind="ROAD_HAZARD", lat=51.5, lon=-0.1,
             observed_at=UTC, sensor="sample-1"):
    return {"evidence": {
        "incident_id": name, "event_class": kind,
        "lat": lat, "lon": lon, "observed_at": observed_at.isoformat(),
        "sensor_sha256": hashlib.sha256(sensor.encode()).hexdigest(),
    }}


class EvidenceGateTests(unittest.TestCase):
    def setUp(self):
        self.clock = TestClock()
        self.gate = adm.EvidenceAdmissionGate(
            clock=self.clock.monotonic, utc_clock=self.clock.utc
        )

    def report(self, source, **kwargs):
        return self.gate.evaluate(authenticated_sender_id=source, payload=evidence(**kwargs))

    def test_two_independent_consistent_observations_relay_exactly_once(self):
        first = self.report("CAR1", sensor="one")
        second = self.report("CAR2", sensor="two", lat=51.5002)
        self.assertEqual(first.status, "pending")
        self.assertFalse(first.relayed)
        self.assertEqual(second.status, "accepted")
        self.assertTrue(second.relayed)
        self.assertEqual(second.independent_sources, 2)
        last = self.report("CAR3", sensor="three")
        self.assertEqual(last.status, "already_accepted")
        self.assertFalse(last.relayed)
        self.assertEqual(self.gate.snapshot()["accepted"], 1)

    def test_signed_payload_cannot_smuggle_remote_actuator_fields(self):
        for where in ("top", "evidence"):
            payload = evidence()
            if where == "top":
                payload["ignition_cut"] = True
            else:
                payload["evidence"]["cmd"] = "SAFE_MODE_STOP"
            with self.subTest(where=where):
                decision = self.gate.evaluate(authenticated_sender_id="CAR1", payload=payload)
                self.assertEqual(decision.reason, "UNEXPECTED_EVIDENCE_FIELDS")
                self.assertFalse(decision.relayed)
        self.assertEqual(self.gate.snapshot()["active_incidents"], 0)

    def test_source_identity_cannot_vote_twice_even_with_fresh_digest(self):
        self.assertFalse(self.report("CAR1", sensor="first").relayed)
        second = self.report("CAR1", sensor="second")
        self.assertEqual(second.reason, "REPEATED_IDENTITY")
        self.assertEqual(second.independent_sources, 1)

    def test_copied_sensor_digest_does_not_count_as_separate_evidence(self):
        self.report("CAR1", sensor="copied")
        blocked = self.report("CAR2", sensor="copied")
        self.assertEqual(blocked.reason, "DUPLICATE_SENSOR_DIGEST")
        self.assertFalse(blocked.relayed)

    def test_spatial_and_temporal_and_class_conflicts_fail_closed(self):
        self.report("CAR1")
        for kwargs, reason in (
            ({"kind": "COLLISION", "sensor": "two"}, "INCIDENT_CLASS_CONFLICT"),
            ({"lat": 52.0, "sensor": "three"}, "INCIDENT_LOCATION_CONFLICT"),
            ({"observed_at": UTC - timedelta(seconds=7), "sensor": "four"},
             "INCIDENT_TIME_CONFLICT"),
        ):
            with self.subTest(reason=reason):
                self.assertEqual(self.report("CAR2", **kwargs).reason, reason)
        self.assertEqual(self.gate.snapshot()["accepted"], 0)

    def test_malformed_stale_nonfinite_and_untrusted_identity_fail_closed(self):
        invalid = (
            {"evidence": {}},
            {"evidence": {"incident_id": "good"}},
            evidence(lat=float("nan")),
            evidence(lat=True),
            evidence(lon=200),
            evidence(observed_at=UTC - timedelta(minutes=3)),
            evidence(observed_at=UTC + timedelta(seconds=8)),
            evidence(observed_at=UTC.replace(tzinfo=None)),
        )
        for payload in invalid:
            with self.subTest(payload=payload):
                outcome = self.gate.evaluate(authenticated_sender_id="CAR1", payload=payload)
                self.assertEqual(outcome.status, "rejected")
        self.assertEqual(
            self.gate.evaluate(authenticated_sender_id="untrusted!", payload=evidence()).reason,
            "AUTHENTICATED_ID_REQUIRED"
        )
        self.assertEqual(self.gate.snapshot()["active_incidents"], 0)

    def test_capacity_rejects_without_eviction_and_expiry_frees_slot(self):
        gate = adm.EvidenceAdmissionGate(
            max_incidents=1, incident_ttl_sec=5,
            clock=self.clock.monotonic, utc_clock=self.clock.utc,
        )
        self.assertEqual(gate.evaluate(authenticated_sender_id="CAR1", payload=evidence(name="A")).status, "pending")
        full = gate.evaluate(authenticated_sender_id="CAR1", payload=evidence(name="B"))
        self.assertEqual(full.reason, "INCIDENT_CAPACITY_REACHED")
        self.assertEqual(gate.snapshot()["active_incidents"], 1)
        self.clock.monotonic_seconds += 5.1
        self.clock.wall_time += timedelta(seconds=5)
        after = gate.evaluate(authenticated_sender_id="CAR1", payload=evidence(name="B", observed_at=self.clock.wall_time))
        self.assertEqual(after.status, "pending")

    def test_concurrent_quorum_is_atomic(self):
        gate = self.gate
        out = []
        lock = threading.Lock()

        def send(index):
            result = gate.evaluate(authenticated_sender_id=f"CAR{index}",
                                   payload=evidence(sensor=f"s{index}"))
            with lock:
                out.append(result)
        threads = [threading.Thread(target=send, args=(i,)) for i in range(16)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        self.assertEqual(sum(value.relayed for value in out), 1)
        self.assertEqual(gate.snapshot()["accepted"], 1)

    def test_quorum_is_bounded_and_configuration_is_fail_closed(self):
        for kwargs in ({"quorum": 1}, {"max_incidents": 0}, {"max_distance_m": float("nan")},
                       {"max_time_delta_sec": 0}, {"incident_ttl_sec": 0}):
            with self.subTest(kwargs=kwargs), self.assertRaises(ValueError):
                adm.EvidenceAdmissionGate(**kwargs)

    def test_snapshot_is_aggregate_and_privacy_sparing(self):
        self.report("PRIVATE_VEHICLE_01", name="private-incident")
        snapshot = str(self.gate.snapshot())
        self.assertNotIn("PRIVATE_VEHICLE_01", snapshot)
        self.assertNotIn("private-incident", snapshot)
        self.assertEqual(self.gate.snapshot()["pending"], 1)


class V2XHubIntegrationTests(unittest.TestCase):
    def setUp(self):
        self.prior_oqs = v2x.oqs
        v2x.oqs = None

    def tearDown(self):
        v2x.oqs = self.prior_oqs

    def established_pair(self, node_id, secret):
        client = v2x.DynamicCryptoAgilityLayer(node_id, shared_secret=secret)
        server = v2x.DynamicCryptoAgilityLayer("hub-peer:" + node_id, shared_secret=secret)
        hello = client.handshake_hello_payload()
        self.assertTrue(server.pin_peer_identity(hello))
        nonce = v2x._make_nonce()
        ack = server.accept_handshake_as_server(hello, session_context=nonce)
        self.assertTrue(client.complete_handshake_as_client(ack, session_context=nonce))
        return client, server

    def signed_alert(self, node_id, client, sensor):
        msg = v2x._new_message(v2x.V2XMessageType.ALERT, node_id, "vehicle",
                               evidence(observed_at=datetime.now(timezone.utc), sensor=sensor))
        msg["security"] = client.sign_message(msg)
        return msg

    def make_hub(self, mode):
        hub = v2x.V2XHub(node_key_registry={"CAR1": KEY_A, "CAR2": KEY_B},
                         evidence_policy=mode)
        clients = {}
        for node, secret in (("CAR1", KEY_A), ("CAR2", KEY_B)):
            client, server = self.established_pair(node, secret)
            conn = object()
            hub._clients[conn] = {"node_id": node, "node_type": "vehicle",
                                  "authenticated": True, "crypto": server,
                                  "replay_cache": {}}
            clients[node] = (conn, client)
        return hub, clients

    def test_enforce_blocks_first_report_and_relays_only_second(self):
        hub, clients = self.make_hub("enforce")
        with mock.patch.object(hub, "_broadcast") as emit:
            a_conn, a_client = clients["CAR1"]
            b_conn, b_client = clients["CAR2"]
            hub._handle_msg(a_conn, self.signed_alert("CAR1", a_client, "one"))
            emit.assert_not_called()
            hub._handle_msg(b_conn, self.signed_alert("CAR2", b_client, "two"))
            emit.assert_called_once()
            self.assertEqual(hub.evidence_admission_status()["accepted"], 1)

    def test_validly_signed_remote_action_is_not_forwarded_in_enforce_mode(self):
        hub, clients = self.make_hub("enforce")
        conn, client = clients["CAR1"]
        attack = self.signed_alert("CAR1", client, "one")
        attack["payload"]["remote_brake_pressure"] = 100
        attack["security"] = client.sign_message(attack)  # valid session MAC
        with mock.patch.object(hub, "_broadcast") as emit:
            hub._handle_msg(conn, attack)
            emit.assert_not_called()
        self.assertEqual(hub.evidence_admission_status()["rejected"], 1)

    def test_invalid_session_mac_never_contributes_to_quorum(self):
        hub, clients = self.make_hub("enforce")
        a_conn, a_client = clients["CAR1"]
        b_conn, b_client = clients["CAR2"]
        attack = self.signed_alert("CAR1", a_client, "one")
        attack["payload"]["evidence"]["lat"] = 52.0  # MAC now invalid
        with mock.patch.object(hub, "_broadcast") as emit:
            hub._handle_msg(a_conn, attack)
            hub._handle_msg(b_conn, self.signed_alert("CAR2", b_client, "two"))
            emit.assert_not_called()
            self.assertEqual(hub.evidence_admission_status()["pending"], 1)

    def test_shadow_preserves_forwarding_but_counts_pending(self):
        hub, clients = self.make_hub("shadow")
        a_conn, client = clients["CAR1"]
        with mock.patch.object(hub, "_broadcast") as emit:
            hub._handle_msg(a_conn, self.signed_alert("CAR1", client, "one"))
            emit.assert_called_once()
        self.assertEqual(hub.evidence_admission_status()["pending"], 1)

    def test_default_off_keeps_legacy_authenticated_forwarding(self):
        hub, clients = self.make_hub("off")
        a_conn, client = clients["CAR1"]
        with mock.patch.object(hub, "_broadcast") as emit:
            hub._handle_msg(a_conn, self.signed_alert("CAR1", client, "one"))
            emit.assert_called_once()
        self.assertEqual(hub.evidence_admission_status()["mode"], "off")

    def test_policy_rejects_invalid_configuration(self):
        with self.assertRaises(ValueError):
            v2x.V2XHub(node_key_registry={"CAR1": KEY_A}, evidence_policy="magic")

    def test_ping_bypasses_evidence_filter(self):
        hub, clients = self.make_hub("enforce")
        conn, client = clients["CAR1"]
        ping = v2x._new_message(v2x.V2XMessageType.PING, "CAR1", "vehicle", {})
        ping["security"] = client.sign_message(ping)
        with mock.patch.object(hub, "_send_raw") as send:
            hub._handle_msg(conn, ping)
            send.assert_called_once()
        self.assertEqual(hub.evidence_admission_status()["pending"], 0)


if __name__ == "__main__":
    unittest.main()
