import copy
import hashlib
import hmac
import json
import unittest
from datetime import datetime, timedelta, timezone

import hardware_transport_security as hws


DEVICE_ID = "pi-bench-001"
DEVICE_KEY = "hardware-device-secret-" + "H" * 48
OTHER_KEY = "hardware-device-secret-" + "Q" * 48


def telemetry(timestamp=None):
    return {
        "source": "raspberry_pi",
        "timestamp": timestamp or datetime.now(timezone.utc).isoformat(),
        "speed": 42.5,
        "acceleration": 0.2,
        "fuel_level": 80.0,
        "battery_voltage": 13.7,
        "engine_temp": 78.0,
        "gps_lat": 23.8103,
        "gps_lon": 90.4125,
        "obstacle_distance": 35.0,
        "emergency_brake_active": False,
        "steering_angle": 1.2,
        "brake_pressure": 0.0,
        "throttle_position": 35.0,
        "rpm": 2400.0,
        "odometer": 123.4,
        "driver_heart_rate_bpm": 72.0,
        "driver_drowsiness_score": 0.1,
        "driver_unwell": False,
        "event": "HW:PI:TELEMETRY",
    }


def resign(envelope, secret=DEVICE_KEY):
    unsigned = dict(envelope)
    unsigned.pop("mac", None)
    key = hws.derive_directional_key(secret, envelope["device_id"], envelope["kind"])
    envelope["mac"] = hmac.new(
        key,
        hws._ENVELOPE_DOMAIN + hws._canonical_bytes(unsigned),
        hashlib.sha256,
    ).hexdigest()
    return envelope


class HardwareTransportSecurityTests(unittest.TestCase):
    def verifier(self, **kwargs):
        return hws.HardwareEnvelopeVerifier({DEVICE_ID: DEVICE_KEY}, **kwargs)

    def test_valid_telemetry_roundtrip(self):
        envelope = hws.build_authenticated_envelope(DEVICE_ID, DEVICE_KEY, "TELEMETRY", telemetry())
        encoded = hws.encode_authenticated_envelope(envelope)
        verified = self.verifier().verify(encoded, expected_kind="TELEMETRY")
        self.assertEqual(verified.device_id, DEVICE_ID)
        self.assertEqual(verified.kind, "TELEMETRY")
        self.assertEqual(verified.payload["speed"], 42.5)

    def test_tampered_payload_fails_mac_before_state_claim(self):
        envelope = hws.build_authenticated_envelope(DEVICE_ID, DEVICE_KEY, "TELEMETRY", telemetry())
        envelope["payload"]["speed"] = 99.0
        verifier = self.verifier()
        with self.assertRaisesRegex(hws.HardwareTransportError, "HW_ENVELOPE_MAC_INVALID") as ctx:
            verifier.verify(envelope, expected_kind="TELEMETRY")
        self.assertFalse(ctx.exception.authenticated)
        self.assertEqual(verifier.metadata()["replay_cache_entries_per_device"], 2048)

    def test_unknown_device_is_rejected(self):
        envelope = hws.build_authenticated_envelope("pi-unknown", OTHER_KEY, "TELEMETRY", telemetry())
        with self.assertRaisesRegex(hws.HardwareTransportError, "HW_DEVICE_NOT_ENROLLED"):
            self.verifier().verify(envelope, expected_kind="TELEMETRY")

    def test_same_authenticated_envelope_cannot_replay(self):
        envelope = hws.build_authenticated_envelope(DEVICE_ID, DEVICE_KEY, "TELEMETRY", telemetry())
        verifier = self.verifier()
        verifier.verify(envelope, expected_kind="TELEMETRY")
        with self.assertRaisesRegex(hws.HardwareTransportError, "HW_REPLAY_DETECTED") as ctx:
            verifier.verify(envelope, expected_kind="TELEMETRY")
        self.assertTrue(ctx.exception.authenticated)

    def test_replay_cache_saturation_fails_closed_without_live_eviction(self):
        verifier = self.verifier(replay_cache_entries=16, replay_window_sec=30)
        now = datetime.now(timezone.utc)
        for index in range(16):
            envelope = hws.build_authenticated_envelope(
                DEVICE_ID,
                DEVICE_KEY,
                "TELEMETRY",
                telemetry(now.isoformat()),
                timestamp=now,
                nonce=f"{index + 1:032x}",
            )
            verifier.verify(envelope, expected_kind="TELEMETRY")
        overflow = hws.build_authenticated_envelope(
            DEVICE_ID,
            DEVICE_KEY,
            "TELEMETRY",
            telemetry(now.isoformat()),
            timestamp=now,
            nonce=f"{17:032x}",
        )
        with self.assertRaisesRegex(hws.HardwareTransportError, "HW_REPLAY_CACHE_SATURATED"):
            verifier.verify(overflow, expected_kind="TELEMETRY")

    def test_stale_envelope_is_rejected(self):
        stale = datetime.now(timezone.utc) - timedelta(minutes=2)
        envelope = hws.build_authenticated_envelope(
            DEVICE_ID,
            DEVICE_KEY,
            "TELEMETRY",
            telemetry(stale.isoformat()),
            timestamp=stale,
        )
        with self.assertRaisesRegex(hws.HardwareTransportError, "HW_ENVELOPE_STALE"):
            self.verifier().verify(envelope, expected_kind="TELEMETRY")

    def test_payload_timestamp_must_track_signed_envelope_timestamp(self):
        now = datetime.now(timezone.utc)
        envelope = hws.build_authenticated_envelope(
            DEVICE_ID,
            DEVICE_KEY,
            "TELEMETRY",
            telemetry((now - timedelta(seconds=10)).isoformat()),
            timestamp=now,
        )
        with self.assertRaisesRegex(hws.HardwareTransportError, "HW_PAYLOAD_TIMESTAMP_MISMATCH") as ctx:
            self.verifier().verify(envelope, expected_kind="TELEMETRY")
        self.assertTrue(ctx.exception.authenticated)

    def test_authenticated_out_of_range_telemetry_is_rejected(self):
        envelope = hws.build_authenticated_envelope(DEVICE_ID, DEVICE_KEY, "TELEMETRY", telemetry())
        envelope["payload"]["speed"] = 900.0
        resign(envelope)
        with self.assertRaisesRegex(hws.HardwareTransportError, "HW_TELEMETRY_RANGE_INVALID_SPEED") as ctx:
            self.verifier().verify(envelope, expected_kind="TELEMETRY")
        self.assertTrue(ctx.exception.authenticated)

    def test_nonfinite_and_boolean_numeric_telemetry_are_rejected(self):
        bad = telemetry()
        bad["speed"] = float("nan")
        with self.assertRaisesRegex(hws.HardwareTransportError, "HW_TELEMETRY_NONFINITE_SPEED"):
            hws.build_authenticated_envelope(DEVICE_ID, DEVICE_KEY, "TELEMETRY", bad)

        bad = telemetry()
        bad["speed"] = True
        with self.assertRaisesRegex(hws.HardwareTransportError, "HW_TELEMETRY_TYPE_INVALID_SPEED"):
            hws.build_authenticated_envelope(DEVICE_ID, DEVICE_KEY, "TELEMETRY", bad)

    def test_json_nan_constant_is_rejected(self):
        malicious = (
            '{"version":"OMNIGUARD_HW_TRANSPORT_V1","kind":"TELEMETRY",'
            '"device_id":"pi-bench-001","timestamp":"2026-08-21T00:00:00+00:00",'
            '"nonce":"' + "ab" * 16 + '","payload":{"speed":NaN},"mac":"' + "0" * 64 + '"}'
        )
        with self.assertRaisesRegex(hws.HardwareTransportError, "HW_JSON_NONFINITE_CONSTANT"):
            self.verifier().verify(malicious)

    def test_command_direction_and_semantics_are_fixed(self):
        payload = hws.build_safe_stop_payload(block_index=7)
        envelope = hws.build_authenticated_envelope(DEVICE_ID, DEVICE_KEY, "COMMAND", payload)
        verified = self.verifier().verify(envelope, expected_kind="COMMAND")
        self.assertEqual(verified.payload["cmd"], "SAFE_MODE_STOP")

        with self.assertRaisesRegex(hws.HardwareTransportError, "HW_MESSAGE_DIRECTION_INVALID"):
            self.verifier().verify(envelope, expected_kind="TELEMETRY")

        unsafe = dict(payload)
        unsafe["throttle"] = 10
        with self.assertRaisesRegex(hws.HardwareTransportError, "HW_COMMAND_SEMANTICS_INVALID"):
            hws.build_authenticated_envelope(DEVICE_ID, DEVICE_KEY, "COMMAND", unsafe)

    def test_connection_device_binding_rejects_second_identity(self):
        keys = {
            DEVICE_ID: DEVICE_KEY,
            "pi-bench-002": OTHER_KEY,
        }
        verifier = hws.HardwareEnvelopeVerifier(keys)
        envelope = hws.build_authenticated_envelope("pi-bench-002", OTHER_KEY, "TELEMETRY", telemetry())
        with self.assertRaisesRegex(hws.HardwareTransportError, "HW_DEVICE_IDENTITY_MISMATCH") as ctx:
            verifier.verify(envelope, expected_kind="TELEMETRY", expected_device_id=DEVICE_ID)
        self.assertTrue(ctx.exception.authenticated)

    def test_directional_keys_are_different(self):
        telemetry_key = hws.derive_directional_key(DEVICE_KEY, DEVICE_ID, "TELEMETRY")
        command_key = hws.derive_directional_key(DEVICE_KEY, DEVICE_ID, "COMMAND")
        self.assertNotEqual(telemetry_key, command_key)

    def test_line_framer_preserves_fragmentation_and_bounds_memory(self):
        framer = hws.AuthenticatedLineFramer(max_frame_bytes=1024)
        self.assertEqual(framer.feed(b'{"a":'), [])
        self.assertEqual(framer.feed(b'1}\n{"b":2}\n'), [b'{"a":1}', b'{"b":2}'])
        with self.assertRaisesRegex(hws.HardwareTransportError, "HW_FRAME_TOO_LARGE"):
            framer.feed(b"x" * 1025)
        self.assertEqual(framer.feed(b"ok\n"), [b"ok"])

    def test_plaintext_transport_is_loopback_only_by_default(self):
        self.assertEqual(hws.validate_plaintext_hardware_host("127.0.0.1"), "127.0.0.1")
        with self.assertRaisesRegex(hws.HardwareTransportError, "HW_PLAINTEXT_LAN_DISABLED"):
            hws.validate_plaintext_hardware_host("192.168.10.20")
        self.assertEqual(
            hws.validate_plaintext_hardware_host("192.168.10.20", allow_private_lan=True),
            "192.168.10.20",
        )
        with self.assertRaisesRegex(hws.HardwareTransportError, "HW_PLAINTEXT_PUBLIC_OR_WILDCARD_REJECTED"):
            hws.validate_plaintext_hardware_host("0.0.0.0", allow_private_lan=True)
        with self.assertRaisesRegex(hws.HardwareTransportError, "HW_PLAINTEXT_PUBLIC_OR_WILDCARD_REJECTED"):
            hws.validate_plaintext_hardware_host("8.8.8.8", allow_private_lan=True)

    def test_registry_rejects_shared_device_secret_and_metadata_redacts_keys(self):
        with self.assertRaisesRegex(hws.HardwareTransportError, "HW_DEVICE_SECRET_REUSED"):
            hws.parse_device_registry(json.dumps({"pi-1": DEVICE_KEY, "pi-2": DEVICE_KEY}))
        verifier = self.verifier()
        encoded = json.dumps(verifier.metadata())
        self.assertNotIn(DEVICE_KEY, encoded)
        self.assertFalse(verifier.metadata()["secret_values_exposed"])
        self.assertFalse(verifier.metadata()["transport_confidentiality"])


if __name__ == "__main__":
    unittest.main()
