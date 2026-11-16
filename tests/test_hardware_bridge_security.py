"""Regression coverage for the bridge's fail-closed hardware trust boundary.

These tests use in-memory frames and mocked actuators. They do not claim
physical, fleet-scale, or statistically validated research security results.
"""
import json
import os
import unittest
from datetime import datetime, timezone
from types import SimpleNamespace
from unittest import mock

import hardware_bridge as bridge
import hardware_transport_security as hws


DEVICE_ID = "test-pi-01"
DEVICE_KEY = "bench-device-" + "P" * 52
SECOND_ID = "test-pi-02"
SECOND_KEY = "bench-device-" + "Q" * 52


def sample():
    return {
        "source": "raspberry_pi",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "speed": 35.0, "acceleration": 0.0, "fuel_level": 80.0,
        "battery_voltage": 12.6, "engine_temp": 72.0, "gps_lat": 23.8,
        "gps_lon": 90.4, "obstacle_distance": 30.0,
        "emergency_brake_active": False, "steering_angle": 0.0,
        "brake_pressure": 0.0, "throttle_position": 22.0, "rpm": 1900.0,
        "odometer": 220.0, "driver_heart_rate_bpm": 70.0,
        "driver_drowsiness_score": 0.1, "driver_unwell": False,
        "event": "HW:PI:TELEMETRY",
    }


def encoded(device_id=DEVICE_ID, key=DEVICE_KEY, kind="TELEMETRY"):
    payload = sample() if kind == "TELEMETRY" else hws.build_safe_stop_payload()
    envelope = hws.build_authenticated_envelope(device_id, key, kind, payload)
    return hws.encode_authenticated_envelope(envelope)


class FakeGate:
    def __init__(self, armed=False):
        self.armed = armed

    def is_armed(self):
        return self.armed


class BridgeSecurityTests(unittest.TestCase):
    def new_verifier(self):
        return hws.HardwareEnvelopeVerifier({
            DEVICE_ID: DEVICE_KEY,
            SECOND_ID: SECOND_KEY,
        }, max_frame_bytes=1024)

    def test_signed_fragmented_telemetry_reaches_verified_payload_only(self):
        session = bridge.AuthenticatedPiTelemetrySession(self.new_verifier())
        frame = encoded()
        self.assertEqual(session.receive(frame[:17]), [])
        verified = session.receive(frame[17:])
        self.assertEqual(len(verified), 1)
        self.assertEqual(verified[0].device_id, DEVICE_ID)
        self.assertEqual(bridge.to_telemetry(verified[0].payload).speed, 35.0)

    def test_unsigned_legacy_telemetry_is_rejected(self):
        session = bridge.AuthenticatedPiTelemetrySession(self.new_verifier())
        with self.assertRaisesRegex(hws.HardwareTransportError, "HW_ENVELOPE_FIELDS_INVALID"):
            session.receive(b'{"speed":35.0,"event":"HW:PI:TELEMETRY"}\n')

    def test_duplicate_top_level_mac_rejected_before_authentication(self):
        envelope = hws.build_authenticated_envelope(DEVICE_ID, DEVICE_KEY, "TELEMETRY", sample())
        raw = json.dumps(envelope, separators=(",", ":")).encode("utf-8")
        # Duplicate a *valid* MAC; last-wins parsers would accept the frame.
        raw = raw[:-1] + b',"mac":"' + envelope["mac"].encode("ascii") + b'"}\n'
        with self.assertRaisesRegex(hws.HardwareTransportError, "HW_JSON_DUPLICATE_KEY"):
            bridge.AuthenticatedPiTelemetrySession(self.new_verifier()).receive(raw)

    def test_duplicate_nested_payload_field_rejected(self):
        envelope = hws.build_authenticated_envelope(DEVICE_ID, DEVICE_KEY, "TELEMETRY", sample())
        raw = json.dumps(envelope, separators=(",", ":"))
        raw = raw.replace('"speed":35.0', '"speed":35.0,"speed":35.0', 1).encode("utf-8") + b"\n"
        with self.assertRaisesRegex(hws.HardwareTransportError, "HW_JSON_DUPLICATE_KEY"):
            bridge.AuthenticatedPiTelemetrySession(self.new_verifier()).receive(raw)

    def test_duplicate_device_id_cannot_override_enrolled_identity(self):
        envelope = hws.build_authenticated_envelope(DEVICE_ID, DEVICE_KEY, "TELEMETRY", sample())
        raw = json.dumps(envelope, separators=(",", ":")).encode("utf-8")
        raw = raw[:-1] + b',"device_id":"' + SECOND_ID.encode("ascii") + b'"}\n'
        with self.assertRaisesRegex(hws.HardwareTransportError, "HW_JSON_DUPLICATE_KEY"):
            bridge.AuthenticatedPiTelemetrySession(self.new_verifier()).receive(raw)

    def test_duplicate_json_key_rejection_does_not_claim_replay_nonce(self):
        envelope = hws.build_authenticated_envelope(DEVICE_ID, DEVICE_KEY, "TELEMETRY", sample())
        raw = json.dumps(envelope, separators=(",", ":")).encode("utf-8")
        ambiguous = raw[:-1] + b',"mac":"' + envelope["mac"].encode("ascii") + b'"}\n'
        verifier = self.new_verifier()
        with self.assertRaisesRegex(hws.HardwareTransportError, "HW_JSON_DUPLICATE_KEY"):
            bridge.AuthenticatedPiTelemetrySession(verifier).receive(ambiguous)
        # A rejected ambiguous encoding must not poison a later valid frame.
        self.assertEqual(len(bridge.AuthenticatedPiTelemetrySession(verifier).receive(raw + b"\n")), 1)

    def test_corrupted_mac_rejected(self):
        envelope = hws.build_authenticated_envelope(DEVICE_ID, DEVICE_KEY, "TELEMETRY", sample())
        envelope["payload"]["speed"] = 42.0
        session = bridge.AuthenticatedPiTelemetrySession(self.new_verifier())
        with self.assertRaisesRegex(hws.HardwareTransportError, "HW_ENVELOPE_MAC_INVALID"):
            session.receive(hws.encode_authenticated_envelope(envelope))

    def test_replay_rejected_across_connections(self):
        verifier = self.new_verifier()
        frame = encoded()
        first = bridge.AuthenticatedPiTelemetrySession(verifier)
        self.assertEqual(len(first.receive(frame)), 1)
        second = bridge.AuthenticatedPiTelemetrySession(verifier)
        with self.assertRaisesRegex(hws.HardwareTransportError, "HW_REPLAY_DETECTED"):
            second.receive(frame)

    def test_one_connection_cannot_switch_device_identity(self):
        session = bridge.AuthenticatedPiTelemetrySession(self.new_verifier())
        self.assertEqual(len(session.receive(encoded())), 1)
        with self.assertRaisesRegex(hws.HardwareTransportError, "HW_DEVICE_IDENTITY_MISMATCH"):
            session.receive(encoded(SECOND_ID, SECOND_KEY))

    def test_commands_are_never_accepted_as_telemetry(self):
        session = bridge.AuthenticatedPiTelemetrySession(self.new_verifier())
        with self.assertRaisesRegex(hws.HardwareTransportError, "HW_MESSAGE_DIRECTION_INVALID"):
            session.receive(encoded(kind="COMMAND"))

    def test_unbounded_frames_fail_closed(self):
        session = bridge.AuthenticatedPiTelemetrySession(self.new_verifier())
        with self.assertRaisesRegex(hws.HardwareTransportError, "HW_FRAME_TOO_LARGE"):
            session.receive(b"x" * 1025)

    def test_no_registry_fails_closed(self):
        with self.assertRaisesRegex(hws.HardwareTransportError, "HW_DEVICE_REGISTRY_REQUIRED"):
            hws.parse_device_registry("{}")

    def test_command_disabled_without_bench_gate(self):
        gate = FakeGate(False)
        with mock.patch.dict(os.environ, {
            "SMARTCAR_HARD_STOP_ENABLED": "1",
            "SMARTCAR_ECU_CONTROL_ENABLED": "0",
        }), mock.patch.object(bridge, "ECUCommandGateway") as gateway:
            dispatcher = bridge.SafeModeActuatorDispatcher(gate=gate)
            conn = mock.Mock()
            bc = SimpleNamespace(safe_mode_active=True)
            block = SimpleNamespace(index=7, safe_mode_activated=True)
            dispatcher.maybe_send_pi(
                conn, bc, block, device_id=DEVICE_ID, device_secret=DEVICE_KEY
            )
        conn.sendall.assert_not_called()
        gateway.return_value.send_safe_mode_stop.assert_not_called()

    def test_bench_armed_network_stop_never_reaches_pi_or_ecu(self):
        # A sender-side MAC and bench arming cannot prove receiver interlocks.
        for armed in (True, False):
            gate = FakeGate(armed)
            with mock.patch.dict(os.environ, {
                "SMARTCAR_HARD_STOP_ENABLED": "1",
                "SMARTCAR_ECU_CONTROL_ENABLED": "1",
            }), mock.patch.object(bridge, "ECUCommandGateway") as gateway:
                dispatcher = bridge.SafeModeActuatorDispatcher(gate=gate)
                conn = mock.Mock()
                ser = mock.Mock()
                bc = SimpleNamespace(safe_mode_active=True)
                block = SimpleNamespace(index=7, safe_mode_activated=True)
                self.assertFalse(dispatcher._should_send(bc, block))
                self.assertFalse(dispatcher.maybe_send_pi(
                    conn, bc, block, device_id=DEVICE_ID, device_secret=DEVICE_KEY
                ))
                self.assertFalse(dispatcher.maybe_send_arduino(
                    ser, bc, block, device_id=DEVICE_ID, device_secret=DEVICE_KEY
                ))
                conn.sendall.assert_not_called()
                ser.write.assert_not_called()
                gateway.return_value.send_safe_mode_stop.assert_not_called()

    def test_ecu_transport_is_never_initialized_even_when_bench_armed(self):
        # The unauthenticated CAN/serial ECU path was intentionally disabled.
        # Re-enabling a bench gate or setting the legacy environment variable
        # must not open either transport.
        gate = FakeGate(True)
        with mock.patch.dict(os.environ, {"SMARTCAR_ECU_CONTROL_ENABLED": "1"}), \
             mock.patch.object(bridge.ECUCommandGateway, "_init_transport") as init, \
             mock.patch.object(bridge.ECUCommandGateway, "_init_can") as init_can, \
             mock.patch.object(bridge.ECUCommandGateway, "_init_serial") as init_serial:
            gateway = bridge.ECUCommandGateway(gate=gate)
            init.assert_not_called()
            init_can.assert_not_called()
            init_serial.assert_not_called()
        self.assertFalse(gateway._init_ok)
        self.assertIsNone(gateway._can_bus)
        self.assertIsNone(gateway._ser)

    def test_ecu_output_fails_closed_even_if_legacy_flags_are_forced(self):
        # Model a stale caller manually forcing the old internal state.
        # Both local-gate states must remain unable to route network requests
        # to CAN/serial; local hardware emergency control stays independent.
        gate = FakeGate(True)
        with mock.patch.dict(os.environ, {"SMARTCAR_ECU_CONTROL_ENABLED": "1"}):
            gateway = bridge.ECUCommandGateway(gate=gate)
        gateway._init_ok = True
        with mock.patch.object(gateway, "_send_can_safe_stop") as send_can, \
             mock.patch.object(gateway, "_send_serial_safe_stop") as send_serial:
            for mode in ("can", "serial"):
                gateway.mode = mode
                for armed in (True, False):
                    gate.armed = armed
                    self.assertFalse(gateway.send_safe_mode_stop(block_index=4))
            send_can.assert_not_called()
            send_serial.assert_not_called()

    def test_legacy_private_ecu_output_helpers_also_fail_closed(self):
        gateway = bridge.ECUCommandGateway(gate=FakeGate(True))
        self.assertFalse(gateway._init_transport())
        self.assertFalse(gateway._init_can())
        self.assertFalse(gateway._init_serial())
        self.assertFalse(gateway._send_can_safe_stop(block_index=4))
        self.assertFalse(gateway._send_serial_safe_stop(block_index=4))
        self.assertFalse(gateway._init_ok)


if __name__ == "__main__":
    unittest.main()
