"""Synthetic serial ingress security tests; not hardware or research evidence."""
import unittest
from unittest import mock
from datetime import datetime, timezone

import hardware_bridge as bridge
from hardware_transport_security import build_authenticated_envelope, encode_authenticated_envelope

DEVICE = "arduino-bench-01"
SECRET = "arduino-bench-secret-" + "Z" * 48


def payload():
    return {
        "source": "arduino", "timestamp": datetime.now(timezone.utc).isoformat(),
        "speed": 12.0, "acceleration": 0.0, "fuel_level": 80.0,
        "battery_voltage": 12.6, "engine_temp": 30.0, "gps_lat": 0.0,
        "gps_lon": 0.0, "obstacle_distance": 30.0,
        "emergency_brake_active": False, "steering_angle": 0.0,
        "brake_pressure": 0.0, "throttle_position": 0.0, "rpm": 1000.0,
        "odometer": 0.0, "driver_heart_rate_bpm": 70.0,
        "driver_drowsiness_score": 0.0, "driver_unwell": False,
        "event": "HW:ARDUINO:TELEMETRY",
    }


class FakeSerial:
    def __init__(self, frames):
        self.frames = iter(frames)
        self.closed = False

    def read(self, size):
        assert size <= 1024
        try:
            item = next(self.frames)
        except StopIteration:
            raise StopIteration
        return item

    def close(self):
        self.closed = True


class SerialIngressTests(unittest.TestCase):
    def run_bridge(self, frames):
        fake = FakeSerial(frames)
        bc = mock.Mock()
        bc.push_telemetry.return_value.index = 3
        env = {"SMARTCAR_HW_DEVICE_KEYS_JSON": '{"arduino-bench-01":"' + SECRET + '"}',
               "SMARTCAR_HARD_STOP_ENABLED": "0", "SMARTCAR_ECU_CONTROL_ENABLED": "0"}
        with mock.patch.object(bridge, "serial") as serial, \
             mock.patch.dict("os.environ", env), \
             mock.patch.object(bridge, "SafeModeActuatorDispatcher") as dispatcher:
            serial.Serial.return_value = fake
            with self.assertRaises((RuntimeError, StopIteration)):
                bridge.run_arduino_mode(bc)
        self.assertTrue(fake.closed)
        return bc, dispatcher

    def test_valid_signed_frame_is_accepted(self):
        frame = encode_authenticated_envelope(build_authenticated_envelope(
            DEVICE, SECRET, "TELEMETRY", payload()))
        bc, _ = self.run_bridge([frame[:9], frame[9:]])
        bc.push_telemetry.assert_called_once()

    def test_unsigned_json_cannot_mutate_ledger(self):
        bc, _ = self.run_bridge([b'{"speed":12}\n'])
        bc.push_telemetry.assert_not_called()

    def test_corrupt_mac_cannot_mutate_ledger(self):
        envelope = build_authenticated_envelope(DEVICE, SECRET, "TELEMETRY", payload())
        envelope["payload"]["speed"] = 42
        bc, _ = self.run_bridge([encode_authenticated_envelope(envelope)])
        bc.push_telemetry.assert_not_called()

    def test_oversized_unterminated_input_is_quarantined(self):
        bc, _ = self.run_bridge([b"x" * 1024] * 6)
        bc.push_telemetry.assert_not_called()

    def test_replayed_frame_cannot_create_second_block(self):
        frame = encode_authenticated_envelope(build_authenticated_envelope(
            DEVICE, SECRET, "TELEMETRY", payload()))
        bc, _ = self.run_bridge([frame, frame])
        self.assertEqual(bc.push_telemetry.call_count, 1)


    def test_silent_serial_peer_is_closed_after_idle_deadline(self):
        class SilentSerial:
            closed = False
            def read(self, size):
                return b""
            def close(self):
                self.closed = True

        fake = SilentSerial()
        ticks = iter(range(100))
        env = {"SMARTCAR_HW_DEVICE_KEYS_JSON": '{"arduino-bench-01":"' + SECRET + '"}',
               "SMARTCAR_HW_IDLE_TIMEOUT_SEC": "2",
               "SMARTCAR_HW_MAX_SESSION_SEC": "30"}
        with mock.patch.object(bridge, "serial") as serial, \
             mock.patch.dict("os.environ", env), \
             mock.patch.object(bridge.time, "monotonic", side_effect=lambda: next(ticks)), \
             mock.patch.object(bridge, "SafeModeActuatorDispatcher"):
            serial.Serial.return_value = fake
            bc = mock.Mock()
            with self.assertRaisesRegex(RuntimeError, "idle timeout"):
                bridge.run_arduino_mode(bc)
            bc.push_telemetry.assert_not_called()
        self.assertTrue(fake.closed)

    def test_trickle_serial_peer_is_closed_at_session_deadline(self):
        class TrickleSerial:
            closed = False
            def read(self, size):
                return b"x"
            def close(self):
                self.closed = True

        fake = TrickleSerial()
        ticks = iter(range(100))
        env = {"SMARTCAR_HW_DEVICE_KEYS_JSON": '{"arduino-bench-01":"' + SECRET + '"}',
               "SMARTCAR_HW_IDLE_TIMEOUT_SEC": "30",
               "SMARTCAR_HW_MAX_SESSION_SEC": "5"}
        with mock.patch.object(bridge, "serial") as serial, \
             mock.patch.dict("os.environ", env), \
             mock.patch.object(bridge.time, "monotonic", side_effect=lambda: next(ticks)), \
             mock.patch.object(bridge, "SafeModeActuatorDispatcher"):
            serial.Serial.return_value = fake
            bc = mock.Mock()
            with self.assertRaisesRegex(RuntimeError, "session lifetime exceeded"):
                bridge.run_arduino_mode(bc)
            bc.push_telemetry.assert_not_called()
        self.assertTrue(fake.closed)

    def test_outbound_stop_is_authenticated_command(self):
        from hardware_transport_security import HardwareEnvelopeVerifier
        gate = mock.Mock()
        gate.is_armed.return_value = True
        with mock.patch.object(bridge, "get_bool", return_value=True), \
             mock.patch.object(bridge, "ECUCommandGateway") as ecu:
            dispatcher = bridge.SafeModeActuatorDispatcher(gate=gate)
            dispatcher._last_sent_at = 0.0
            ser = mock.Mock()
            bc = mock.Mock(safe_mode_active=True)
            block = mock.Mock(index=17, safe_mode_activated=True)
            dispatcher.maybe_send_arduino(
                ser, bc, block, device_id=DEVICE, device_secret=SECRET
            )
            ser.write.assert_called_once()
            raw = ser.write.call_args.args[0]
            self.assertNotIn(b'"cmd":', raw)
            verifier = HardwareEnvelopeVerifier({DEVICE: SECRET})
            result = verifier.verify(raw.removesuffix(b"\n"), expected_kind="COMMAND")
            self.assertEqual(result.device_id, DEVICE)
            ecu.return_value.send_safe_mode_stop.assert_called_once_with(block_index=17)

    def test_failed_can_does_not_downgrade_to_unsigned_serial(self):
        gate = mock.Mock()
        gate.is_armed.return_value = True
        with mock.patch.object(bridge, "get_bool", return_value=True), \
             mock.patch.object(bridge, "get_env", return_value="can"), \
             mock.patch.object(bridge.ECUCommandGateway, "_init_can") as init_can, \
             mock.patch.object(bridge.ECUCommandGateway, "_init_serial") as init_serial:
            gateway = bridge.ECUCommandGateway(gate=gate)
            init_can.assert_called_once()
            init_serial.assert_not_called()
            self.assertFalse(gateway._init_ok)
            self.assertEqual(gateway.mode, "can")

    def test_explicit_unsigned_ecu_serial_is_disabled(self):
        gate = mock.Mock()
        gate.is_armed.return_value = True
        with mock.patch.object(bridge, "get_bool", return_value=True), \
             mock.patch.object(bridge, "get_env", return_value="serial"), \
             mock.patch.object(bridge.ECUCommandGateway, "_init_serial") as init_serial:
            gateway = bridge.ECUCommandGateway(gate=gate)
            init_serial.assert_not_called()
            self.assertFalse(gateway._init_ok)
            with mock.patch.object(gateway, "_send_serial_safe_stop") as send:
                gateway.send_safe_mode_stop(block_index=17)
                send.assert_not_called()

    def test_unarmed_stop_never_writes_serial(self):
        gate = mock.Mock()
        gate.is_armed.return_value = False
        with mock.patch.object(bridge, "get_bool", return_value=True), \
             mock.patch.object(bridge, "ECUCommandGateway"):
            dispatcher = bridge.SafeModeActuatorDispatcher(gate=gate)
            ser = mock.Mock()
            dispatcher.maybe_send_arduino(
                ser, mock.Mock(safe_mode_active=True),
                mock.Mock(index=2, safe_mode_activated=True),
                device_id=DEVICE, device_secret=SECRET,
            )
            ser.write.assert_not_called()


    def test_can_stop_is_blocked_even_when_transport_and_gate_are_ready(self):
        gate = mock.Mock()
        gate.is_armed.return_value = True
        with mock.patch.object(bridge, "get_bool", return_value=True), \
             mock.patch.object(bridge, "get_env", return_value="can"), \
             mock.patch.object(bridge.ECUCommandGateway, "_init_can"):
            gateway = bridge.ECUCommandGateway(gate=gate)
            gateway._init_ok = True
            gateway._can_bus = mock.Mock()
            gateway.send_safe_mode_stop(block_index=17)
            gateway._can_bus.send.assert_not_called()

    def test_can_stop_does_not_call_frame_builder(self):
        gateway = bridge.ECUCommandGateway(gate=mock.Mock())
        gateway.mode = "can"
        gateway.enabled = True
        gateway._init_ok = True
        gateway._can_bus = mock.Mock()
        with mock.patch.object(gateway, "_send_can_safe_stop") as send:
            gateway.send_safe_mode_stop(block_index=1)
            send.assert_not_called()

if __name__ == "__main__":
    unittest.main()
