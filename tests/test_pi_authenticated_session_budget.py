"""Synthetic authenticated TCP flood-budget test; no hardware or network required."""
import unittest
from unittest import mock

import hardware_bridge as bridge
from hardware_transport_security import build_authenticated_envelope, encode_authenticated_envelope
from datetime import datetime, timezone

DEVICE = "pi-bench-01"
SECRET = "pi-bench-secret-" + "K" * 48


def payload():
    return {
        "source": "pi", "timestamp": datetime.now(timezone.utc).isoformat(),
        "speed": 12.0, "acceleration": 0.0, "fuel_level": 80.0,
        "battery_voltage": 12.6, "engine_temp": 30.0, "gps_lat": 0.0,
        "gps_lon": 0.0, "obstacle_distance": 30.0,
        "emergency_brake_active": False, "steering_angle": 0.0,
        "brake_pressure": 0.0, "throttle_position": 0.0, "rpm": 1000.0,
        "odometer": 0.0, "driver_heart_rate_bpm": 70.0,
        "driver_drowsiness_score": 0.0, "driver_unwell": False,
        "event": "HW:PI:TELEMETRY",
    }



class FakeConnection:
    def __init__(self, data):
        self.data = data
        self.calls = 0

    def __enter__(self):
        return self

    def __exit__(self, *args):
        return False

    def settimeout(self, value):
        self.timeout = value

    def recv(self, count):
        self.calls += 1
        if self.calls == 1:
            return self.data
        return b""


class FakeServer:
    def __init__(self, connection):
        self.connection = connection
        self.accept_calls = 0

    def __enter__(self):
        return self

    def __exit__(self, *args):
        return False

    def setsockopt(self, *args):
        pass

    def bind(self, address):
        pass

    def listen(self, backlog):
        pass

    def accept(self):
        self.accept_calls += 1
        if self.accept_calls == 1:
            return self.connection, ("127.0.0.1", 50000)
        raise StopIteration


class PiSessionBudgetTests(unittest.TestCase):
    def test_valid_authenticated_flood_is_bounded_before_second_ledger_write(self):
        frames = b"".join(
            encode_authenticated_envelope(
                build_authenticated_envelope(DEVICE, SECRET, "TELEMETRY", payload())
            )
            for _ in range(2)
        )
        conn = FakeConnection(frames)
        server = FakeServer(conn)
        bc = mock.Mock()
        bc.push_telemetry.return_value.index = 4
        env = {
            "SMARTCAR_HW_DEVICE_KEYS_JSON": '{"' + DEVICE + '":"' + SECRET + '"}',
            "SMARTCAR_HW_MAX_FRAMES_PER_SESSION": "1",
            "SMARTCAR_HARD_STOP_ENABLED": "0",
            "SMARTCAR_ECU_CONTROL_ENABLED": "0",
        }
        with mock.patch.dict("os.environ", env), \
             mock.patch.object(bridge.socket, "socket", return_value=server), \
             mock.patch.object(bridge, "SafeModeActuatorDispatcher"):
            with self.assertRaises(StopIteration):
                bridge.run_pi_mode(bc)
        bc.push_telemetry.assert_called_once()
        self.assertEqual(server.accept_calls, 2)


if __name__ == "__main__":
    unittest.main()
