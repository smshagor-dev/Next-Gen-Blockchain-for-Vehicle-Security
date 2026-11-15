"""Fail-closed ECU egress tests; no real CAN, serial or vehicle hardware."""
import unittest
from unittest.mock import patch, MagicMock

import hardware_bridge


class ArmedBenchGate:
    def is_armed(self):
        return True


class EcuEgressIsolationTests(unittest.TestCase):
    def setUp(self):
        self.bus = MagicMock()
        self.serial = MagicMock()
        self.can_stub = MagicMock()
        self.can_stub.interface.Bus.return_value = self.bus
        self.serial_stub = MagicMock()
        self.serial_stub.Serial.return_value = self.serial

    def test_explicitly_enabled_armed_bench_never_opens_can_or_serial(self):
        for mode in ("can", "serial"):
            with self.subTest(mode=mode), \
                 patch.object(hardware_bridge, "get_bool", return_value=True), \
                 patch.object(hardware_bridge, "get_env", side_effect=lambda name, default=None: mode if name == "SMARTCAR_ECU_MODE" else default), \
                 patch.object(hardware_bridge, "can", self.can_stub), \
                 patch.object(hardware_bridge, "serial", self.serial_stub):
                gateway = hardware_bridge.ECUCommandGateway(gate=ArmedBenchGate())
                self.assertFalse(gateway._init_ok)
                self.assertIsNone(gateway._can_bus)
                self.assertIsNone(gateway._ser)
                self.assertFalse(gateway.send_safe_mode_stop(7))
                self.assertFalse(gateway._init_transport())
                self.assertFalse(gateway._init_can())
                self.assertFalse(gateway._init_serial())
                self.assertFalse(gateway._send_can_safe_stop(7))
                self.assertFalse(gateway._send_serial_safe_stop(7))
        self.can_stub.interface.Bus.assert_not_called()
        self.serial_stub.Serial.assert_not_called()
        self.bus.send.assert_not_called()
        self.serial.write.assert_not_called()

    def test_injected_live_bus_cannot_be_used_by_legacy_direct_method(self):
        with patch.object(hardware_bridge, "get_bool", return_value=True), \
             patch.object(hardware_bridge, "get_env", return_value="can"), \
             patch.object(hardware_bridge, "can", self.can_stub):
            gateway = hardware_bridge.ECUCommandGateway(gate=ArmedBenchGate())
            gateway._can_bus = self.bus  # simulate stale or injected transport
            gateway._init_ok = True
            self.assertFalse(gateway._send_can_safe_stop(42))
            self.assertFalse(gateway.send_safe_mode_stop(42))
            self.bus.send.assert_not_called()

    def test_network_dispatcher_does_not_reach_ecu_even_with_safe_mode(self):
        class Block:
            index = 4
            safe_mode_activated = True

        class Chain:
            safe_mode_active = True

        with patch.object(hardware_bridge, "get_bool", return_value=True), \
             patch.object(hardware_bridge, "get_env", return_value="can"), \
             patch.object(hardware_bridge, "can", self.can_stub):
            dispatcher = hardware_bridge.SafeModeActuatorDispatcher(gate=ArmedBenchGate())
            connection = MagicMock()
            # The bench-node envelope is not an ECU command and must not
            # cause a CAN bus open or a CAN frame transmission.
            dispatcher.maybe_send_pi(
                connection, Chain(), Block(),
                device_id="bench", device_secret="a" * 32)
            self.can_stub.interface.Bus.assert_not_called()
            self.bus.send.assert_not_called()


if __name__ == "__main__":
    unittest.main()
