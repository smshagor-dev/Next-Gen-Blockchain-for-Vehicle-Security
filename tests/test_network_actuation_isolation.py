"""Network/physical actuation separation regressions; no hardware is exercised."""
import unittest
from unittest.mock import Mock, patch

from hardware_bridge import SafeModeActuatorDispatcher, ECUCommandGateway


class NetworkActuationIsolationTests(unittest.TestCase):
    def setUp(self):
        self.gate = Mock()
        self.gate.is_armed.return_value = True
        self.dispatcher = SafeModeActuatorDispatcher(gate=self.gate)
        self.blockchain = Mock(safe_mode_active=True)
        self.block = Mock(index=17, safe_mode_activated=True)

    def test_arduino_command_never_written_even_when_bench_armed(self):
        serial = Mock()
        self.assertFalse(self.dispatcher.maybe_send_arduino(
            serial, self.blockchain, self.block,
            device_id="enrolled", device_secret="secret"))
        serial.write.assert_not_called()

    def test_pi_command_never_sent_even_when_bench_armed(self):
        conn = Mock()
        self.assertFalse(self.dispatcher.maybe_send_pi(
            conn, self.blockchain, self.block,
            device_id="enrolled", device_secret="secret"))
        conn.sendall.assert_not_called()

    def test_environment_opt_in_does_not_override_isolation(self):
        with patch("hardware_bridge.get_bool", return_value=True):
            dispatcher = SafeModeActuatorDispatcher(gate=self.gate)
        self.assertFalse(dispatcher.enabled)
        self.assertFalse(dispatcher._should_send(self.blockchain, self.block))

    def test_direct_ecu_gateway_still_fail_closed(self):
        gateway = ECUCommandGateway(gate=self.gate)
        self.assertFalse(gateway.send_safe_mode_stop(block_index=17))
        self.assertFalse(gateway._init_transport())
        self.assertFalse(gateway._send_can_safe_stop(17))
        self.assertFalse(gateway._send_serial_safe_stop(17))

    def test_emergency_and_sensor_states_cannot_enable_network_output(self):
        for emergency in (False, True):
            for sensor_ok in (False, True):
                self.blockchain.safe_mode_active = emergency
                self.block.safe_mode_activated = not sensor_ok
                with self.subTest(emergency=emergency, sensor_ok=sensor_ok):
                    self.assertFalse(self.dispatcher._should_send(self.blockchain, self.block))
                    conn = Mock()
                    self.dispatcher.maybe_send_pi(
                        conn, self.blockchain, self.block,
                        device_id="enrolled", device_secret="secret")
                    conn.sendall.assert_not_called()


if __name__ == "__main__":
    unittest.main()
