"""Deterministic state-transition conformance against production network output.

This is software-only safety regression evidence, not physical interlock proof.
The oracle intentionally permits no network-originated physical command until
receiver authorization and independent physical interlocks exist.
"""
import itertools
import unittest
from types import SimpleNamespace
from unittest.mock import Mock, patch

from hardware_bridge import SafeModeActuatorDispatcher, ECUCommandGateway


class StatefulNetworkIsolationConformance(unittest.TestCase):
    def test_transition_traces_never_emit_network_actuation(self):
        # Trace dimensions: local emergency latch, sensor health, ledger alarm,
        # legacy bench gate, and restart. Every sequence has three transitions.
        alphabet = tuple(itertools.product((False, True), repeat=5))
        checked = 0
        for first in alphabet:
            for second in alphabet:
                # 1,024 deterministic two-step traces plus a restart step.
                gate = Mock()
                gateway = Mock()
                with patch("hardware_bridge.ECUCommandGateway", return_value=gateway):
                    dispatcher = SafeModeActuatorDispatcher(gate=gate)
                    for emergency, sensor_ok, alarm, armed, restart in (first, second):
                        gate.is_armed.return_value = armed
                        bc = SimpleNamespace(safe_mode_active=alarm or emergency)
                        block = SimpleNamespace(index=checked, safe_mode_activated=not sensor_ok)
                        if restart:
                            dispatcher = SafeModeActuatorDispatcher(gate=gate)
                        conn, serial = Mock(), Mock()
                        self.assertFalse(dispatcher._should_send(bc, block))
                        self.assertFalse(dispatcher.maybe_send_pi(
                            conn, bc, block, device_id="enrolled", device_secret="secret"))
                        self.assertFalse(dispatcher.maybe_send_arduino(
                            serial, bc, block, device_id="enrolled", device_secret="secret"))
                        conn.sendall.assert_not_called()
                        serial.write.assert_not_called()
                        gateway.send_safe_mode_stop.assert_not_called()
                        checked += 1
        self.assertEqual(checked, 2048)

    def test_legacy_ecu_state_corruption_cannot_enable_output(self):
        gate = Mock()
        gateway = ECUCommandGateway(gate=gate)
        for armed, mode, init_ok in itertools.product(
            (False, True), ("can", "serial"), (False, True)
        ):
            gate.is_armed.return_value = armed
            gateway.mode = mode
            gateway._init_ok = init_ok
            self.assertFalse(gateway.send_safe_mode_stop(block_index=42))
            self.assertFalse(gateway._send_can_safe_stop(42))
            self.assertFalse(gateway._send_serial_safe_stop(42))


if __name__ == "__main__":
    unittest.main()
