"""Fail-closed hardware mode dispatch tests; no physical hardware is accessed."""
import unittest
from unittest import mock

import hardware_bridge as bridge


class HardwareModeDispatchTests(unittest.TestCase):
    def _run(self, mode):
        def env(key, default=None):
            if key == "SMARTCAR_HW_MODE":
                return mode
            return default

        with mock.patch.object(bridge, "get_env", side_effect=env), \
             mock.patch.object(bridge, "SmartCarBlockchain") as chain, \
             mock.patch.object(bridge, "run_pi_mode") as pi, \
             mock.patch.object(bridge, "run_arduino_mode") as arduino:
            bridge.main()
            return chain, pi, arduino

    def test_unknown_mode_never_opens_either_transport(self):
        chain, pi, arduino = self._run("pii")
        pi.assert_not_called()
        arduino.assert_not_called()
        chain.return_value.stop_engine.assert_called_once()
        chain.return_value.save.assert_called_once()

    def test_empty_mode_does_not_default_to_arduino(self):
        _, pi, arduino = self._run("")
        pi.assert_not_called()
        arduino.assert_not_called()

    def test_explicit_pi_mode_only_opens_pi(self):
        _, pi, arduino = self._run("pi")
        pi.assert_called_once()
        arduino.assert_not_called()

    def test_explicit_arduino_mode_only_opens_arduino(self):
        _, pi, arduino = self._run("arduino")
        arduino.assert_called_once()
        pi.assert_not_called()


if __name__ == "__main__":
    unittest.main()
