"""Executable regression for bench stop cooldown under wall-clock discontinuities.

Only the dispatcher class is evaluated with inert dependencies. No hardware access.
"""
import ast
from pathlib import Path
import types
import unittest
from unittest.mock import patch


class CooldownClockTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        source = Path(__file__).resolve().parents[1].joinpath("hardware_bridge.py").read_text(encoding="utf-8-sig")
        tree = ast.parse(source)
        node = next(n for n in tree.body if isinstance(n, ast.ClassDef) and n.name == "SafeModeActuatorDispatcher")
        class FakeGate:
            def is_armed(self):
                return True
        class FakeGateway:
            def __init__(self, gate):
                pass
        cls.clock = types.SimpleNamespace(value=100.0, monotonic=lambda: cls.clock.value)
        namespace = {
            "Optional": __import__("typing").Optional,
            "BenchActuationGate": FakeGate,
            "ECUCommandGateway": FakeGateway,
            "get_bool": lambda *_: True,
            "time": cls.clock,
        }
        exec(compile(ast.Module(body=[node], type_ignores=[]), "<dispatcher>", "exec"), namespace)
        cls.dispatcher_class = namespace["SafeModeActuatorDispatcher"]

    def test_cooldown_is_monotonic_and_first_stop_not_suppressed(self):
        dispatcher = self.dispatcher_class()
        bc = types.SimpleNamespace(safe_mode_active=True)
        block = types.SimpleNamespace(safe_mode_activated=True)
        self.clock.value = 100.0
        self.assertTrue(dispatcher._should_send(bc, block))
        dispatcher._last_sent_at = self.clock.value
        self.clock.value = 100.4
        self.assertFalse(dispatcher._should_send(bc, block))
        self.clock.value = 100.81
        self.assertTrue(dispatcher._should_send(bc, block))

    def test_no_command_when_unarmed_or_safe_mode_inactive(self):
        dispatcher = self.dispatcher_class()
        bc = types.SimpleNamespace(safe_mode_active=False)
        block = types.SimpleNamespace(safe_mode_activated=False)
        self.assertFalse(dispatcher._should_send(bc, block))
        dispatcher.gate.is_armed = lambda: False
        bc.safe_mode_active = True
        self.assertFalse(dispatcher._should_send(bc, block))


if __name__ == "__main__":
    unittest.main()
