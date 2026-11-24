"""Source-level and isolated lazy-generator regression tests; no hardware access."""
import ast
import pathlib
import unittest
from unittest.mock import patch

ROOT = pathlib.Path(__file__).resolve().parents[1]
SOURCE = ROOT / "hardware_bridge.py"


class HardwareIngressParserTests(unittest.TestCase):
    def test_production_module_parses(self):
        ast.parse(SOURCE.read_text(encoding="utf-8-sig"), filename=str(SOURCE))

    def _helper(self):
        module = ast.parse(SOURCE.read_text(encoding="utf-8-sig"))
        node = next(n for n in module.body if isinstance(n, ast.FunctionDef)
                    and n.name == "_quarantined_serial_frames")
        class HardwareTransportError(Exception):
            def __init__(self, reason):
                super().__init__(reason)
                self.reason = reason
        scope = {"HardwareTransportError": HardwareTransportError}
        exec(compile(ast.Module(body=[node], type_ignores=[]), str(SOURCE), "exec"), scope)
        return scope["_quarantined_serial_frames"], HardwareTransportError

    def test_deferred_failure_quarantines(self):
        helper, error = self._helper()
        class Session:
            def receive_iter(self, chunk):
                yield "valid"
                raise error("HW_INVALID_MAC")
        frames = helper(Session(), b"fragment")
        self.assertEqual(next(frames), "valid")
        with patch("builtins.print"):
            with self.assertRaisesRegex(RuntimeError, "authentication/framing failure"):
                next(frames)
        with self.assertRaises(StopIteration):
            next(frames)

    def test_immediate_failure_quarantines(self):
        helper, error = self._helper()
        class Session:
            def receive_iter(self, chunk):
                raise error("HW_BAD_FRAME")
                yield None
        with patch("builtins.print"):
            with self.assertRaises(RuntimeError):
                list(helper(Session(), b"bad"))

    def test_unrelated_programming_error_not_hidden(self):
        helper, _ = self._helper()
        class Session:
            def receive_iter(self, chunk):
                raise AssertionError("programming defect")
                yield None
        with self.assertRaisesRegex(AssertionError, "programming defect"):
            list(helper(Session(), b"x"))


if __name__ == "__main__":
    unittest.main()
