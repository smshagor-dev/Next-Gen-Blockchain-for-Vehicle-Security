"""Non-actuating negative controls for bounded hardware JSON parsing.

Run: python -m unittest discover -s tests -p 'test_hardware_json_depth_fail_closed.py' -v
"""
import unittest

from hardware_transport_security import (
    HardwareTransportError,
    _canonical_bytes,
    _strict_json_loads,
)


class HardwareJsonDepthTests(unittest.TestCase):
    def test_deeply_nested_array_rejected_as_transport_error(self):
        raw = "[" * 1500 + "0" + "]" * 1500
        with self.assertRaises(HardwareTransportError) as caught:
            _strict_json_loads(raw)
        self.assertEqual(caught.exception.reason, "HW_JSON_NESTING_EXCEEDED")

    def test_deeply_nested_object_rejected_as_transport_error(self):
        raw = '{"a":' * 1500 + "0" + "}" * 1500
        with self.assertRaises(HardwareTransportError) as caught:
            _strict_json_loads(raw)
        self.assertEqual(caught.exception.reason, "HW_JSON_NESTING_EXCEEDED")

    def test_canonicalization_depth_rejected_as_transport_error(self):
        nested = 0
        for _ in range(1500):
            nested = [nested]
        with self.assertRaises(HardwareTransportError) as caught:
            _canonical_bytes({"payload": nested})
        self.assertEqual(caught.exception.reason, "HW_CANONICAL_ENCODING_INVALID")

    def test_shallow_json_still_parses(self):
        self.assertEqual(_strict_json_loads('{"payload":{"x":[1,2]}}'),
                         {"payload": {"x": [1, 2]}})

    def test_malformed_json_keeps_distinct_error(self):
        with self.assertRaises(HardwareTransportError) as caught:
            _strict_json_loads('{"a":}')
        self.assertEqual(caught.exception.reason, "HW_JSON_MALFORMED")

    def test_duplicate_members_still_rejected(self):
        with self.assertRaises(HardwareTransportError) as caught:
            _strict_json_loads('{"a":1,"a":2}')
        self.assertEqual(caught.exception.reason, "HW_JSON_DUPLICATE_KEY")


if __name__ == "__main__":
    unittest.main()
