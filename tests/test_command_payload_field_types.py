"""Negative controls for exact command field types (synthetic, no ECU output)."""
import unittest
from datetime import datetime, timezone

from hardware_transport_security import (
    HardwareTransportError, build_safe_stop_payload, validate_safe_stop_payload,
)


class CommandFieldTypeTests(unittest.TestCase):
    def setUp(self):
        self.valid = build_safe_stop_payload(
            block_index=4, incident_id="incident-4",
            timestamp=datetime(2026, 11, 23, tzinfo=timezone.utc),
        )

    def test_valid_canonical_command(self):
        self.assertEqual(validate_safe_stop_payload(self.valid), self.valid)

    def test_reject_coercible_command_name(self):
        for value in ("safe_mode_stop", " SAFE_MODE_STOP ", ["SAFE_MODE_STOP"], 1, None):
            with self.subTest(value=value), self.assertRaises(HardwareTransportError):
                validate_safe_stop_payload({**self.valid, "cmd": value})

    def test_reject_non_string_timestamp(self):
        for value in (0, True, None, ["2026-11-23T00:00:00+00:00"]):
            with self.subTest(value=value), self.assertRaises(HardwareTransportError):
                validate_safe_stop_payload({**self.valid, "timestamp": value})

    def test_reject_non_string_incident_id(self):
        for value in (0, True, None, ["incident-4"], {"id": "incident-4"}):
            with self.subTest(value=value), self.assertRaises(HardwareTransportError):
                validate_safe_stop_payload({**self.valid, "incident_id": value})

    def test_no_mutation_on_rejection(self):
        bad = {**self.valid, "incident_id": ["incident-4"]}
        before = dict(bad)
        with self.assertRaises(HardwareTransportError):
            validate_safe_stop_payload(bad)
        self.assertEqual(bad, before)


if __name__ == "__main__":
    unittest.main()
