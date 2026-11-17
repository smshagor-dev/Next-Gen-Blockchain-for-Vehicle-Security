"""Authenticated telemetry event boundary tests; no physical actuator required."""
import sys
import unittest
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from hardware_transport_security import (
    HardwareTransportError, build_authenticated_envelope,
    validate_telemetry_payload, _NUMERIC_RANGES, _BOOL_FIELDS,
)

SECRET = "test-device-key-0123456789abcdef0123456789abcdef"


def payload(event):
    now = datetime.now(timezone.utc).isoformat()
    data = {key: (lo + hi) / 2 for key, (lo, hi) in _NUMERIC_RANGES.items()}
    data.update({key: False for key in _BOOL_FIELDS})
    data.update(timestamp=now, event=event)
    return data


class EventBoundaryTests(unittest.TestCase):
    def test_control_del_rejected_before_signing(self):
        for event in ("hello\x7fworld", "hello\x00world", "hello\nworld"):
            with self.subTest(event=repr(event)):
                with self.assertRaisesRegex(HardwareTransportError, "HW_TELEMETRY_EVENT_INVALID"):
                    validate_telemetry_payload(payload(event))
                with self.assertRaisesRegex(HardwareTransportError, "HW_TELEMETRY_EVENT_INVALID"):
                    build_authenticated_envelope("test-device", SECRET, "TELEMETRY", payload(event))

    def test_utf8_boundary(self):
        self.assertEqual(validate_telemetry_payload(payload("é" * 80))["event"], "é" * 80)
        with self.assertRaisesRegex(HardwareTransportError, "HW_TELEMETRY_EVENT_INVALID"):
            validate_telemetry_payload(payload("é" * 81))


if __name__ == "__main__":
    unittest.main()
