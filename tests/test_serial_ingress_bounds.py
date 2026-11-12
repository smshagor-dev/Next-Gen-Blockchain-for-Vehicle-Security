"""Serial ingress bounded framing: in-memory only, no real actuator access."""
import io
import unittest
from hardware_bridge import read_bounded_serial_json

class SerialIngressTests(unittest.TestCase):
    def test_valid_object(self):
        self.assertEqual(read_bounded_serial_json(io.BytesIO(b'{"speed":3}\\n')), {"speed": 3})

    def test_empty_timeout(self):
        self.assertIsNone(read_bounded_serial_json(io.BytesIO(b"")))

    def test_incomplete_frame_rejected(self):
        with self.assertRaisesRegex(ValueError, "incomplete"):
            read_bounded_serial_json(io.BytesIO(b'{"speed":3}'))

    def test_oversized_frame_rejected(self):
        with self.assertRaisesRegex(ValueError, "oversized"):
            read_bounded_serial_json(io.BytesIO(b"x" * 100 + b"\\n"), 64)

    def test_invalid_utf8_rejected(self):
        with self.assertRaisesRegex(ValueError, "invalid serial JSON"):
            read_bounded_serial_json(io.BytesIO(b"\\xff\\n"))

    def test_nonobject_rejected(self):
        with self.assertRaisesRegex(ValueError, "must be an object"):
            read_bounded_serial_json(io.BytesIO(b"[]\\n"))

    def test_invalid_limit_rejected(self):
        with self.assertRaisesRegex(ValueError, "limit"):
            read_bounded_serial_json(io.BytesIO(b"{}\\n"), 1)

if __name__ == "__main__":
    unittest.main()
