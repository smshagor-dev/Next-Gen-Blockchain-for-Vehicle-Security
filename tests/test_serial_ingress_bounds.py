"""Serial ingress bounded framing: in-memory only, no real actuator access."""
import io
import unittest
from hardware_bridge import read_bounded_serial_json, SerialFramingDesynchronized

class FakeSerial(io.BytesIO):
    def read_until(self, expected=b"\n", size=None):
        out = bytearray()
        while size is None or len(out) < size:
            b = self.read(1)
            if not b:
                break
            out.extend(b)
            if b == expected:
                break
        return bytes(out)

class SerialIngressTests(unittest.TestCase):
    def test_valid_object(self):
        self.assertEqual(read_bounded_serial_json(FakeSerial(b'{"speed":3}\n')), {"speed": 3})

    def test_empty_timeout(self):
        self.assertIsNone(read_bounded_serial_json(FakeSerial(b"")))

    def test_incomplete_frame_rejected(self):
        with self.assertRaisesRegex(SerialFramingDesynchronized, "incomplete"):
            read_bounded_serial_json(FakeSerial(b'{"speed":3}'))

    def test_oversized_frame_rejected(self):
        with self.assertRaisesRegex(SerialFramingDesynchronized, "oversized"):
            read_bounded_serial_json(FakeSerial(b"x" * 100 + b"\n"), 64)

    def test_oversized_frame_quarantines_even_with_valid_following_frame(self):
        port = FakeSerial(b"x" * 100 + b"\\n" + b'{"speed":3}\\n')
        with self.assertRaises(SerialFramingDesynchronized):
            read_bounded_serial_json(port, 64)
        # The caller must close this port; it cannot safely resume parsing
        # bytes left over from an oversized or unterminated frame.
        self.assertTrue(port.read())

    def test_timeout_with_partial_frame_requires_port_restart(self):
        with self.assertRaises(SerialFramingDesynchronized):
            read_bounded_serial_json(FakeSerial(b'{"speed":3'), 64)

    def test_invalid_utf8_rejected(self):
        with self.assertRaisesRegex(ValueError, "invalid serial JSON"):
            read_bounded_serial_json(FakeSerial(b"\xff\n"))

    def test_nonobject_rejected(self):
        with self.assertRaisesRegex(ValueError, "must be an object"):
            read_bounded_serial_json(FakeSerial(b"[]\n"))

    def test_nonfinite_json_rejected(self):
        with self.assertRaisesRegex(ValueError, "invalid serial JSON"):
            read_bounded_serial_json(FakeSerial(b'{"speed":NaN}\n'))

    def test_invalid_limit_rejected(self):
        with self.assertRaisesRegex(ValueError, "limit"):
            read_bounded_serial_json(FakeSerial(b"{}\n"), 1)

if __name__ == "__main__":
    unittest.main()
