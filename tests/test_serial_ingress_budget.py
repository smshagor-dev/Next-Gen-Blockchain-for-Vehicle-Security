import unittest
from serial_ingress_budget import SerialIngressBudget, SerialIngressBudgetExceeded


class SerialIngressBudgetTests(unittest.TestCase):
    def test_exact_byte_limit(self):
        b = SerialIngressBudget(max_bytes=1024, max_frames=2)
        b.charge_bytes(1000)
        b.charge_bytes(24)
        self.assertEqual(b.bytes_seen, 1024)
        with self.assertRaisesRegex(SerialIngressBudgetExceeded, "BYTE"):
            b.charge_bytes(1)
        self.assertEqual(b.bytes_seen, 1024)

    def test_frame_cap(self):
        b = SerialIngressBudget(max_bytes=1024, max_frames=2)
        b.charge_frame()
        b.charge_frame()
        with self.assertRaisesRegex(SerialIngressBudgetExceeded, "FRAME"):
            b.charge_frame()
        self.assertEqual(b.frames_seen, 2)

    def test_invalid_configuration_and_bool(self):
        for kwargs in (
            {"max_bytes": True, "max_frames": 2},
            {"max_bytes": 1024, "max_frames": False},
            {"max_bytes": 0, "max_frames": 1},
        ):
            with self.assertRaises(ValueError):
                SerialIngressBudget(**kwargs)

    def test_reject_invalid_counts(self):
        b = SerialIngressBudget(max_bytes=1024, max_frames=1)
        for n in (-1, True, 1.5):
            with self.assertRaises(ValueError):
                b.charge_bytes(n)

    def test_repeated_partial_input_is_bounded(self):
        b = SerialIngressBudget(max_bytes=1024, max_frames=100)
        for _ in range(1024):
            b.charge_bytes(1)
        with self.assertRaises(SerialIngressBudgetExceeded):
            b.charge_bytes(1)

    def test_frame_count_independent_of_bytes(self):
        b = SerialIngressBudget(max_bytes=1024, max_frames=1)
        b.charge_bytes(100)
        b.charge_frame()
        with self.assertRaises(SerialIngressBudgetExceeded):
            b.charge_frame()
        self.assertEqual(b.bytes_seen, 100)


if __name__ == "__main__":
    unittest.main()
