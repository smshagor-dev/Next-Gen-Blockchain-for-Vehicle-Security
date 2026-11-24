"""Process exit-before-readiness fault injection (no vehicle actuation)."""
import unittest
from research_contracts.process_readiness_fault import probe


class ProcessReadinessFaultTests(unittest.TestCase):
    def test_abrupt_exit_detected(self):
        result = probe("exit", timeout=3)
        self.assertEqual(result["reason"], "exited_before_ready", result)
        self.assertEqual(result["exitcode"], 23)

    def test_normal_ready(self):
        result = probe("normal", timeout=3)
        self.assertEqual(result["reason"], "ready", result)
        self.assertTrue(result["detected"])

    def test_invalid_input(self):
        with self.assertRaises(ValueError):
            probe("unknown")
        with self.assertRaises(ValueError):
            probe("exit", timeout=0)


if __name__ == "__main__":
    unittest.main()
