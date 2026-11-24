"""Isolated non-actuating serial fault model regressions."""
import unittest
from research_contracts.serial_fault_sequence_model import Session, State, run

class SerialFaultSequenceTests(unittest.TestCase):
    def test_authenticated_evidence_only(self):
        s = Session()
        self.assertEqual(s.step(bytes_received=12, frame_complete=True, authenticated=True), "evidence_only")
        self.assertEqual(s.accepted, 1)

    def test_partial_flood_budget(self):
        s = Session(byte_limit=32)
        for _ in range(5):
            s.step(bytes_received=8)
        self.assertEqual(s.quarantine_reason, "byte_budget")

    def test_bad_mac_quarantines(self):
        s = Session()
        s.step(bytes_received=5, frame_complete=True)
        self.assertEqual(s.state, State.QUARANTINED)

    def test_malformed_quarantines(self):
        s = Session()
        s.step(bytes_received=1, malformed=True)
        self.assertEqual(s.quarantine_reason, "malformed")

    def test_frame_limit(self):
        s = Session(frame_limit=1)
        s.step(bytes_received=1, frame_complete=True, authenticated=True)
        s.step(bytes_received=1, frame_complete=True, authenticated=True)
        self.assertEqual(s.quarantine_reason, "frame_budget")

    def test_quarantine_absorbing(self):
        s = Session()
        s.step(bytes_received=1, malformed=True)
        self.assertEqual(s.step(bytes_received=100000, frame_complete=True, authenticated=True), "closed")
        self.assertEqual(s.accepted, 0)

    def test_invalid_byte_count(self):
        with self.assertRaises(ValueError):
            Session().step(bytes_received=-1)

    def test_reproducible(self):
        self.assertEqual(run(42, 30), run(42, 30))

    def test_synthetic_scenarios(self):
        rows = run(17, 6)
        self.assertEqual(len(rows), 6)
        self.assertEqual(rows[0]["state"], "open")
        self.assertTrue(all(r["state"] == "quarantined" for r in rows[1:]))

if __name__ == "__main__":
    unittest.main()
