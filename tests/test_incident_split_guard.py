import csv
import tempfile
import unittest
from pathlib import Path
from research_contracts.incident_split_guard import validate, REQUIRED

H = 'a' * 64

def record(i, split='train', incident=None, vehicle=None, session=None, digest=H):
    return dict(record_id=str(i), source_sha256=digest, incident_id=incident or 'i'+str(i),
                vehicle_id=vehicle or 'v'+str(i), session_id=session or 's'+str(i),
                split=split, label=str(i % 2))

class GuardTests(unittest.TestCase):
    def check(self, rows):
        with tempfile.TemporaryDirectory() as d:
            path = Path(d) / 'manifest.csv'
            with path.open('w', newline='') as f:
                writer = csv.DictWriter(f, fieldnames=REQUIRED)
                writer.writeheader()
                writer.writerows(rows)
            return validate(path)

    def test_valid_disjoint(self):
        self.assertEqual(self.check([record(1), record(2, 'test')])['records'], 2)

    def test_duplicate_record(self):
        with self.assertRaisesRegex(ValueError, 'duplicate'):
            self.check([record(1), record(1)])

    def test_incident_leak(self):
        with self.assertRaisesRegex(ValueError, 'leakage'):
            self.check([record(1), record(2, 'test', incident='i1')])

    def test_vehicle_leak(self):
        with self.assertRaisesRegex(ValueError, 'leakage'):
            self.check([record(1), record(2, 'test', vehicle='v1')])

    def test_session_leak(self):
        with self.assertRaisesRegex(ValueError, 'leakage'):
            self.check([record(1), record(2, 'test', session='s1')])

    def test_bad_digest(self):
        with self.assertRaisesRegex(ValueError, 'sha256'):
            self.check([record(1, digest='wrong')])

    def test_empty(self):
        with self.assertRaisesRegex(ValueError, 'empty'):
            self.check([])

    def test_invalid_label(self):
        row = record(1)
        row['label'] = 'attack'
        with self.assertRaisesRegex(ValueError, 'label'):
            self.check([row])

    def test_same_group_same_split_allowed(self):
        self.assertEqual(self.check([record(1), record(2, incident='i1', vehicle='v1', session='s1')])['records'], 2)

if __name__ == '__main__':
    unittest.main()
