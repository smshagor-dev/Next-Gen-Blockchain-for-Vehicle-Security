import csv
import tempfile
import unittest
from pathlib import Path
from research_contracts.cross_source_embargo import FIELDS, validate

D1, D2 = 'a' * 64, 'b' * 64


def row(record, digest, incident, vehicle, session, split, t):
    return dict(zip(FIELDS, (record, digest, incident, vehicle, session, split, str(t))))


class CrossSourceEmbargoTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.path = Path(self.temp.name) / 'splits.csv'
        self.rows = [row('r1', D1, 'i1', 'v1', 's1', 'train', 100),
                     row('r2', D2, 'i2', 'v2', 's2', 'test', 200)]

    def check(self, rows=None, embargo=10):
        with self.path.open('w', newline='') as f:
            writer = csv.DictWriter(f, fieldnames=FIELDS)
            writer.writeheader()
            writer.writerows(self.rows if rows is None else rows)
        return validate(self.path, embargo)

    def test_valid_disjoint_holdout(self):
        self.assertEqual(self.check()['records'], 2)

    def test_cross_file_vehicle_leakage(self):
        self.rows[1]['global_vehicle_id'] = 'v1'
        with self.assertRaisesRegex(ValueError, 'identity leakage'): self.check()

    def test_cross_file_incident_leakage(self):
        self.rows[1]['global_incident_id'] = 'i1'
        with self.assertRaisesRegex(ValueError, 'identity leakage'): self.check()

    def test_cross_file_session_leakage(self):
        self.rows[1]['global_session_id'] = 's1'
        with self.assertRaisesRegex(ValueError, 'identity leakage'): self.check()

    def test_embargo_boundary_rejected(self):
        self.rows[1]['event_time_s'] = '110'
        with self.assertRaisesRegex(ValueError, 'embargo'): self.check()

    def test_reverse_time_rejected(self):
        self.rows[1]['event_time_s'] = '90'
        with self.assertRaisesRegex(ValueError, 'chronological'): self.check()

    def test_nonfinite_time_rejected(self):
        self.rows[1]['event_time_s'] = 'nan'
        with self.assertRaisesRegex(ValueError, 'nonfinite'): self.check()

    def test_duplicate_record_rejected(self):
        with self.assertRaisesRegex(ValueError, 'duplicate'): self.check(self.rows + [self.rows[0]])

    def test_invalid_embargo_rejected(self):
        with self.assertRaisesRegex(ValueError, 'embargo'): self.check(embargo=float('nan'))

    def test_missing_identity_rejected(self):
        self.rows[1]['global_session_id'] = ''
        with self.assertRaisesRegex(ValueError, 'missing'): self.check()

    def test_duplicate_header_rejected(self):
        self.path.write_text('record_id,record_id\na,b\n')
        with self.assertRaisesRegex(ValueError, 'schema'): validate(self.path)


if __name__ == '__main__':
    unittest.main()
