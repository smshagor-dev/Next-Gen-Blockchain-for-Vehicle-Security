import csv
import tempfile
import unittest
from pathlib import Path
from research_contracts.paired_cluster_influence_audit import load, audit

class ClusterSensitivityTests(unittest.TestCase):
    def make(self, records):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        path = Path(tmp.name) / 'incidents.csv'
        with path.open('w', newline='') as stream:
            writer = csv.writer(stream)
            writer.writerow(['scenario_id','incident_id','truth','baseline','proposed'])
            writer.writerows(records)
        return path

    def test_stable_positive_effect(self):
        records = [(f's{i}',f'a{i}',0,1,0) for i in range(3)] + [(f's{i}',f'b{i}',1,0,1) for i in range(3)]
        rows, digest = load(self.make(records))
        result = audit(rows, digest)
        self.assertEqual(result['paired_effect'], 1)
        self.assertTrue(result['effect_sign_stable'])

    def test_duplicate_incident_rejected(self):
        path = self.make([('s1','a',0,0,0),('s1','a',1,1,1)])
        with self.assertRaisesRegex(ValueError,'duplicate'):
            load(path)

    def test_nonbinary_rejected(self):
        with self.assertRaisesRegex(ValueError,'nonbinary'):
            load(self.make([('s1','a',0,2,1)]))

    def test_missing_class_in_loo_is_reported(self):
        records = [('s1','a',1,0,1),('s2','b',0,0,0),('s3','c',0,0,0)]
        rows, digest = load(self.make(records))
        result = audit(rows, digest)
        self.assertIsNone(result['leave_one_scenario_out'][0]['effect'])
        self.assertFalse(result['effect_sign_stable'])

    def test_too_few_scenarios_rejected(self):
        rows, digest = load(self.make([('s1','a',0,0,0),('s2','b',1,1,1)]))
        with self.assertRaisesRegex(ValueError,'three'):
            audit(rows,digest)

if __name__ == '__main__':
    unittest.main()
