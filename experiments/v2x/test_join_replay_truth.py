import json
import unittest
from join_replay_truth import join

DIGEST = 'a' * 64
TRUTH = b'incident_id,cluster_id,should_alert\na,c1,1\nb,c1,0\nc,c2,1\n'

def replay(events, **changes):
    data = {'input_sha256': DIGEST, 'events': events, 'count': len(events),
            'simulated_alerts': sum(x['verdict'] == 'simulated_alert' for x in events)}
    data.update(changes)
    return json.dumps(data).encode()

class JoinTests(unittest.TestCase):
    def test_missing_is_false_negative(self):
        result = join(TRUTH, replay([{'incident_id': 'a', 'verdict': 'simulated_alert'}]), DIGEST)
        self.assertEqual(result['counts'], {'tp': 1, 'tn': 1, 'fp': 0, 'fn': 1})
        self.assertEqual(result['missing_decisions'], 2)
    def test_false_positive(self):
        result = join(TRUTH, replay([{'incident_id': 'b', 'verdict': 'simulated_alert'}]), DIGEST)
        self.assertEqual(result['counts']['fp'], 1)
    def test_duplicate_replay(self):
        event = {'incident_id': 'a', 'verdict': 'simulated_alert'}
        with self.assertRaises(ValueError): join(TRUTH, replay([event, event]), DIGEST)
    def test_unexpected_incident(self):
        with self.assertRaises(ValueError): join(TRUTH, replay([{'incident_id': 'z', 'verdict': 'simulated_alert'}]), DIGEST)
    def test_digest_mismatch(self):
        with self.assertRaises(ValueError): join(TRUTH, replay([]), 'b' * 64)
    def test_bad_counts(self):
        with self.assertRaises(ValueError): join(TRUTH, replay([], count=3), DIGEST)
    def test_duplicate_truth(self):
        with self.assertRaises(ValueError): join(TRUTH + b'a,c3,1\n', replay([]), DIGEST)
    def test_ragged_truth(self):
        with self.assertRaises(ValueError): join(TRUTH + b'd,c4\n', replay([]), DIGEST)
    def test_duplicate_json_key(self):
        with self.assertRaises(ValueError): join(TRUTH, b'{"events":[],"events":[]}', DIGEST)
    def test_no_truth(self):
        with self.assertRaises(ValueError): join(b'incident_id,cluster_id,should_alert\n', replay([]), DIGEST)

if __name__ == '__main__':
    unittest.main()
