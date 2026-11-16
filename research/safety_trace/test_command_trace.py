import json
import unittest
from check_command_trace import check

BASE = dict(event_id='e1', decision='deny', origin='network',
            evidence_valid=False, local_override=False, actuator_write=False)

def run(*events):
    return check(json.dumps(event) for event in events)

class SafetyTraceTests(unittest.TestCase):
    def test_safe_deny(self):
        self.assertTrue(run(BASE)['pass'])
    def test_gated_allow(self):
        self.assertTrue(run(dict(BASE, decision='allow', evidence_valid=True))['pass'])
    def test_local_override(self):
        self.assertTrue(run(dict(BASE, origin='local', decision='allow', local_override=True, actuator_write=True))['pass'])
    def test_network_actuator(self):
        self.assertIn('network_actuator_write', self.properties(dict(BASE, actuator_write=True)))
    def test_denied_actuator(self):
        self.assertIn('denied_actuator_write', self.properties(dict(BASE, origin='local', actuator_write=True)))
    def test_ungated_allow(self):
        self.assertIn('ungated_network_allow', self.properties(dict(BASE, decision='allow')))
    def test_forged_override(self):
        self.assertIn('forged_local_override', self.properties(dict(BASE, local_override=True)))
    def test_blocked_override(self):
        self.assertIn('local_override_blocked', self.properties(dict(BASE, origin='local', local_override=True)))
    def test_duplicate(self):
        self.assertIn('duplicate_event_id', [v['property'] for v in run(BASE, BASE)['violations']])
    def test_bad_type(self):
        self.assertIn('invalid_schema', self.properties(dict(BASE, actuator_write=1)))
    def test_malformed(self):
        self.assertEqual(check(['{'])['violations'][0]['property'], 'invalid_json')
    def test_missing(self):
        self.assertEqual(check(['{}'])['violations'][0]['property'], 'missing_fields')
    def test_empty(self):
        self.assertFalse(check([])['pass'])
    @staticmethod
    def properties(event):
        return [v['property'] for v in run(event)['violations']]

if __name__ == '__main__':
    unittest.main()
