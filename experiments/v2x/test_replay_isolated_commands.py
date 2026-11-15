import itertools
import json
import unittest
from replay_isolated_commands import evaluate, replay

def event(**changes):
    obj = dict(incident_id="trial-1", command="alert", authenticated=True,
               fresh=True, evidence_admitted=True, local_emergency=False)
    obj.update(changes)
    return obj

class IsolatedReplayTests(unittest.TestCase):
    def test_exhaustive_remote_action_invariant(self):
        for auth, fresh, admitted, emergency in itertools.product((False, True), repeat=4):
            for action in ("brake", "steer", "throttle", "reset_emergency"):
                self.assertNotEqual(evaluate(event(command=action, authenticated=auth,
                    fresh=fresh, evidence_admitted=admitted, local_emergency=emergency)),
                    "simulated_alert")
    def test_alert_requires_all_gates(self):
        for auth, fresh, admitted, emergency in itertools.product((False, True), repeat=4):
            allowed = auth and fresh and admitted and not emergency
            verdict = evaluate(event(authenticated=auth, fresh=fresh,
                                      evidence_admitted=admitted, local_emergency=emergency))
            self.assertEqual(verdict == "simulated_alert", allowed)
    def test_duplicate_rejected(self):
        raw = (json.dumps(event()) + "\n") * 2
        with self.assertRaises(ValueError):
            replay(raw.encode())
    def test_schema_rejected(self):
        with self.assertRaises(ValueError):
            evaluate(dict(event(), unexpected=True))
    def test_no_boolean_coercion(self):
        with self.assertRaises(ValueError):
            evaluate(event(authenticated=1))
    def test_deterministic_receipt(self):
        raw = (json.dumps(event()) + "\n").encode()
        self.assertEqual(replay(raw), replay(raw))
    def test_invalid_line_rejected(self):
        with self.assertRaises(ValueError):
            replay(b'{"bad":true}\n')
    def test_empty_is_not_effectiveness_evidence(self):
        self.assertEqual(replay(b"")["evidence_class"], "synthetic_or_unverified_simulation_only")

    def test_duplicate_security_gate_rejected(self):
        raw = json.dumps(event()).replace('"authenticated": true',
            '"authenticated": false, "authenticated": true').encode() + b"\n"
        with self.assertRaisesRegex(ValueError, "duplicate JSON field"):
            replay(raw)

    def test_duplicate_incident_identifier_key_rejected(self):
        raw = json.dumps(event()).replace('"incident_id": "trial-1"',
            '"incident_id": "forged", "incident_id": "trial-1"').encode() + b"\n"
        with self.assertRaisesRegex(ValueError, "duplicate JSON field"):
            replay(raw)

    def test_nonfinite_json_constant_rejected(self):
        raw = json.dumps(event()).replace('"authenticated": true',
            '"authenticated": NaN').encode() + b"\n"
        with self.assertRaisesRegex(ValueError, "non-finite"):
            replay(raw)

    def test_invalid_utf8_rejected(self):
        with self.assertRaisesRegex(ValueError, "invalid input at line"):
            replay(b"\\xff\\n")

    def test_valid_input_still_admitted(self):
        raw = (json.dumps(event()) + "\\n").encode()
        result = replay(raw)
        self.assertEqual(result["events"], [{"incident_id": "trial-1", "verdict": "simulated_alert"}])

if __name__ == "__main__":
    unittest.main()
