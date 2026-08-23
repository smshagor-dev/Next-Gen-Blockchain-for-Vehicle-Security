import unittest

from runtime_security_strength import (
    STRENGTH_DEGRADED,
    STRENGTH_GUARDED,
    STRENGTH_RISK,
    STRENGTH_STRONG,
    evaluate_security_strength,
)


def point(value, source="test"):
    return {"status": "ok", "source": source, "value": value}


def healthy_snapshot():
    return {
        "connection_status": point("Connected"),
        "security_capability": point({"key_establishment": "ML-KEM-512"}),
        "identity_security": point({"identity_authenticity": True}),
        "consensus_security": point({"consensus_model": "permissioned"}),
    }


class RuntimeSecurityStrengthTests(unittest.TestCase):
    def test_connected_runtime_with_core_metadata_is_strong(self):
        result = evaluate_security_strength(healthy_snapshot())
        self.assertEqual(result["level"], STRENGTH_STRONG)
        self.assertTrue(result["source_backed"])
        self.assertFalse(result["numeric_score_synthesized"])
        self.assertFalse(result["certification_claim"])

    def test_partial_runtime_is_guarded(self):
        data = healthy_snapshot()
        data["connection_status"] = point("Partial")
        result = evaluate_security_strength(data)
        self.assertEqual(result["level"], STRENGTH_GUARDED)

    def test_medium_explicit_alert_is_guarded(self):
        data = healthy_snapshot()
        data["alerts"] = [{"severity": "medium"}]
        self.assertEqual(evaluate_security_strength(data)["level"], STRENGTH_GUARDED)

    def test_high_explicit_alert_is_risk(self):
        data = healthy_snapshot()
        data["security_alerts"] = [{"severity": "high"}]
        self.assertEqual(evaluate_security_strength(data)["level"], STRENGTH_RISK)

    def test_disconnected_runtime_is_degraded_not_fake_healthy(self):
        data = healthy_snapshot()
        data["connection_status"] = point("Not Connected")
        self.assertEqual(evaluate_security_strength(data)["level"], STRENGTH_DEGRADED)

    def test_missing_core_security_metadata_is_degraded(self):
        data = healthy_snapshot()
        data.pop("identity_security")
        result = evaluate_security_strength(data)
        self.assertEqual(result["level"], STRENGTH_DEGRADED)
        self.assertIn("identity_security", result["missing_core_metadata"])

    def test_empty_snapshot_fails_conservatively(self):
        result = evaluate_security_strength({})
        self.assertEqual(result["level"], STRENGTH_DEGRADED)
        self.assertFalse(result["core_metadata_available"])


if __name__ == "__main__":
    unittest.main()
