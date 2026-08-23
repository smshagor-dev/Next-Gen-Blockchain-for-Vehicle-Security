import unittest
from pathlib import Path


class V400DashboardSecurityStrengthTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.text = Path("dashboard_reference_raster_ui.py").read_text(encoding="utf-8")

    def test_dashboard_replaces_legacy_score_with_security_strength(self):
        self.assertIn('text="Security Strength"', self.text)
        self.assertIn('evaluate_security_strength(data)', self.text)
        self.assertIn('"source-backed runtime posture"', self.text)

    def test_strength_levels_have_explicit_operational_colors(self):
        for constant in (
            "STRENGTH_STRONG",
            "STRENGTH_GUARDED",
            "STRENGTH_DEGRADED",
            "STRENGTH_RISK",
        ):
            self.assertIn(constant, self.text)
        for color in ("#24d18b", "#f6c343", "#f5a524", "#ff5c6c"):
            self.assertIn(color, self.text)

    def test_vehicle_risk_badge_uses_same_strength_evaluator(self):
        self.assertIn("def _derive_vehicle_risk_state", self.text)
        self.assertIn("strength = evaluate_security_strength(data)", self.text)
        self.assertIn('STRENGTH_STRONG: "protected"', self.text)
        self.assertIn('STRENGTH_RISK: "risk"', self.text)

    def test_sidebar_release_version_is_dynamic(self):
        self.assertIn("from release_metadata import RELEASE_VERSION", self.text)
        self.assertIn('child.configure(text=f"v{RELEASE_VERSION}")', self.text)


if __name__ == "__main__":
    unittest.main()
