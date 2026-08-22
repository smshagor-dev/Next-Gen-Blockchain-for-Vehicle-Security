import ast
import unittest
from pathlib import Path


class ReferenceDashboardContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.path = Path("dashboard_reference_ui.py")
        cls.text = cls.path.read_text(encoding="utf-8")
        cls.tree = ast.parse(cls.text)
        cls.main_text = Path("main.py").read_text(encoding="utf-8-sig")

    def test_main_launches_reference_shell(self):
        self.assertIn("from dashboard_reference_ui import SmartCarDashboard", self.main_text)

    def test_reference_sidebar_has_all_requested_pages(self):
        for key, title in (
            ("overview", "Dashboard"),
            ("vehicles", "Vehicles"),
            ("transactions", "Transactions"),
            ("access", "Access Control"),
            ("ownership", "Ownership"),
            ("audit", "Audit Logs"),
            ("threats", "Threat Detection"),
            ("alerts", "Alerts"),
            ("scan", "Security Scan"),
            ("contracts", "Smart Contract"),
            ("nodes", "Nodes"),
            ("settings", "Settings"),
        ):
            self.assertIn(f'("{key}", "{title}"', self.text)
            self.assertIn(f'self._reference_pages["{key}"]', self.text)

    def test_sidebar_items_use_real_page_controller(self):
        self.assertIn("command=lambda p=key: self._show_reference_page(p)", self.text)
        self.assertIn("page.tkraise()", self.text)
        self.assertIn("self._active_page = key", self.text)

    def test_dashboard_matches_reference_information_hierarchy(self):
        for marker in (
            "Total Vehicles",
            "Total Transactions",
            "Active Nodes",
            "Security Score",
            "Vehicle Status Overview",
            "Recent Blockchain Activity",
            "Network Status",
            "Security Alerts",
            "Transaction Overview",
        ):
            self.assertIn(marker, self.text)

    def test_runtime_values_are_provider_or_backend_derived(self):
        render = self._method_source("_render_snapshot")
        for marker in (
            'data.get("connection_status"',
            'data.get("vehicle_overview"',
            'data.get("v2x_peers"',
            'data.get("object_detection"',
            'data.get("camera_status"',
            'data.get("identity_security"',
            'data.get("reviewer_audit"',
            'getattr(self.blockchain, "chain", None)',
        ):
            self.assertIn(marker, render)

    def test_reference_screenshot_numbers_are_not_hardcoded(self):
        # Guard only user-visible literal KPI strings from the reference image.
        # Numeric canvas geometry (for example cx - 128) is legitimate UI layout.
        for forbidden in ('"128"', '"1,256"', '"98.6%"', '"+18.7%"', '"156 ms"', '"3.2s"'):
            self.assertNotIn(forbidden, self.text)

    def test_no_demo_or_random_runtime_generation(self):
        lowered = self.text.lower()
        for forbidden in (
            "random.uniform(",
            "random.randint(",
            "fake_peer",
            "fake_detection",
            "demo_telemetry",
            "mock_vehicle",
        ):
            self.assertNotIn(forbidden, lowered)
        self.assertIn("no explicit numeric score", lowered)

    def test_missing_boolean_values_are_not_coerced_to_false(self):
        method = self._method_source("_bool_text")
        self.assertIn("if not ready or not isinstance(value, bool)", method)
        self.assertIn("return UNAVAILABLE", method)

    def test_security_score_is_explicit_only(self):
        method = self._method_source("_security_score")
        self.assertIn("Only display an explicitly exposed numeric score", method)
        self.assertNotIn("return 98", method)
        self.assertNotIn("100 -", method)

    def test_access_actions_reuse_authenticated_backend_methods(self):
        for marker in (
            "command=self._do_auth",
            "self._do_start",
            "self._do_stop",
            "self._do_lock",
            "command=self._do_recover",
        ):
            self.assertIn(marker, self.text)

    def test_runtime_secrets_are_not_displayed(self):
        self.assertIn('"Configured" if bool(self.AUTH_TOKEN)', self.text)
        self.assertIn('"Configured" if bool(self.PASSWORD)', self.text)
        self.assertNotIn("configure(text=self.AUTH_TOKEN", self.text)
        self.assertNotIn("configure(text=self.PASSWORD", self.text)

    def _method_source(self, method_name: str) -> str:
        for node in ast.walk(self.tree):
            if isinstance(node, ast.FunctionDef) and node.name == method_name:
                return ast.get_source_segment(self.text, node) or ""
        self.fail(f"method not found: {method_name}")


if __name__ == "__main__":
    unittest.main()
