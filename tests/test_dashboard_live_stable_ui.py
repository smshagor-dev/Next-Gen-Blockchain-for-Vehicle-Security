import ast
import unittest
from pathlib import Path


class StableLiveDashboardContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.path = Path("dashboard_live_stable_ui.py")
        cls.text = cls.path.read_text(encoding="utf-8")
        cls.tree = ast.parse(cls.text)
        cls.main_text = Path("main.py").read_text(encoding="utf-8-sig")

    def test_main_launches_stable_live_shell(self):
        self.assertIn("from dashboard_live_stable_ui import SmartCarDashboard", self.main_text)
        self.assertIn("class StableLiveSmartCarDashboard(LiveSocketSmartCarDashboard)", self.text)

    def test_activity_feed_updates_in_place_without_destroy(self):
        method = self._method_source("_render_activity_feed")
        helper = self._method_source("_apply_feed_items")
        self.assertNotIn(".destroy()", method)
        self.assertNotIn(".destroy()", helper)
        self.assertIn("slot[\"signature\"] == signature", helper)
        self.assertIn("pack_forget", helper)
        self.assertIn("_feed_slot", helper)

    def test_security_alert_feed_updates_in_place_without_destroy(self):
        method = self._method_source("_render_alert_feed")
        self.assertNotIn(".destroy()", method)
        self.assertIn("_apply_feed_items", method)
        self.assertIn("No explicit alerts", method)

    def test_transaction_graph_is_timestamp_and_chain_backed(self):
        series = self._method_source("_transaction_series")
        chart = self._method_source("_draw_transaction_chart")
        self.assertIn("timestamp", series)
        self.assertIn("total_before_window", series)
        self.assertIn("self._block_fields", series)
        self.assertIn("Committed blockchain records", chart)
        self.assertIn("canvas.create_polygon", chart)
        self.assertIn("canvas.create_line", chart)
        self.assertIn("canvas.create_text", chart)
        self.assertIn("self._transaction_chart_signatures", chart)
        self.assertIn("source_signature", chart)
        self.assertNotIn("random", chart.lower())

    def test_graph_truthfully_handles_short_history(self):
        chart = self._method_source("_draw_transaction_chart")
        self.assertIn("Insufficient history for trend", chart)
        self.assertIn("No committed transaction history", chart)

    def test_no_fake_dashboard_values_or_secret_rendering(self):
        lowered = self.text.lower()
        for forbidden in (
            '"128"',
            '"1,256"',
            '"98.6%"',
            '"+18.7%"',
            "smartcar_auth_token",
            "smartcar_password",
            "mock_vehicle",
            "fake_peer",
        ):
            self.assertNotIn(forbidden, lowered)

    def _method_source(self, method_name: str) -> str:
        for node in ast.walk(self.tree):
            if isinstance(node, ast.FunctionDef) and node.name == method_name:
                return ast.get_source_segment(self.text, node) or ""
        self.fail(f"method not found: {method_name}")


if __name__ == "__main__":
    unittest.main()
