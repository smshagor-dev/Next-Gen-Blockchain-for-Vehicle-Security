import ast
import unittest
from pathlib import Path


class PixelMatchedDashboardContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.path = Path("dashboard_pixel_ui.py")
        cls.text = cls.path.read_text(encoding="utf-8")
        cls.tree = ast.parse(cls.text)
        cls.main_text = Path("main.py").read_text(encoding="utf-8-sig")
        cls.reference_text = Path("dashboard_reference_ui.py").read_text(encoding="utf-8")

    def test_main_launches_pixel_matched_shell(self):
        self.assertIn("from dashboard_pixel_ui import SmartCarDashboard", self.main_text)

    def test_shell_inherits_complete_working_reference_navigation(self):
        self.assertIn("class PixelMatchedSmartCarDashboard(ReferenceSmartCarDashboard)", self.text)
        for title in (
            "Dashboard",
            "Vehicles",
            "Transactions",
            "Access Control",
            "Ownership",
            "Audit Logs",
            "Threat Detection",
            "Alerts",
            "Security Scan",
            "Smart Contract",
            "Nodes",
            "Settings",
        ):
            self.assertIn(title, self.reference_text)
        self.assertIn("command=lambda p=key: self._show_reference_page(p)", self.text)
        self.assertIn("page.tkraise()", self.text)

    def test_overview_matches_reference_information_hierarchy(self):
        for marker in (
            "Welcome back,",
            "Secure. Transparent. Decentralized.",
            "Blockchain Network",
            "Total Vehicles",
            "Total Transactions",
            "Active Nodes",
            "Security Score",
            "Vehicle Status Overview",
            "Recent Blockchain Activity",
            "Network Status",
            "Security Alerts",
            "Transaction Overview",
            "Built with ♥ using Blockchain Technology for a Secure Future",
        ):
            self.assertIn(marker, self.text)

    def test_reference_sample_kpis_are_not_display_literals(self):
        # Geometry values may coincidentally use the same digits, so only quoted
        # display literals from the supplied screenshot are forbidden.
        for forbidden in (
            '"128"',
            '"1,256"',
            '"98.6%"',
            '"+18.7%"',
            '"156 ms"',
            '"3.2s"',
        ):
            self.assertNotIn(forbidden, self.text)

    def test_pixel_shell_stays_source_backed(self):
        render = self._method_source("_render_snapshot")
        self.assertIn("super()._render_snapshot(data)", render)
        self.assertIn('data.get("connection_status"', render)
        self.assertIn('data.get("vehicle_overview"', render)
        self.assertIn('data.get("v2x_peers"', render)
        self.assertIn('getattr(self.blockchain, "chain", None)', render)
        self.assertNotIn("random.", self.text.lower())
        self.assertNotIn("mock_vehicle", self.text.lower())
        self.assertNotIn("fake_peer", self.text.lower())

    def test_vehicle_art_is_code_drawn_multi_layer_sports_car(self):
        method = self._method_source("_draw_vehicle_art")
        for marker in (
            "Shield background",
            "Holographic platform rings",
            "Main body silhouette",
            "Roof / windshield cabin",
            "Front grille/headlamp details",
            "Wheels, rims, brake accents",
            "canvas.create_polygon",
            "canvas.create_oval",
            "canvas.create_line",
        ):
            self.assertIn(marker, method)
        self.assertNotIn("PhotoImage", method)

    def test_network_map_does_not_claim_fake_geography(self):
        method = self._method_source("_draw_peer_map")
        self.assertIn("Decorative world topology background", method)
        self.assertIn("relative topology • not geographic", method)
        self.assertIn("relative_distance", method)
        self.assertIn("relative_heading", method)
        self.assertNotIn("random", method.lower())

    def test_single_record_chart_is_truthful(self):
        method = self._method_source("_draw_transaction_chart")
        self.assertIn("if len(chain) == 1", method)
        self.assertIn("Insufficient history for trend", method)
        self.assertNotIn("demo", method.lower())

    def test_activity_slots_do_not_invent_events(self):
        method = self._method_source("_render_activity_feed")
        self.assertIn("No additional ledger activity", method)
        self.assertIn("self._block_fields(block)", method)
        self.assertNotIn("Ownership Transfer", method)
        self.assertNotIn("Access Granted", method)

    def test_runtime_credentials_are_not_added_to_pixel_shell(self):
        lowered = self.text.lower()
        self.assertNotIn("smartcar_auth_token", lowered)
        self.assertNotIn("smartcar_password", lowered)
        self.assertNotIn("self.auth_token", lowered)
        self.assertNotIn("self.password", lowered)

    def _method_source(self, method_name: str) -> str:
        for node in ast.walk(self.tree):
            if isinstance(node, ast.FunctionDef) and node.name == method_name:
                return ast.get_source_segment(self.text, node) or ""
        self.fail(f"method not found: {method_name}")


if __name__ == "__main__":
    unittest.main()
