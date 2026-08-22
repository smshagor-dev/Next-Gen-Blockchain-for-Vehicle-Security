import ast
import unittest
from pathlib import Path


class ProductionOverviewContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.path = Path("dashboard_production_ui.py")
        cls.text = cls.path.read_text(encoding="utf-8")
        cls.tree = ast.parse(cls.text)
        cls.main_text = Path("main.py").read_text(encoding="utf-8-sig")

    def test_main_launches_production_overview(self):
        self.assertIn("from dashboard_production_ui import SmartCarDashboard", self.main_text)

    def test_overview_is_fixed_without_canvas_or_scrollbar(self):
        self.assertIn('if key != "overview"', self.text)
        self.assertIn("Deliberately do not register a canvas/scrollbar for Overview", self.text)
        self.assertNotIn('self._page_canvases["overview"]', self.text)
        self.assertNotIn('ttk.Scrollbar(page', self._method_source("_build_overview_page"))
        self.assertNotIn('tk.Canvas(page', self._method_source("_build_overview_page"))

    def test_overview_defaults_are_explicitly_unavailable(self):
        overview = self._method_source("_build_overview_page")
        for key in ("connection", "vehicle", "speed", "peers", "ledger", "vision"):
            self.assertIn(f'("{key}",', overview)
        self.assertNotIn('"CHECK"', overview)
        self.assertNotIn('"0", "observed peers"', overview)
        self.assertNotIn('"0", "visible records"', overview)

    def test_missing_boolean_data_is_not_coerced_to_false(self):
        render = self._method_source("_render_live_overview")
        self.assertIn("engine_value, engine_ready = self._point_result(engine_point)", render)
        self.assertIn("safe_value, safe_ready = self._point_result(safe_point)", render)
        self.assertIn("vehicle_state = UNAVAILABLE", render)
        self.assertNotIn("bool(self._point_value", render)

    def test_overview_uses_provider_and_backend_sources(self):
        render = self._method_source("_render_live_overview")
        required = (
            'data.get("connection_status"',
            'data.get("vehicle_overview"',
            'data.get("v2x_peers"',
            'data.get("camera_status"',
            'data.get("object_detection"',
            'data.get("security_capability"',
            'data.get("identity_security"',
            'data.get("consensus_security"',
            'data.get("privacy_pedersen"',
            'data.get("fl_validation"',
            'data.get("reviewer_audit"',
            'getattr(self.blockchain, "chain", None)',
        )
        for marker in required:
            self.assertIn(marker, render)

    def test_no_synthetic_runtime_values_are_added(self):
        lowered = self.text.lower()
        for marker in ("random.uniform(", "random.randint(", "fake_peer", "fake_detection", "demo_telemetry"):
            self.assertNotIn(marker, lowered)
        self.assertIn("super()._render_snapshot(data)", self.text)

    def _method_source(self, method_name: str) -> str:
        for node in ast.walk(self.tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name == method_name:
                return ast.get_source_segment(self.text, node) or ""
        self.fail(f"method not found: {method_name}")


if __name__ == "__main__":
    unittest.main()
