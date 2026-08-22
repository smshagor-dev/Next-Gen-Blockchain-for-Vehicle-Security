import ast
import unittest
from pathlib import Path


class ProductionDashboardNavigationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.path = Path("dashboard_modern_ui.py")
        cls.text = cls.path.read_text(encoding="utf-8")
        cls.tree = ast.parse(cls.text)

    def test_sidebar_routes_have_real_pages(self):
        expected = {
            "overview",
            "vehicle",
            "security",
            "network",
            "vision",
            "events",
            "research",
            "settings",
        }
        self.assertIn("PAGE_DEFINITIONS", self.text)
        for key in expected:
            self.assertIn(f'("{key}",', self.text)
            self.assertIn(f'self._page_contents["{key}"]', self.text)

    def test_sidebar_buttons_navigate_to_page_controller(self):
        self.assertIn("command=lambda p=key: self._show_page(p)", self.text)
        self.assertIn("self._pages[key].tkraise()", self.text)
        self.assertIn("self._active_page = key", self.text)
        self.assertIn("self.page_title_label.configure(text=title)", self.text)
        self.assertIn("self.page_subtitle_label.configure(text=subtitle)", self.text)

    def test_runtime_render_targets_are_preserved(self):
        required = (
            'self._create_panel(left, "vehicle"',
            'self._create_panel(right, "access"',
            'self._create_panel(lower, "speed"',
            'self._create_panel(lower, "road"',
            'self._create_panel(row, "anomaly"',
            'self._create_panel(row, "warnings"',
            'self._create_panel(row, "radar"',
            'self._create_panel(row, "health"',
            'self._create_panel(page, "camera"',
            'self._create_panel(page, "timeline"',
        )
        for marker in required:
            self.assertIn(marker, self.text)

    def test_dashboard_does_not_replace_backend_with_demo_data(self):
        forbidden = (
            "random.uniform(",
            "random.randint(",
            "fake_peer",
            "fake_detection",
            "demo_telemetry",
        )
        lowered = self.text.lower()
        for marker in forbidden:
            self.assertNotIn(marker, lowered)
        self.assertIn("super()._render_snapshot(data)", self.text)
        self.assertIn("self.provider.collect()", self.text)


if __name__ == "__main__":
    unittest.main()
