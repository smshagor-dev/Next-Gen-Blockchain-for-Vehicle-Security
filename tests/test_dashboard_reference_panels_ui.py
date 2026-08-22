import ast
import unittest
from pathlib import Path


class ExactReferencePanelContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.path = Path('dashboard_reference_panels_ui.py')
        cls.text = cls.path.read_text(encoding='utf-8')
        cls.tree = ast.parse(cls.text)
        cls.main_text = Path('main.py').read_text(encoding='utf-8-sig')

    def test_active_shell_is_exact_reference_panels(self):
        self.assertIn('from dashboard_reference_panels_ui import SmartCarDashboard', self.main_text)
        self.assertIn('class ExactReferencePanelsDashboard(StableLiveSmartCarDashboard)', self.text)

    def test_vehicle_reference_art_contract(self):
        source = self._method('_draw_vehicle_art')
        for marker in ('faint shield', 'Holographic blue base/glow', 'Three-quarter front sports-car body', 'Wheels: large, dark'):
            self.assertIn(marker, source)
        self.assertIn('Image.Resampling.LANCZOS', source)
        self.assertNotIn('random', source.lower())

    def test_network_reference_contract(self):
        install = self._method('_install_reference_network_metrics')
        draw = self._method('_draw_peer_map')
        for label in ('Active Nodes', 'Avg. Latency', 'Uptime', 'Block Height'):
            self.assertIn(label, install)
        self.assertIn('Dotted world silhouette', draw)
        self.assertIn('decorative map context only', draw)
        self.assertIn('relative_distance', draw)
        self.assertIn('relative_heading', draw)

    def test_network_metrics_never_fabricate_latency_or_uptime(self):
        render = self._method('_render_snapshot')
        self.assertIn('latency is not None else "—"', render)
        self.assertIn('uptime is not None else "—"', render)
        self.assertNotIn('156', self.text)
        self.assertNotIn('99.9', self.text)
        self.assertNotIn('1256', self.text)

    def _method(self, name):
        for node in ast.walk(self.tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name == name:
                return ast.get_source_segment(self.text, node) or ''
        self.fail(f'method not found: {name}')


if __name__ == '__main__':
    unittest.main()
