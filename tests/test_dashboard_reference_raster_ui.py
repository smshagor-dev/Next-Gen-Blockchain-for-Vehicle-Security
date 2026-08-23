import ast
import base64
import io
import unittest
from pathlib import Path

from PIL import Image, ImageStat


class ReferenceRasterDashboardTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.module_path = Path("dashboard_reference_raster_ui.py")
        cls.module_text = cls.module_path.read_text(encoding="utf-8")
        cls.module_tree = ast.parse(cls.module_text)
        cls.main_text = Path("main.py").read_text(encoding="utf-8-sig")
        cls.asset_root = Path("assets/dashboard/reference")
        cls.compose_reference = staticmethod(cls._load_isolated_function("_compose_reference"))

    @classmethod
    def _load_isolated_function(cls, name: str):
        for node in cls.module_tree.body:
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name == name:
                isolated = ast.Module(body=[node], type_ignores=[])
                ast.fix_missing_locations(isolated)
                namespace = {}
                exec(compile(isolated, str(cls.module_path), "exec"), namespace)
                return namespace[name]
        raise AssertionError(f"function not found: {name}")

    def _decode(self, stem: str) -> Image.Image:
        parts = sorted(self.asset_root.glob(f"{stem}.png.b64.*"))
        self.assertTrue(parts, f"missing bundled PNG parts for {stem}")
        encoded = "".join(p.read_text(encoding="ascii").strip() for p in parts)
        raw = base64.b64decode(encoded, validate=True)
        self.assertTrue(raw.startswith(b"\x89PNG\r\n\x1a\n"))
        image = Image.open(io.BytesIO(raw))
        image.load()
        return image.convert("RGBA")

    def test_active_launcher_uses_reference_raster_layer(self):
        self.assertIn("from dashboard_reference_raster_ui import SmartCarDashboard", self.main_text)
        self.assertIn("class RasterReferenceDashboard(ExactReferencePanelsDashboard)", self.module_text)

    def test_vehicle_asset_is_exact_reference_crop_geometry(self):
        image = self._decode("vehicle-status-ref")
        self.assertEqual(image.size, (242, 242))
        self.assertIn('_VEHICLE_ASSET = "vehicle-status-ref"', self.module_text)

    def test_network_asset_is_exact_reference_crop_geometry(self):
        image = self._decode("network-status-ref")
        self.assertEqual(image.size, (242, 145))
        self.assertIn('_NETWORK_ASSET = "network-status-ref"', self.module_text)

    def test_reference_composition_fills_wide_canvases_without_black_bars(self):
        vehicle = self.compose_reference(self._decode("vehicle-status-ref"), 520, 310)
        network = self.compose_reference(
            self._decode("network-status-ref"),
            520,
            220,
            foreground_brightness=1.72,
            foreground_contrast=1.28,
            foreground_sharpness=1.40,
        )
        self.assertEqual(vehicle.size, (520, 310))
        self.assertEqual(network.size, (520, 220))
        for image in (vehicle, network):
            rgb = image.convert("RGB")
            stat = ImageStat.Stat(rgb)
            self.assertGreater(sum(stat.mean), 8.0)
            self.assertGreater(sum(stat.var), 20.0)

    def test_network_view_is_always_rendered_even_with_zero_peers(self):
        self.assertIn("Always render the supplied world-map background, even with zero peers", self.module_text)
        self.assertIn("No observed V2X peers", self.module_text)
        self.assertIn("foreground_brightness=1.72", self.module_text)

    def test_vehicle_has_live_three_state_risk_badge(self):
        for marker in ('"protected": "#24d18b"', '"warning": "#f6c343"', '"risk": "#ff5c6c"'):
            self.assertIn(marker, self.module_text)
        for label in ("PROTECTED", "WARNING", "RISK"):
            self.assertIn(label, self.module_text)
        self.assertIn("_derive_vehicle_risk_state", self.module_text)

    def test_assets_are_local_and_runtime_does_not_download_or_generate_images(self):
        lowered = self.module_text.lower()
        self.assertNotIn("http://", lowered)
        self.assertNotIn("https://", lowered)
        self.assertNotIn("requests.", lowered)
        self.assertNotIn("urllib", lowered)
        self.assertIn("base64.b64decode", self.module_text)
        self.assertIn("ImageOps.fit", self.module_text)
        self.assertIn("ImageOps.contain", self.module_text)

    def test_reference_demo_metrics_are_not_injected(self):
        for forbidden in ('"156 ms"', '"99.9%"', '"1,256"'):
            self.assertNotIn(forbidden, self.module_text)
        self.assertIn("ExactReferencePanelsDashboard", self.module_text)


if __name__ == "__main__":
    unittest.main()
