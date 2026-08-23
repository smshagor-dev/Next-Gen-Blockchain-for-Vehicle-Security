import base64
import io
import unittest
from pathlib import Path

from PIL import Image


class ReferenceRasterDashboardTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.module_path = Path("dashboard_reference_raster_ui.py")
        cls.module_text = cls.module_path.read_text(encoding="utf-8")
        cls.main_text = Path("main.py").read_text(encoding="utf-8-sig")
        cls.asset_root = Path("assets/dashboard/reference")

    def _decode(self, stem: str) -> Image.Image:
        parts = sorted(self.asset_root.glob(f"{stem}.png.b64.*"))
        self.assertTrue(parts, f"missing bundled PNG parts for {stem}")
        encoded = "".join(p.read_text(encoding="ascii").strip() for p in parts)
        raw = base64.b64decode(encoded, validate=True)
        self.assertTrue(raw.startswith(b"\x89PNG\r\n\x1a\n"))
        image = Image.open(io.BytesIO(raw))
        image.load()
        return image

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

    def test_assets_are_local_and_runtime_does_not_generate_or_download_images(self):
        lowered = self.module_text.lower()
        self.assertNotIn("http://", lowered)
        self.assertNotIn("https://", lowered)
        self.assertNotIn("requests.", lowered)
        self.assertNotIn("urllib", lowered)
        self.assertIn("base64.b64decode", self.module_text)
        self.assertIn("ImageOps.contain", self.module_text)

    def test_reference_demo_metrics_are_not_injected(self):
        for forbidden in ('"156 ms"', '"99.9%"', '"1,256"'):
            self.assertNotIn(forbidden, self.module_text)
        self.assertIn("ExactReferencePanelsDashboard", self.module_text)


if __name__ == "__main__":
    unittest.main()
