import ast
import unittest
from pathlib import Path


class LiveSocketDashboardContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.ui_path = Path("dashboard_live_ui.py")
        cls.ui_text = cls.ui_path.read_text(encoding="utf-8")
        cls.ui_tree = ast.parse(cls.ui_text)
        cls.art_text = Path("dashboard_vehicle_art.py").read_text(encoding="utf-8")
        cls.go_live_text = Path("api/go/live_stream.go").read_text(encoding="utf-8")
        cls.main_text = Path("main.py").read_text(encoding="utf-8-sig")

    def test_main_launches_live_socket_shell(self):
        self.assertIn("from dashboard_live_ui import SmartCarDashboard", self.main_text)

    def test_live_shell_inherits_full_pixel_navigation(self):
        self.assertIn("class LiveSocketSmartCarDashboard(pixel.PixelMatchedSmartCarDashboard)", self.ui_text)
        self.assertIn("SmartCarDashboard = LiveSocketSmartCarDashboard", self.ui_text)

    def test_go_backend_exposes_authenticated_loopback_live_socket(self):
        self.assertIn('defaultLiveStreamAddr = "127.0.0.1:8788"', self.go_live_text)
        self.assertIn('liveProtocolLabel     = "smartcar-live-v1"', self.go_live_text)
        self.assertIn("validateLiveStreamAddr", self.go_live_text)
        self.assertIn("liveProof", self.go_live_text)
        self.assertIn("hmac.Equal", self.go_live_text)
        self.assertIn("isLoopbackRemote", self.go_live_text)
        self.assertIn("SMARTCAR_GO_ENABLE_LIVE_STREAM", self.go_live_text)

    def test_dashboard_connects_to_go_live_socket_not_local_socketpair(self):
        self.assertIn("socket.create_connection", self.ui_text)
        self.assertIn("SmartCarDashboardGoLiveSocket", self.ui_text)
        self.assertIn("_connect_live_socket", self.ui_text)
        self.assertIn("_recv_json_line", self.ui_text)
        self.assertIn("_apply_live_status", self.ui_text)
        self.assertNotIn("socket.socketpair()", self.ui_text)

    def test_live_handshake_uses_same_secret_without_exposing_it(self):
        method = self._method_source("_connect_live_socket")
        self.assertIn("api_secret", method)
        self.assertIn("hmac.new", method)
        self.assertIn("hashlib.sha256", method)
        self.assertIn('"type": "auth"', method)
        self.assertNotIn("print(", method)

    def test_ui_loop_is_push_first_and_http_refresh_is_fallback_only(self):
        method = self._method_source("_update_ui")
        self.assertIn("_drain_live_queue", method)
        self.assertIn("not self._live_socket_connected", method)
        self.assertIn("FALLBACK_COLLECT_INTERVAL_SEC", method)
        self.assertNotIn("self.manual_refresh()", method)

    def test_active_shell_removes_manual_refresh_controls(self):
        method = self._method_source("_strip_manual_refresh_controls")
        self.assertIn('text == "Refresh Now"', method)
        self.assertIn("child.destroy()", method)
        self.assertIn('text == "Refresh Interval"', method)
        self.assertIn('text="Live Update"', method)

    def test_cached_provider_avoids_requerying_metadata_during_live_frames(self):
        method = self._method_source("_metadata", class_name="LiveDashboardDataProvider")
        self.assertIn("backend.live_cache", method)
        self.assertIn("_CACHE_ATTRS", method)
        self.assertIn("super()._metadata(method_name)", method)

    def test_socket_status_uses_existing_ledger_verifier(self):
        method = self._method_source("_apply_live_status")
        self.assertIn("_ledger_verifier", method)
        self.assertIn("verify_and_track", method)
        self.assertIn("BackendBlock", method)
        self.assertIn("_security_capabilities", method)

    def test_vehicle_art_is_antialiased_pillow_renderer(self):
        self.assertIn("Image.Resampling.LANCZOS", self.art_text)
        self.assertIn("ImageFilter.GaussianBlur", self.art_text)
        self.assertIn("Metallic vertical gradient", self.art_text)
        self.assertIn("Wheels with layered rims and red brake calipers", self.art_text)
        method = self._method_source("_draw_vehicle_art")
        self.assertIn("render_vehicle_hero", method)
        self.assertIn("ImageTk.PhotoImage", method)
        self.assertIn("self._vehicle_photo_key", method)

    def test_vehicle_art_renders_headlessly(self):
        from dashboard_vehicle_art import render_vehicle_hero

        image = render_vehicle_hero(640, 360)
        self.assertEqual(image.size, (640, 360))
        self.assertEqual(image.mode, "RGBA")

    def test_live_shell_does_not_add_fake_reference_values_or_credentials(self):
        lowered = self.ui_text.lower() + self.art_text.lower()
        for forbidden in (
            '"128"',
            '"1,256"',
            '"98.6%"',
            '"+18.7%"',
            "smartcar_auth_token",
            "smartcar_password",
        ):
            self.assertNotIn(forbidden.lower(), lowered)

    def test_backend_actions_are_serialized_against_live_updates(self):
        for method_name in ("_do_auth", "_do_start", "_do_stop", "_do_lock", "_do_recover"):
            method = self._method_source(method_name)
            self.assertIn("self._live_action_lock", method)
            self.assertIn("super().", method)

    def test_shutdown_stops_socket_worker(self):
        method = self._method_source("on_closing")
        self.assertIn("self._live_stop.set()", method)
        self.assertIn("conn.shutdown", method)
        self.assertIn("thread.join", method)
        self.assertIn("super().on_closing()", method)

    def _method_source(self, method_name: str, class_name: str | None = None) -> str:
        for node in ast.walk(self.ui_tree):
            if not isinstance(node, ast.ClassDef):
                continue
            if class_name is not None and node.name != class_name:
                continue
            for item in node.body:
                if isinstance(item, ast.FunctionDef) and item.name == method_name:
                    return ast.get_source_segment(self.ui_text, item) or ""
        self.fail(f"method not found: {method_name}")


if __name__ == "__main__":
    unittest.main()
