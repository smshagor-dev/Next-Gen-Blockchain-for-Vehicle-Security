import unittest
from pathlib import Path
from unittest.mock import patch

from dashboard import DashboardDataProvider, SmartCarDashboard, UNAVAILABLE
from smartcar_backend import BackendBlock, GoBackend


class DummyBackend:
    car_unlocked = False
    engine_started = False
    emergency_brake_active = False
    safe_mode_active = False
    chain = []

    def security_capabilities(self):
        return {
            "key_establishment": "ML-KEM/Kyber runtime metadata",
            "commitment_binding": "Pedersen - classical discrete-log assumption",
            "fallback_ecdh_p256": "disabled_by_default/classical",
        }

    def identity_security(self):
        return {
            "identity_authenticity": True,
            "sybil_resistance": False,
            "identity_admission_policy": "OPEN_REGISTRATION",
        }

    def consensus_security(self):
        return {"consensus_model": "simple_majority", "majority_attack_resistant": False}

    def pedersen_privacy(self):
        return {"pedersen_mode": "COMMIT_ONLY", "aggregate_statistics_recoverable": False}

    def fl_validation(self):
        return {"supports_byzantine_robustness_claim": False, "test_samples": 24}

    def adversarial_validation(self):
        return {"supports_general_detection_claim": False, "detection_rate_headline_allowed": False}

    def reviewer_audit(self):
        return {"general_100_percent_detection_claim": False}

    def complexity_boundary(self):
        return {"full_system_o_n_claim": False, "naive_full_mesh_network_volume": "O(n^2)"}

    def contribution_boundary(self):
        return {"claims_new_cryptographic_primitive": False}

    def v2x_peers(self):
        return [
            {"peer_id": "CAR_B", "relative_distance": 42.0, "relative_heading": 20.0, "speed": 31.0},
            {"peer_id": "CAR_C", "relative_distance": 75.0, "relative_heading": -15.0, "speed": 28.0},
        ]


class FailingBackend(DummyBackend):
    @property
    def car_unlocked(self):
        raise RuntimeError("lock module down")

    def security_capabilities(self):
        raise RuntimeError("security metadata down")


class DashboardRedesignTests(unittest.TestCase):
    def test_dashboard_data_provider_exists(self):
        self.assertTrue(callable(DashboardDataProvider))

    def test_no_hardcoded_telemetry_values(self):
        text = Path("dashboard.py").read_text(encoding="utf-8")
        for forbidden in ["4 km/h", "1030 RPM", "30.5 C", "99.6 %", "18.0 %"]:
            self.assertNotIn(forbidden, text)

    def test_missing_data_shows_unavailable_metadata(self):
        provider = DashboardDataProvider(DummyBackend(), "CAR_A")
        snapshot = provider.collect()
        telemetry = snapshot["vehicle_overview"]["telemetry"]
        self.assertEqual(telemetry["status"], "unavailable")
        self.assertEqual(telemetry["value"], {})

    def test_security_cards_use_real_metadata_provider_values(self):
        provider = DashboardDataProvider(DummyBackend(), "CAR_A")
        snapshot = provider.collect()
        caps = snapshot["security_capability"]["value"]
        self.assertEqual(caps["key_establishment"], "ML-KEM/Kyber runtime metadata")
        self.assertEqual(caps["fallback_ecdh_p256"], "disabled_by_default/classical")

    def test_road_scene_uses_v2x_peers(self):
        provider = DashboardDataProvider(DummyBackend(), "CAR_A")
        snapshot = provider.collect()
        peers = snapshot["v2x_peers"]["value"]
        self.assertEqual(len(peers), 2)
        self.assertEqual(peers[0]["peer_id"], "CAR_B")

    def test_road_scene_uses_object_detection_results(self):
        provider = DashboardDataProvider(DummyBackend(), "CAR_A")
        provider.set_object_detections([{"class": "pedestrian", "distance_m": 11.0}])
        snapshot = provider.collect()
        detections = snapshot["object_detection"]["value"]
        self.assertEqual(detections[0]["class"], "pedestrian")

    def test_no_random_vehicle_generation(self):
        text = Path("dashboard.py").read_text(encoding="utf-8")
        self.assertNotIn("import random", text)
        self.assertNotIn("random.", text)

    def test_no_random_radar_dots(self):
        text = Path("dashboard.py").read_text(encoding="utf-8").lower()
        self.assertNotIn("simulate nearby v2x", text)
        self.assertNotIn("random radar", text)

    def test_road_scene_does_not_invent_peer_positions_from_index(self):
        text = Path("dashboard.py").read_text(encoding="utf-8")
        self.assertNotIn("20 + idx", text)
        self.assertNotIn("idx %", text)

    def test_ego_vehicle_rendered_when_telemetry_exists(self):
        text = Path("dashboard.py").read_text(encoding="utf-8")
        self.assertIn("EGO", text)
        self.assertIn("_render_road_scene", text)

    def test_scrollable_layout_exists(self):
        text = Path("dashboard.py").read_text(encoding="utf-8")
        self.assertIn("main_canvas", text)
        self.assertIn("ttk.Scrollbar", text)

    def test_responsive_layout_exists(self):
        text = Path("dashboard.py").read_text(encoding="utf-8")
        self.assertIn("_apply_responsive_layout", text)
        self.assertIn("columns = 6", text)
        self.assertIn("columns = 1", text)

    def test_command_center_layout_panels_exist(self):
        text = Path("dashboard.py").read_text(encoding="utf-8")
        for required in [
            "Access Control",
            "Vehicle / Security Status",
            "Reviewer / Security Warnings",
            "Live Camera / Object Detection",
            "Road Scene",
            "Event Log / Telemetry Timeline",
            "Speed Meter",
            "V2X Radar",
            "Anomaly Detection",
            "System Health / Connection",
            "left_column",
            "center_column",
            "right_column",
        ]:
            self.assertIn(required, text)

    def test_access_controls_and_throttle_exist(self):
        text = Path("dashboard.py").read_text(encoding="utf-8")
        for required in ["AUTH", "START", "STOP", "LOCK", "RECOVER", "Force Chain Reset", "throttle_scale", "throttle_progress"]:
            self.assertIn(required, text)

    def test_visual_command_widgets_exist(self):
        text = Path("dashboard.py").read_text(encoding="utf-8")
        for required in ["road_canvas", "camera_label", "speed_canvas", "radar_canvas", "anomaly_canvas"]:
            self.assertIn(required, text)

    def test_manual_refresh_updates_in_place(self):
        text = Path("dashboard.py").read_text(encoding="utf-8")
        start = text.index("    def manual_refresh")
        end = text.index("    @staticmethod", start)
        body = text[start:end]
        self.assertNotIn("_build_ui", body)
        self.assertNotIn("destroy(", body)
        self.assertIn("yview_moveto", body)
        self.assertIn("_metadata_expanded", body)

    def test_collapsible_metadata_groups_exist(self):
        text = Path("dashboard.py").read_text(encoding="utf-8")
        for required in [
            "Hybrid Security",
            "Identity / Sybil Boundary",
            "Consensus Boundary",
            "FL / Adversarial Validation",
            "Reviewer Audit",
            "Complexity / Contribution",
            "_toggle_metadata",
        ]:
            self.assertIn(required, text)

    def test_dashboard_provider_survives_module_failures(self):
        provider = DashboardDataProvider(FailingBackend(), "CAR_A")
        snapshot = provider.collect()
        self.assertIn(snapshot["connection_status"]["value"], {"Partial", "Disconnected"})
        self.assertEqual(snapshot["security_capability"]["status"], "error")

    def test_backend_block_telemetry_binds_into_provider(self):
        backend = DummyBackend()
        backend.chain = [
            BackendBlock(
                index=1,
                timestamp="2026-06-06T00:00:00Z",
                vehicle_id="CAR_A",
                telemetry={"speed": 44.0, "rpm": 1200.0, "fuel_level": 81.0},
                event_data="TELEMETRY",
                block_hash="abc",
            )
        ]
        provider = DashboardDataProvider(backend, "CAR_A")
        telemetry = provider.collect()["vehicle_overview"]["telemetry"]
        self.assertEqual(telemetry["status"], "ok")
        self.assertEqual(telemetry["value"]["speed"], 44.0)

    def test_go_backend_retries_after_connection_reset(self):
        class FakeResponse:
            def __enter__(self):
                return self

            def __exit__(self, *_args):
                return False

            def read(self):
                return b'{"success": true}'

        backend = GoBackend.__new__(GoBackend)
        backend.base_url = "http://127.0.0.1:8787"
        backend._init_payload = {}
        recovered = []

        with patch.object(backend, "_recover_service", lambda: recovered.append(True)):
            with patch(
                "smartcar_backend.urllib.request.urlopen",
                side_effect=[ConnectionResetError(10054, "connection reset"), FakeResponse()],
            ):
                result = backend._request("POST", "/engine/start", {})

        self.assertEqual(result, {"success": True})
        self.assertEqual(len(recovered), 1)

    def test_action_error_hides_raw_winerror(self):
        message = SmartCarDashboard._action_error(ConnectionResetError(10054, "connection reset"))
        self.assertIn("Backend connection was interrupted", message)
        self.assertNotIn("WinError", message)


if __name__ == "__main__":
    unittest.main()
