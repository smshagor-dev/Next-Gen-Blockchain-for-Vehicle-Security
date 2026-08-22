"""Production OmniGuard V2X dashboard composition.

This layer keeps the routed modern console while making Overview a fixed,
single-screen operational picture backed only by provider/backend data.
Missing data is never converted into a synthetic healthy/false/zero state.
"""

import tkinter as tk
from typing import Any, Dict, Iterable, Optional, Tuple

from dashboard_modern_ui import (
    BLUE,
    CARD_DEEP,
    C,
    NO_DATA,
    NOT_CONNECTED,
    SURFACE_ALT,
    TEAL,
    UNAVAILABLE,
    ModernSmartCarDashboard,
)


class ProductionSmartCarDashboard(ModernSmartCarDashboard):
    """Modern routed console with a no-scroll, real-data-only Overview page."""

    def _create_scroll_page(self, key: str):
        if key != "overview":
            return super()._create_scroll_page(key)

        page = tk.Frame(self.page_host, bg=C["bg"])
        page.grid(row=0, column=0, sticky="nsew")
        content = tk.Frame(page, bg=C["bg"], padx=16, pady=12)
        content.pack(fill="both", expand=True)
        self._pages[key] = page
        self._page_contents[key] = content
        # Deliberately do not register a canvas/scrollbar for Overview.
        # The complete operational picture must stay inside one viewport.

    @staticmethod
    def _point_result(point: Any) -> Tuple[Any, bool]:
        if not isinstance(point, dict):
            return None, False
        if point.get("status") in {"error", "unavailable"}:
            return point.get("value"), False
        if "value" not in point:
            return None, False
        return point.get("value"), True

    @staticmethod
    def _point_source(point: Any) -> str:
        if not isinstance(point, dict):
            return "source unavailable"
        return str(point.get("source") or "source unavailable")

    @classmethod
    def _real_bool(cls, point: Any, true_text: str, false_text: str) -> str:
        value, ready = cls._point_result(point)
        if not ready or not isinstance(value, bool):
            return UNAVAILABLE
        return true_text if value else false_text

    @staticmethod
    def _chain_rows(chain: Any) -> Optional[list]:
        if isinstance(chain, (list, tuple)):
            return list(chain)
        return None

    def _build_overview_page(self):
        page = self._page_contents["overview"]
        for column in range(12):
            page.grid_columnconfigure(column, weight=1, uniform="overview")
        page.grid_rowconfigure(2, weight=3)
        page.grid_rowconfigure(3, weight=2)

        heading = tk.Frame(page, bg=C["bg"])
        heading.grid(row=0, column=0, columnspan=12, sticky="ew", pady=(0, 8))
        tk.Label(
            heading,
            text="Live Operations Overview",
            bg=C["bg"],
            fg=C["text"],
            font=self.f_page_title,
        ).pack(side="left")
        tk.Label(
            heading,
            text="Provider/backend data only • no simulated values • no scrolling",
            bg=C["bg"],
            fg=C["dim"],
            font=self.f_small,
        ).pack(side="right")

        metrics = tk.Frame(page, bg=C["bg"])
        metrics.grid(row=1, column=0, columnspan=12, sticky="ew", pady=(0, 10))
        self._overview_metrics: Dict[str, Dict[str, tk.Label]] = {}
        specs = (
            ("connection", "Runtime", UNAVAILABLE, "provider connection", TEAL),
            ("vehicle", "Vehicle State", UNAVAILABLE, "engine / safe mode", BLUE),
            ("speed", "Speed", UNAVAILABLE, "live telemetry", C["green"]),
            ("peers", "V2X Peers", UNAVAILABLE, "observed peers", C["purple"]),
            ("ledger", "Ledger", UNAVAILABLE, "visible records", C["orange"]),
            ("vision", "Vision", UNAVAILABLE, "camera / detections", C["yellow"]),
        )
        for idx, (key, title, value, note, accent) in enumerate(specs):
            metrics.grid_columnconfigure(idx, weight=1, uniform="overview-metric")
            card = self._metric_card(metrics, title, value, note, accent)
            card["outer"].grid(row=0, column=idx, sticky="nsew", padx=(0 if idx == 0 else 4, 0 if idx == len(specs) - 1 else 4))
            self._overview_metrics[key] = card

        vehicle_panel = self._create_panel(page, "overview_vehicle_live", "Vehicle Telemetry", 260)
        vehicle_panel["outer"].grid(row=2, column=0, columnspan=5, sticky="nsew", padx=(0, 5), pady=(0, 10))
        self._overview_vehicle_labels: Dict[str, tk.Label] = {}
        for key, title in (
            ("vehicle_id", "Vehicle ID"),
            ("access", "Lock / Access"),
            ("engine", "Engine"),
            ("safe_mode", "Safe Mode"),
            ("emergency", "Emergency Brake"),
            ("speed", "Speed"),
            ("rpm", "RPM"),
            ("fuel", "Fuel"),
            ("temperature", "Temperature"),
            ("throttle", "Throttle"),
        ):
            self._overview_vehicle_labels[key] = self._info_row(vehicle_panel["body"], title)

        network_panel = self._create_panel(page, "overview_network_live", "V2X & Vision", 260)
        network_panel["outer"].grid(row=2, column=5, columnspan=3, sticky="nsew", padx=5, pady=(0, 10))
        self._overview_network_labels: Dict[str, tk.Label] = {}
        for key, title in (
            ("peer_status", "Peer Source"),
            ("peer_count", "Observed Peers"),
            ("nearest_peer", "Nearest Peer"),
            ("camera", "Camera"),
            ("detections", "Detections"),
            ("latest_detection", "Latest Detection"),
        ):
            self._overview_network_labels[key] = self._info_row(network_panel["body"], title)

        security_panel = self._create_panel(page, "overview_security_live", "Security Metadata", 260)
        security_panel["outer"].grid(row=2, column=8, columnspan=4, sticky="nsew", padx=(5, 0), pady=(0, 10))
        self._overview_security_labels: Dict[str, tk.Label] = {}
        for key, title in (
            ("key_establishment", "Key Establishment"),
            ("identity", "Identity"),
            ("consensus", "Consensus"),
            ("privacy", "Privacy Mode"),
            ("fl", "FL Validation"),
            ("reviewer", "Paper Claim Status"),
        ):
            self._overview_security_labels[key] = self._info_row(security_panel["body"], title)

        ledger_panel = self._create_panel(page, "overview_ledger_live", "Latest Ledger Activity", 190)
        ledger_panel["outer"].grid(row=3, column=0, columnspan=7, sticky="nsew", padx=(0, 5))
        self.overview_ledger_text = tk.Text(
            ledger_panel["body"],
            height=6,
            bg=CARD_DEEP,
            fg=C["text"],
            insertbackground=BLUE,
            relief="flat",
            bd=0,
            font=self.f_mono,
            wrap="none",
            padx=9,
            pady=7,
        )
        self.overview_ledger_text.pack(fill="both", expand=True)
        self.overview_ledger_text.configure(state="disabled")

        source_panel = self._create_panel(page, "overview_sources_live", "Runtime Sources", 190)
        source_panel["outer"].grid(row=3, column=7, columnspan=5, sticky="nsew", padx=(5, 0))
        self._overview_source_labels: Dict[str, tk.Label] = {}
        for key, title in (
            ("backend", "Backend"),
            ("connection", "Connection Source"),
            ("telemetry", "Telemetry Source"),
            ("peers", "Peer Source"),
            ("camera", "Camera Source"),
            ("updated", "Snapshot Updated"),
        ):
            self._overview_source_labels[key] = self._info_row(source_panel["body"], title)

        # Compatibility targets used by the inherited modern renderer. The final
        # values are overwritten below by _render_live_overview with strict
        # unavailable-vs-false semantics.
        self.overview_state = self._overview_metrics["vehicle"]["value"]
        self.overview_summary = tk.Label(page, text="", bg=C["bg"], fg=C["dim"])

    def _set_overview_label(self, group: Dict[str, tk.Label], key: str, value: Any, ready: bool = True):
        label = group.get(key)
        if label is None:
            return
        label.configure(text=self._display(value) if ready else UNAVAILABLE, fg=C["text"] if ready else C["orange"])

    def _nearest_peer_text(self, peers: Iterable[Any]) -> str:
        candidates = []
        for peer in peers:
            if not isinstance(peer, dict):
                continue
            distance = self._as_float(self._first_value(peer, ("relative_distance", "distance", "distance_m"), None))
            if distance is None:
                continue
            peer_id = peer.get("peer_id", peer.get("id", "peer"))
            candidates.append((distance, peer_id))
        if not candidates:
            return UNAVAILABLE
        distance, peer_id = min(candidates, key=lambda item: item[0])
        return f"{peer_id} • {distance:.1f} m"

    def _latest_detection_text(self, detections: Iterable[Any]) -> str:
        for detection in reversed(list(detections)):
            if not isinstance(detection, dict):
                continue
            cls = detection.get("class", detection.get("object_class", "object"))
            distance = self._as_float(detection.get("distance_m"))
            return f"{cls} • {distance:.1f} m" if distance is not None else str(cls)
        return NO_DATA

    def _render_overview_ledger(self, chain_rows: Optional[list]):
        lines = []
        if chain_rows is not None:
            for block in chain_rows[-5:]:
                index = getattr(block, "index", UNAVAILABLE)
                timestamp = getattr(block, "timestamp", UNAVAILABLE)
                event = getattr(block, "event_data", "")
                if isinstance(block, dict):
                    index = block.get("index", UNAVAILABLE)
                    timestamp = block.get("timestamp", UNAVAILABLE)
                    event = block.get("event_data", block.get("event", ""))
                lines.append(f"[{self._display(index)}] {str(timestamp)}  {event or 'event unavailable'}")
        self.overview_ledger_text.configure(state="normal")
        self.overview_ledger_text.delete("1.0", "end")
        self.overview_ledger_text.insert("end", "\n".join(lines) if lines else NO_DATA)
        self.overview_ledger_text.configure(state="disabled")
        self._set_badge("overview_ledger_live", "ok" if lines else "no_data")

    def _render_live_overview(self, data: Dict[str, Any]):
        connection_point = data.get("connection_status", {})
        connection, connection_ready = self._point_result(connection_point)
        connection_text = str(connection) if connection_ready else NOT_CONNECTED
        connection_color = C["green"] if connection_text == "Connected" else C["yellow"] if connection_text == "Partial" else C["red"]
        self._overview_metrics["connection"]["value"].configure(text=connection_text, fg=connection_color)
        self._overview_metrics["connection"]["note"].configure(text=self._point_source(connection_point))

        vehicle = data.get("vehicle_overview", {})
        engine_point = vehicle.get("engine_status", {})
        lock_point = vehicle.get("lock_status", {})
        safe_point = vehicle.get("safe_mode", {})
        emergency_point = vehicle.get("emergency_status", {})
        telemetry_point = vehicle.get("telemetry", {})
        telemetry_value, telemetry_ready = self._point_result(telemetry_point)
        telemetry = telemetry_value if telemetry_ready and isinstance(telemetry_value, dict) else {}

        engine_value, engine_ready = self._point_result(engine_point)
        safe_value, safe_ready = self._point_result(safe_point)
        if safe_ready and isinstance(safe_value, bool) and safe_value:
            vehicle_state = "SAFE MODE"
            vehicle_color = C["orange"]
        elif engine_ready and isinstance(engine_value, bool):
            vehicle_state = "ENGINE ON" if engine_value else "ENGINE OFF"
            vehicle_color = C["green"] if engine_value else C["text"]
        else:
            vehicle_state = UNAVAILABLE
            vehicle_color = C["orange"]
        self._overview_metrics["vehicle"]["value"].configure(text=vehicle_state, fg=vehicle_color)
        self._overview_metrics["vehicle"]["note"].configure(text=self._point_source(engine_point))

        speed = self._as_float(self._first_value(telemetry, ("speed", "speed_kmh"), None)) if telemetry_ready else None
        self._overview_metrics["speed"]["value"].configure(
            text=f"{speed:.1f} km/h" if speed is not None else UNAVAILABLE,
            fg=C["text"] if speed is not None else C["orange"],
        )
        self._overview_metrics["speed"]["note"].configure(text=self._point_source(telemetry_point))

        peers_point = data.get("v2x_peers", {})
        peers_value, peers_ready = self._point_result(peers_point)
        peers = peers_value if peers_ready and isinstance(peers_value, list) else []
        peer_count_text = str(len(peers)) if peers_ready else UNAVAILABLE
        self._overview_metrics["peers"]["value"].configure(text=peer_count_text, fg=C["text"] if peers_ready else C["orange"])
        self._overview_metrics["peers"]["note"].configure(text=self._point_source(peers_point))

        chain_rows = self._chain_rows(getattr(self.blockchain, "chain", None))
        chain_ready = chain_rows is not None
        ledger_text = str(len(chain_rows)) if chain_ready else UNAVAILABLE
        self._overview_metrics["ledger"]["value"].configure(text=ledger_text, fg=C["text"] if chain_ready else C["orange"])
        self._overview_metrics["ledger"]["note"].configure(text="backend.chain" if chain_ready else "chain unavailable")

        camera_point = data.get("camera_status", {})
        camera_value = camera_point.get("value") if isinstance(camera_point, dict) else None
        camera_connected = bool(camera_value.get("connected")) if isinstance(camera_value, dict) else False
        detection_point = data.get("object_detection", {})
        detections_value, detections_ready = self._point_result(detection_point)
        detections = detections_value if detections_ready and isinstance(detections_value, list) else []
        if camera_connected:
            vision_text = f"LIVE • {len(detections)}"
            vision_color = C["green"]
        elif isinstance(camera_value, dict):
            vision_text = "NOT CONNECTED"
            vision_color = C["orange"]
        else:
            vision_text = UNAVAILABLE
            vision_color = C["orange"]
        self._overview_metrics["vision"]["value"].configure(text=vision_text, fg=vision_color)
        self._overview_metrics["vision"]["note"].configure(text=self._point_source(camera_point))

        vehicle_id, vehicle_id_ready = self._point_result(vehicle.get("vehicle_id", {}))
        self._set_overview_label(self._overview_vehicle_labels, "vehicle_id", vehicle_id, vehicle_id_ready)
        self._set_overview_label(self._overview_vehicle_labels, "access", self._real_bool(lock_point, "Unlocked", "Locked"), self._real_bool(lock_point, "Unlocked", "Locked") != UNAVAILABLE)
        self._set_overview_label(self._overview_vehicle_labels, "engine", self._real_bool(engine_point, "Running", "Stopped"), self._real_bool(engine_point, "Running", "Stopped") != UNAVAILABLE)
        self._set_overview_label(self._overview_vehicle_labels, "safe_mode", self._real_bool(safe_point, "Active", "Inactive"), self._real_bool(safe_point, "Active", "Inactive") != UNAVAILABLE)
        self._set_overview_label(self._overview_vehicle_labels, "emergency", self._real_bool(emergency_point, "Active", "Inactive"), self._real_bool(emergency_point, "Active", "Inactive") != UNAVAILABLE)

        telemetry_fields = {
            "speed": (("speed", "speed_kmh"), " km/h"),
            "rpm": (("rpm",), " rpm"),
            "fuel": (("fuel_level",), " %"),
            "temperature": (("engine_temp", "temperature"), " °C"),
            "throttle": (("throttle_position", "throttle", "throttle_pos"), " %"),
        }
        for key, (names, suffix) in telemetry_fields.items():
            value = self._first_value(telemetry, names, None) if telemetry_ready else None
            numeric = self._as_float(value)
            if numeric is not None:
                self._set_overview_label(self._overview_vehicle_labels, key, f"{numeric:.1f}{suffix}", True)
            elif value is not None:
                self._set_overview_label(self._overview_vehicle_labels, key, value, True)
            else:
                self._set_overview_label(self._overview_vehicle_labels, key, UNAVAILABLE, False)
        self._set_badge("overview_vehicle_live", telemetry_point.get("status", "unavailable") if isinstance(telemetry_point, dict) else "unavailable")

        self._set_overview_label(self._overview_network_labels, "peer_status", peers_point.get("status", UNAVAILABLE) if isinstance(peers_point, dict) else UNAVAILABLE, isinstance(peers_point, dict))
        self._set_overview_label(self._overview_network_labels, "peer_count", len(peers), peers_ready)
        nearest = self._nearest_peer_text(peers) if peers_ready else UNAVAILABLE
        self._set_overview_label(self._overview_network_labels, "nearest_peer", nearest, nearest != UNAVAILABLE)
        self._set_overview_label(self._overview_network_labels, "camera", "Connected" if camera_connected else "Not Connected", isinstance(camera_value, dict))
        self._set_overview_label(self._overview_network_labels, "detections", len(detections), detections_ready)
        latest_detection = self._latest_detection_text(detections) if detections_ready else UNAVAILABLE
        self._set_overview_label(self._overview_network_labels, "latest_detection", latest_detection, latest_detection != UNAVAILABLE)
        self._set_badge("overview_network_live", "ok" if camera_connected or peers_ready else "unavailable")

        security_points = {
            "caps": data.get("security_capability", {}),
            "identity": data.get("identity_security", {}),
            "consensus": data.get("consensus_security", {}),
            "privacy": data.get("privacy_pedersen", {}),
            "fl": data.get("fl_validation", {}),
            "reviewer": data.get("reviewer_audit", {}),
        }
        security_values = {key: self._metadata_value(point) for key, point in security_points.items()}
        security_display = {
            "key_establishment": security_values["caps"].get("key_establishment", security_values["caps"].get("pqc_key_establishment", UNAVAILABLE)),
            "identity": security_values["identity"].get("identity_authenticity", UNAVAILABLE),
            "consensus": security_values["consensus"].get("consensus_model", UNAVAILABLE),
            "privacy": security_values["privacy"].get("pedersen_mode", UNAVAILABLE),
            "fl": security_values["fl"].get("fl_validation_level", UNAVAILABLE),
            "reviewer": security_values["reviewer"].get("paper_ready_claim_status", UNAVAILABLE),
        }
        for key, value in security_display.items():
            self._set_overview_label(self._overview_security_labels, key, value, value != UNAVAILABLE)
        statuses = [point.get("status", "unavailable") for point in security_points.values() if isinstance(point, dict)]
        security_status = "error" if "error" in statuses else "ok" if statuses and all(status == "ok" for status in statuses) else "warning"
        self._set_badge("overview_security_live", security_status)

        self._render_overview_ledger(chain_rows)

        self._set_overview_label(self._overview_source_labels, "backend", type(self.blockchain).__name__, True)
        self._set_overview_label(self._overview_source_labels, "connection", self._point_source(connection_point), True)
        self._set_overview_label(self._overview_source_labels, "telemetry", self._point_source(telemetry_point), True)
        self._set_overview_label(self._overview_source_labels, "peers", self._point_source(peers_point), True)
        self._set_overview_label(self._overview_source_labels, "camera", self._point_source(camera_point), True)
        self._set_overview_label(self._overview_source_labels, "updated", data.get("updated_at", UNAVAILABLE), bool(data.get("updated_at")))
        self._set_badge("overview_sources_live", "ok" if connection_ready else "warning")

    def _render_snapshot(self, data: Dict[str, Any]):
        super()._render_snapshot(data)
        self._render_live_overview(data)


SmartCarDashboard = ProductionSmartCarDashboard
