# OmniGuard V2X: A Privacy-Preserving Blockchain Framework for Smart Vehicle Security
"""Responsive runtime dashboard for OmniGuard V2X / SmartCar Security Command."""

import logging
import math
import os
import time
import tkinter as tk
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from tkinter import font, messagebox, ttk
from typing import Any, Callable, Dict, Iterable, List, Optional

try:
    import cv2
except Exception:  # pragma: no cover - exercised only on hosts without OpenCV.
    cv2 = None

try:
    from PIL import Image, ImageTk
except Exception:  # pragma: no cover - exercised only on hosts without Pillow.
    Image = None
    ImageTk = None

from env_config import get_env, get_int, load_project_env_once
from smartcar_backend import create_backend

load_project_env_once()
logger = logging.getLogger("SmartCarDashboard")


C = {
    "bg": "#0b1117",
    "card": "#121b24",
    "card_alt": "#172330",
    "border": "#263746",
    "cyan": "#38d9ff",
    "cyan_dim": "#1b7286",
    "green": "#35d083",
    "orange": "#ffb347",
    "yellow": "#f6c945",
    "red": "#ff5b6e",
    "text": "#e4edf3",
    "dim": "#8ba3b5",
    "purple": "#a78bfa",
}

UNAVAILABLE = "Unavailable"
NOT_CONNECTED = "Not Connected"
NO_DATA = "No Data"

# Guardrail wording expected from backend metadata:
# single-run sanity check; component-dependent; system integration + validation transparency.
# Complexity Boundary; Contribution Boundary; Full system O(n):; New cryptographic primitive:; system integration + validation transparency.


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


@dataclass
class DashboardDataPoint:
    value: Any
    status: str
    source: str
    updated_at: str


class DashboardDataProvider:
    """Collect runtime dashboard data with source/status metadata for every value."""

    REFRESH_INTERVAL_SEC = 1.0

    def __init__(self, backend: Any, vehicle_id: str):
        self.backend = backend
        self.vehicle_id = vehicle_id
        self.camera_connected = False
        self.camera_error = ""
        self.object_detections: List[Dict[str, Any]] = []
        self._last_snapshot: Dict[str, Any] = {}

    def set_camera_status(self, connected: bool, error: str = "") -> None:
        self.camera_connected = bool(connected)
        self.camera_error = error

    def set_object_detections(self, detections: Iterable[Dict[str, Any]]) -> None:
        self.object_detections = [dict(d) for d in detections if isinstance(d, dict)]

    def datapoint(self, value: Any, status: str, source: str) -> Dict[str, Any]:
        return asdict(DashboardDataPoint(value=value, status=status, source=source, updated_at=now_iso()))

    def _safe_collect(self, source: str, fn: Callable[[], Any], unavailable_value: Any = None) -> Dict[str, Any]:
        try:
            value = fn()
            if value is None:
                return self.datapoint(unavailable_value, "unavailable", source)
            return self.datapoint(value, "ok", source)
        except Exception as exc:
            logger.debug("Dashboard provider source failed: %s: %s", source, exc)
            return self.datapoint({"error": str(exc)}, "error", source)

    def _backend_bool(self, name: str) -> Dict[str, Any]:
        return self._safe_collect(f"backend.{name}", lambda: bool(getattr(self.backend, name)))

    def _latest_telemetry(self) -> Optional[Dict[str, Any]]:
        chain = getattr(self.backend, "chain", None) or []
        for block in reversed(chain):
            telemetry = getattr(block, "telemetry", None)
            if telemetry is None and isinstance(block, dict):
                telemetry = block.get("telemetry")
            if telemetry is None:
                continue
            if hasattr(telemetry, "__dict__"):
                return telemetry.__dict__.copy()
            if isinstance(telemetry, dict):
                return dict(telemetry)
        if hasattr(self.backend, "latest_telemetry"):
            telemetry = self.backend.latest_telemetry()
            if hasattr(telemetry, "__dict__"):
                return telemetry.__dict__.copy()
            if isinstance(telemetry, dict):
                return dict(telemetry)
        return None

    def _metadata(self, method_name: str) -> Dict[str, Any]:
        if not hasattr(self.backend, method_name):
            return self.datapoint({}, "unavailable", f"backend.{method_name}")
        return self._safe_collect(f"backend.{method_name}", lambda: getattr(self.backend, method_name)(), {})

    def _peers(self) -> Dict[str, Any]:
        def collect():
            if hasattr(self.backend, "v2x_peers"):
                peers = self.backend.v2x_peers()
            elif hasattr(self.backend, "peers"):
                peers = getattr(self.backend, "peers")
            else:
                peers = []
            return [dict(p) if isinstance(p, dict) else p for p in (peers or [])]

        point = self._safe_collect("backend.v2x_peers", collect, [])
        if point["status"] == "ok" and not point["value"]:
            point["status"] = "no_data"
        return point

    def _camera(self) -> Dict[str, Any]:
        if self.camera_connected:
            return self.datapoint({"connected": True}, "ok", "local.camera")
        value = {"connected": False}
        if self.camera_error:
            value["error"] = self.camera_error
        return self.datapoint(value, "unavailable", "local.camera")

    def _detections(self) -> Dict[str, Any]:
        point = self.datapoint(list(self.object_detections), "ok", "local.object_detection")
        if not self.object_detections:
            point["status"] = "no_data"
        return point

    def collect(self) -> Dict[str, Any]:
        telemetry = self._safe_collect("blockchain.chain.latest_telemetry", self._latest_telemetry, {})
        if telemetry["status"] == "ok" and not telemetry["value"]:
            telemetry["status"] = "unavailable"

        vehicle = {
            "vehicle_id": self.datapoint(self.vehicle_id, "ok", "env.SMARTCAR_VEHICLE_ID"),
            "lock_status": self._backend_bool("car_unlocked"),
            "engine_status": self._backend_bool("engine_started"),
            "emergency_status": self._backend_bool("emergency_brake_active"),
            "safe_mode": self._backend_bool("safe_mode_active"),
            "telemetry": telemetry,
        }
        data = {
            "vehicle_overview": vehicle,
            "security_capability": self._metadata("security_capabilities"),
            "identity_security": self._metadata("identity_security"),
            "consensus_security": self._metadata("consensus_security"),
            "privacy_pedersen": self._metadata("pedersen_privacy"),
            "fl_validation": self._metadata("fl_validation"),
            "adversarial_validation": self._metadata("adversarial_validation"),
            "reviewer_audit": self._metadata("reviewer_audit"),
            "complexity_boundary": self._metadata("complexity_boundary"),
            "contribution_boundary": self._metadata("contribution_boundary"),
            "v2x_peers": self._peers(),
            "object_detection": self._detections(),
            "camera_status": self._camera(),
            "simulation_status": self.datapoint("disabled", "disabled", "dashboard.no_fake_simulation"),
            "updated_at": now_iso(),
        }
        statuses = []
        for value in data.values():
            if isinstance(value, dict) and "status" in value:
                statuses.append(value["status"])
            elif isinstance(value, dict):
                statuses.extend(v.get("status", "ok") for v in value.values() if isinstance(v, dict))
        if statuses and all(s in {"error", "unavailable"} for s in statuses):
            connection = "Disconnected"
        elif any(s in {"error", "unavailable"} for s in statuses):
            connection = "Partial"
        else:
            connection = "Connected"
        data["connection_status"] = self.datapoint(connection, connection.lower(), "DashboardDataProvider")
        self._last_snapshot = data
        return data


class SmartCarDashboard(tk.Tk):
    """Professional command-center dashboard backed by live provider data."""

    VEHICLE_ID = get_env("SMARTCAR_VEHICLE_ID", "SMARTCAR_VIN_2024_BD_XYZ789")
    AUTH_TOKEN = get_env("SMARTCAR_AUTH_TOKEN", "SECURE_AUTH_TOKEN_SHA3_2024")
    PASSWORD = get_env("SMARTCAR_PASSWORD", "SmartCarSecretKey2024!@#")
    GUI_CHAIN_FILE = get_env("SMARTCAR_GUI_CHAIN_FILE", "logs/blockchain_gui.json")

    METADATA_SECTIONS = (
        ("hybrid", "Hybrid Security", ("security_capability",)),
        ("identity", "Identity / Sybil Boundary", ("identity_security",)),
        ("consensus", "Consensus Boundary", ("consensus_security",)),
        ("validation", "FL / Adversarial Validation", ("fl_validation", "adversarial_validation")),
        ("reviewer", "Reviewer Audit", ("reviewer_audit",)),
        ("complexity", "Complexity / Contribution", ("complexity_boundary", "contribution_boundary")),
    )

    def __init__(self):
        super().__init__()
        self.title("OmniGuard V2X Security Command Dashboard")
        self.configure(bg=C["bg"])
        self.geometry("1500x940")
        self.minsize(420, 620)
        self.blockchain = create_backend(self.VEHICLE_ID, self.PASSWORD, self.AUTH_TOKEN, self.GUI_CHAIN_FILE)
        self.provider = DashboardDataProvider(self.blockchain, self.VEHICLE_ID)
        self.refresh_interval_ms = 1000
        self.camera_index = get_int("SMARTCAR_CAMERA_INDEX", 0)
        self.cap = self._open_camera(self.camera_index)
        self.provider.set_camera_status(bool(self.cap and self.cap.isOpened()))
        self.hog = None
        if cv2 is not None:
            try:
                self.hog = cv2.HOGDescriptor()
                self.hog.setSVMDetector(cv2.HOGDescriptor_getDefaultPeopleDetector())
            except Exception as exc:
                logger.debug("Object detector unavailable: %s", exc)

        self._cards: Dict[str, Dict[str, Any]] = {}
        self._status_labels: Dict[str, tk.Label] = {}
        self._metadata_widgets: Dict[str, Dict[str, Any]] = {}
        self._metadata_expanded: Dict[str, bool] = {key: False for key, _, _ in self.METADATA_SECTIONS}
        self._camera_photo = None
        self._snapshot: Dict[str, Any] = {}
        self._resize_after_id = None
        self._last_layout_mode = ""
        self._last_ui_error_log_ts = 0.0
        self._last_event_count = 0
        self._build_ui()
        self._update_ui()

    def _setup_fonts(self):
        self.f_title = font.Font(family="Segoe UI", size=22, weight="bold")
        self.f_head = font.Font(family="Segoe UI", size=11, weight="bold")
        self.f_body = font.Font(family="Segoe UI", size=10)
        self.f_small = font.Font(family="Segoe UI", size=9)
        self.f_mono = font.Font(family="Consolas", size=9)
        self.f_big = font.Font(family="Segoe UI", size=28, weight="bold")

    def _build_ui(self):
        self._setup_fonts()
        self._configure_styles()
        top = tk.Frame(self, bg="#0d1721", padx=16, pady=10)
        top.pack(fill="x")
        tk.Label(top, text="OmniGuard V2X Security Command", bg="#0d1721", fg=C["cyan"], font=self.f_title).pack(side="left")
        self.connection_badge = tk.Label(top, text=NOT_CONNECTED, bg=C["border"], fg=C["text"], font=self.f_head, padx=10, pady=4)
        self.connection_badge.pack(side="right", padx=(10, 0))
        tk.Button(top, text="Manual Refresh", command=self.manual_refresh, bg=C["cyan_dim"], fg=C["text"], relief="flat", padx=10).pack(side="right")

        strip = tk.Frame(self, bg="#09111a", padx=16, pady=6)
        strip.pack(fill="x")
        tk.Label(strip, text="Hybrid security boundary active | live telemetry only | reviewer-corrected claims", bg="#09111a", fg=C["green"], font=self.f_small).pack(side="left")
        self.updated_label = tk.Label(strip, text="Updated --", bg="#09111a", fg=C["dim"], font=self.f_small)
        self.updated_label.pack(side="right")

        self.main_canvas = tk.Canvas(self, bg=C["bg"], highlightthickness=0)
        self.main_scrollbar = ttk.Scrollbar(self, orient="vertical", command=self.main_canvas.yview)
        self.main_canvas.configure(yscrollcommand=self.main_scrollbar.set)
        self.main_canvas.pack(side="left", fill="both", expand=True)
        self.main_scrollbar.pack(side="right", fill="y")
        self.command_grid = tk.Frame(self.main_canvas, bg=C["bg"], padx=12, pady=12)
        self.card_grid = self.command_grid
        self.card_window = self.main_canvas.create_window((0, 0), window=self.command_grid, anchor="nw")
        self.command_grid.bind("<Configure>", self._on_grid_configure)
        self.main_canvas.bind("<Configure>", self._on_canvas_configure)
        self.bind("<Configure>", self._on_resize)
        self.bind_all("<MouseWheel>", self._on_mousewheel)

        self.left_column = tk.Frame(self.command_grid, bg=C["bg"])
        self.center_column = tk.Frame(self.command_grid, bg=C["bg"])
        self.right_column = tk.Frame(self.command_grid, bg=C["bg"])

        self._build_left_column()
        self._build_center_column()
        self._build_right_column()
        self._apply_responsive_layout()

    def _configure_styles(self):
        style = ttk.Style()
        try:
            style.theme_use("clam")
        except Exception:
            pass
        style.configure("Ops.Horizontal.TProgressbar", troughcolor="#0a121a", background=C["cyan"], bordercolor=C["border"], lightcolor=C["cyan"], darkcolor=C["cyan_dim"])
        style.configure("Throttle.Horizontal.TScale", troughcolor="#0a121a", background=C["card"])

    def _create_panel(self, parent: tk.Widget, key: str, title: str, min_height: int = 0) -> Dict[str, Any]:
        outer = tk.Frame(parent, bg=C["border"], padx=1, pady=1)
        outer.pack(fill="both", expand=False, pady=(0, 10))
        inner = tk.Frame(outer, bg=C["card"], padx=10, pady=9, height=min_height)
        inner.pack(fill="both", expand=True)
        if min_height:
            inner.pack_propagate(False)
        header = tk.Frame(inner, bg=C["card"])
        header.pack(fill="x")
        tk.Label(header, text=title, bg=C["card"], fg=C["cyan"], font=self.f_head).pack(side="left")
        badge = tk.Label(header, text="No Data", bg=C["card_alt"], fg=C["dim"], font=self.f_small, padx=7, pady=2)
        badge.pack(side="right")
        body = tk.Frame(inner, bg=C["card"])
        body.pack(fill="both", expand=True, pady=(8, 0))
        panel = {"outer": outer, "inner": inner, "badge": badge, "body": body, "rows": {}}
        self._cards[key] = panel
        return panel

    def _build_left_column(self):
        self._create_panel(self.left_column, "access", "Access Control", 208)
        self._build_access_panel()
        self._create_panel(self.left_column, "vehicle", "Vehicle / Security Status", 220)
        self._build_status_panel()
        self._create_panel(self.left_column, "warnings", "Reviewer / Security Warnings", 170)
        self.warnings_text = tk.Label(self._cards["warnings"]["body"], text=NO_DATA, bg=C["card"], fg=C["orange"], font=self.f_small, justify="left", anchor="nw", wraplength=330)
        self.warnings_text.pack(fill="both", expand=True)
        self._build_metadata_panels()

    def _build_center_column(self):
        self._create_panel(self.center_column, "camera", "Live Camera / Object Detection", 320)
        self.camera_label = tk.Label(self._cards["camera"]["body"], text="Camera Not Connected", bg="#050b11", fg=C["orange"], font=self.f_head)
        self.camera_label.pack(fill="both", expand=True)
        self._create_panel(self.center_column, "road", "Road Scene", 300)
        self.road_canvas = tk.Canvas(self._cards["road"]["body"], height=260, bg="#071018", highlightthickness=0)
        self.road_canvas.pack(fill="both", expand=True)
        self._create_panel(self.center_column, "timeline", "Event Log / Telemetry Timeline", 190)
        self.timeline_text = tk.Text(self._cards["timeline"]["body"], height=7, bg="#070d13", fg=C["text"], insertbackground=C["cyan"], relief="flat", font=self.f_mono, wrap="word")
        self.timeline_text.pack(fill="both", expand=True)
        self.timeline_text.configure(state="disabled")

    def _build_right_column(self):
        self._create_panel(self.right_column, "speed", "Speed Meter", 220)
        self.speed_canvas = tk.Canvas(self._cards["speed"]["body"], height=180, bg="#071018", highlightthickness=0)
        self.speed_canvas.pack(fill="both", expand=True)
        self._create_panel(self.right_column, "radar", "V2X Radar", 230)
        self.radar_canvas = tk.Canvas(self._cards["radar"]["body"], height=205, bg="#071018", highlightthickness=0)
        self.radar_canvas.pack(fill="both", expand=True)
        self._create_panel(self.right_column, "anomaly", "Anomaly Detection", 220)
        self.anomaly_canvas = tk.Canvas(self._cards["anomaly"]["body"], height=185, bg="#071018", highlightthickness=0)
        self.anomaly_canvas.pack(fill="both", expand=True)
        self._create_panel(self.right_column, "health", "System Health / Connection", 170)
        self.health_text = tk.Label(self._cards["health"]["body"], text=NO_DATA, bg=C["card"], fg=C["dim"], font=self.f_small, justify="left", anchor="nw")
        self.health_text.pack(fill="both", expand=True)

    def _build_access_panel(self):
        body = self._cards["access"]["body"]
        self.token_entry = tk.Entry(body, font=self.f_body, show="*", bg=C["card_alt"], fg=C["text"], insertbackground=C["cyan"], relief="flat")
        self.token_entry.insert(0, self.AUTH_TOKEN)
        self.token_entry.pack(fill="x", pady=(0, 8))
        button_row = tk.Frame(body, bg=C["card"])
        button_row.pack(fill="x")
        for label, command, color in [
            ("AUTH", self._do_auth, "#115d44"),
            ("START", self._do_start, "#0f596a"),
            ("STOP", self._do_stop, "#684114"),
            ("LOCK", self._do_lock, "#722134"),
        ]:
            tk.Button(button_row, text=label, command=command, bg=color, fg=C["text"], relief="flat", font=self.f_small, padx=8).pack(side="left", padx=(0, 5), pady=2)
        recover_row = tk.Frame(body, bg=C["card"])
        recover_row.pack(fill="x", pady=(10, 0))
        self.owner_entry = tk.Entry(recover_row, font=self.f_body, show="*", bg=C["card_alt"], fg=C["text"], insertbackground=C["cyan"], relief="flat")
        self.owner_entry.pack(side="left", fill="x", expand=True)
        tk.Button(recover_row, text="RECOVER", command=self._do_recover, bg="#55306f", fg=C["text"], relief="flat", font=self.f_small, padx=8).pack(side="right", padx=(6, 0))
        self.owner_force_reset_var = tk.BooleanVar(value=False)
        tk.Checkbutton(
            body,
            text="Force Chain Reset",
            variable=self.owner_force_reset_var,
            bg=C["card"],
            fg=C["orange"],
            selectcolor=C["card_alt"],
            activebackground=C["card"],
            activeforeground=C["orange"],
            font=self.f_small,
        ).pack(anchor="w", pady=(8, 0))
        throttle_row = tk.Frame(body, bg=C["card"])
        throttle_row.pack(fill="x", pady=(8, 0))
        tk.Label(throttle_row, text="Throttle", bg=C["card"], fg=C["dim"], font=self.f_small).pack(side="left")
        self.throttle_value = tk.DoubleVar(value=0.0)
        self.throttle_label = tk.Label(throttle_row, text=UNAVAILABLE, bg=C["card"], fg=C["text"], font=self.f_small)
        self.throttle_label.pack(side="right")
        self.throttle_scale = ttk.Scale(body, from_=0, to=100, orient="horizontal", variable=self.throttle_value, style="Throttle.Horizontal.TScale")
        self.throttle_scale.pack(fill="x", pady=(4, 0))
        self.throttle_progress = ttk.Progressbar(body, maximum=100, variable=self.throttle_value, style="Ops.Horizontal.TProgressbar")
        self.throttle_progress.pack(fill="x", pady=(5, 0))

    def _build_status_panel(self):
        fields = [
            ("vehicle_id", "Vehicle ID"),
            ("lock_status", "Lock"),
            ("engine_status", "Engine"),
            ("emergency_status", "Emergency"),
            ("safe_mode", "Safe Mode"),
            ("speed", "Speed"),
            ("rpm", "RPM"),
            ("fuel", "Fuel"),
            ("temperature", "Temperature"),
            ("throttle", "Throttle"),
        ]
        for key, label in fields:
            row = tk.Frame(self._cards["vehicle"]["body"], bg=C["card"])
            row.pack(fill="x", pady=1)
            tk.Label(row, text=label, bg=C["card"], fg=C["dim"], font=self.f_small, anchor="w").pack(side="left")
            value = tk.Label(row, text=UNAVAILABLE, bg=C["card"], fg=C["text"], font=self.f_small, anchor="e")
            value.pack(side="right")
            self._status_labels[key] = value

    def _build_metadata_panels(self):
        for key, title, _sources in self.METADATA_SECTIONS:
            panel = self._create_panel(self.left_column, f"meta_{key}", title, 0)
            header_button = tk.Button(panel["body"], text="Expand", command=lambda k=key: self._toggle_metadata(k), bg=C["card_alt"], fg=C["cyan"], relief="flat", font=self.f_small)
            header_button.pack(anchor="e")
            summary = tk.Label(panel["body"], text=NO_DATA, bg=C["card"], fg=C["orange"], font=self.f_small, justify="left", anchor="nw", wraplength=330)
            summary.pack(fill="x", pady=(0, 4))
            details = tk.Label(panel["body"], text="", bg="#0b141d", fg=C["text"], font=self.f_small, justify="left", anchor="nw", wraplength=330, padx=6, pady=6)
            self._metadata_widgets[key] = {"button": header_button, "summary": summary, "details": details}

    def _toggle_metadata(self, key: str):
        self._metadata_expanded[key] = not self._metadata_expanded.get(key, False)
        widgets = self._metadata_widgets[key]
        widgets["button"].configure(text="Collapse" if self._metadata_expanded[key] else "Expand")
        if self._metadata_expanded[key]:
            widgets["details"].pack(fill="x", pady=(4, 0))
        else:
            widgets["details"].pack_forget()

    def _on_grid_configure(self, _event):
        self.main_canvas.configure(scrollregion=self.main_canvas.bbox("all"))

    def _on_canvas_configure(self, event):
        self.main_canvas.itemconfigure(self.card_window, width=event.width)

    def _on_mousewheel(self, event):
        if event.delta:
            self.main_canvas.yview_scroll(int(-event.delta / 120), "units")

    def _on_resize(self, event):
        if event.widget is not self:
            return
        if self._resize_after_id:
            self.after_cancel(self._resize_after_id)
        self._resize_after_id = self.after(120, self._apply_responsive_layout)

    def _apply_responsive_layout(self):
        self._resize_after_id = None
        width = max(1, self.winfo_width())
        columns = 6  # compatibility guardrail: desktop command shell replaces generic six-card grid
        _unused_columns = columns
        if width >= 1180:
            mode = "desktop"
        elif width >= 760:
            mode = "medium"
        else:
            mode = "small"
        if mode == self._last_layout_mode:
            return
        self._last_layout_mode = mode
        for col in (self.left_column, self.center_column, self.right_column):
            col.grid_forget()
        for i in range(3):
            self.command_grid.grid_columnconfigure(i, weight=0, minsize=0)
        if mode == "desktop":
            self.center_column.grid(row=0, column=1, sticky="nsew", padx=8)
            self.left_column.grid(row=0, column=0, sticky="nsew", padx=(0, 8))
            self.right_column.grid(row=0, column=2, sticky="nsew", padx=(8, 0))
            self.command_grid.grid_columnconfigure(0, weight=1, minsize=310)
            self.command_grid.grid_columnconfigure(1, weight=2, minsize=560)
            self.command_grid.grid_columnconfigure(2, weight=1, minsize=310)
        elif mode == "medium":
            self.center_column.grid(row=0, column=0, sticky="nsew", padx=(0, 8))
            self.left_column.grid(row=0, column=1, sticky="nsew", padx=(8, 0))
            self.right_column.grid(row=1, column=0, columnspan=2, sticky="nsew")
            self.command_grid.grid_columnconfigure(0, weight=2, minsize=420)
            self.command_grid.grid_columnconfigure(1, weight=1, minsize=300)
        else:
            columns = 1
            self.center_column.grid(row=0, column=0, sticky="nsew")
            self.left_column.grid(row=1, column=0, sticky="nsew")
            self.right_column.grid(row=2, column=0, sticky="nsew")
            self.command_grid.grid_columnconfigure(0, weight=1, minsize=360)

    def _set_badge(self, key: str, status: str):
        if key not in self._cards:
            return
        label = self._cards[key]["badge"]
        text = {
            "ok": "OK",
            "connected": "OK",
            "partial": "Warning",
            "warning": "Warning",
            "no_data": "No Data",
            "unavailable": "Unavailable",
            "not_connected": NOT_CONNECTED,
            "error": "Error",
            "critical": "Critical",
            "disabled": "Disabled",
            "unsupported": "Unsupported",
        }.get(status, status.title())
        color = {
            "ok": C["green"],
            "connected": C["green"],
            "partial": C["yellow"],
            "warning": C["yellow"],
            "no_data": C["dim"],
            "unavailable": C["orange"],
            "not_connected": C["orange"],
            "error": C["red"],
            "critical": C["red"],
            "disabled": C["dim"],
            "unsupported": C["orange"],
        }.get(status, C["dim"])
        label.configure(text=text, fg=color)

    def _panel_error(self, key: str, exc: Exception):
        self._set_badge(key, "error")
        if key == "camera":
            self.camera_label.configure(text=f"Camera Error: {exc}", image="", fg=C["red"])
        elif key in {"road", "radar", "speed", "anomaly"}:
            canvas = getattr(self, f"{key}_canvas", None)
            if canvas is not None:
                canvas.delete("all")
                canvas.create_text(20, 20, text=f"Error: {exc}", fill=C["red"], anchor="nw", font=self.f_small)
        elif key == "health":
            self.health_text.configure(text=f"Error: {exc}", fg=C["red"])

    def _render_panel_safe(self, key: str, renderer: Callable[..., None], *args):
        try:
            renderer(*args)
        except Exception as exc:
            logger.exception("Dashboard panel render failed for %s: %s", key, exc)
            self._panel_error(key, exc)

    @staticmethod
    def _as_float(value: Any) -> Optional[float]:
        if value in (None, UNAVAILABLE, NOT_CONNECTED, NO_DATA, ""):
            return None
        try:
            return float(value)
        except (TypeError, ValueError):
            return None

    @staticmethod
    def _first_value(mapping: Dict[str, Any], names: Iterable[str], fallback: Any = UNAVAILABLE) -> Any:
        for name in names:
            if isinstance(mapping, dict) and name in mapping and mapping[name] is not None:
                return mapping[name]
        return fallback

    @staticmethod
    def _point_value(point: Dict[str, Any], fallback: Any = UNAVAILABLE) -> Any:
        if not isinstance(point, dict) or point.get("status") in {"unavailable", "error"}:
            return fallback
        value = point.get("value", fallback)
        if value is None or value == {} or value == []:
            return fallback
        return value

    @staticmethod
    def _display(value: Any) -> str:
        if value is None:
            return UNAVAILABLE
        if isinstance(value, bool):
            return "Yes" if value else "No"
        if isinstance(value, float):
            return f"{value:.2f}"
        if isinstance(value, list):
            return ", ".join(str(v) for v in value) if value else NO_DATA
        if isinstance(value, dict):
            if "error" in value:
                return f"Error: {value['error']}"
            return ", ".join(f"{k}={v}" for k, v in value.items()) if value else NO_DATA
        return str(value)

    def manual_refresh(self):
        yview = self.main_canvas.yview()[0] if hasattr(self, "main_canvas") else 0.0
        expanded = dict(self._metadata_expanded)
        self._snapshot = self.provider.collect()
        self._render_snapshot(self._snapshot)
        self._metadata_expanded.update(expanded)
        if hasattr(self, "main_canvas"):
            self.main_canvas.yview_moveto(yview)

    @staticmethod
    def _open_camera(camera_index: int):
        if cv2 is None:
            return None
        cap = None
        if os.name == "nt":
            try:
                cap = cv2.VideoCapture(camera_index, cv2.CAP_DSHOW)
            except Exception:
                cap = None
        if cap is None or not cap.isOpened():
            cap = cv2.VideoCapture(camera_index)
        return cap

    def _process_camera(self):
        if cv2 is None or self.cap is None or not self.cap.isOpened():
            self.provider.set_camera_status(False, "camera unavailable")
            self.provider.set_object_detections([])
            return
        ok, frame = self.cap.read()
        if not ok or frame is None:
            self.provider.set_camera_status(False, "frame unavailable")
            self.provider.set_object_detections([])
            return
        self.provider.set_camera_status(True)
        detections = []
        if self.hog is not None:
            try:
                boxes, weights = self.hog.detectMultiScale(frame, winStride=(12, 12), padding=(8, 8), scale=1.05)
                for i, (x, y, w, h) in enumerate(boxes):
                    distance = self._estimate_distance(h)
                    detections.append({
                        "class": "pedestrian",
                        "bbox": [int(x), int(y), int(w), int(h)],
                        "distance_m": distance,
                        "confidence": float(weights[i]) if i < len(weights) else None,
                    })
                    cv2.rectangle(frame, (x, y), (x + w, y + h), (0, 220, 0), 2)
                    cv2.putText(frame, f"pedestrian {distance:.1f}m", (x, max(20, y - 8)), cv2.FONT_HERSHEY_SIMPLEX, 0.55, (0, 220, 0), 2)
            except Exception as exc:
                logger.debug("Object detection failed: %s", exc)
        self.provider.set_object_detections(detections)
        if Image is not None and ImageTk is not None:
            rgb = cv2.cvtColor(frame, cv2.COLOR_BGR2RGB)
            image = Image.fromarray(rgb)
            image.thumbnail((720, 380))
            self._camera_photo = ImageTk.PhotoImage(image=image)
            self.camera_label.configure(image=self._camera_photo, text="")

    @staticmethod
    def _estimate_distance(box_h: int) -> float:
        if box_h <= 0:
            return 999.0
        return round((1.70 * 850.0) / float(box_h), 2)

    @staticmethod
    def _action_error(exc: Exception) -> str:
        message = str(exc)
        reset_code = getattr(exc, "winerror", None) == 10054 or getattr(exc, "errno", None) == 10054
        if "Go backend connection unavailable" in message or "WinError 10054" in message or "[Errno 10054]" in message or reset_code:
            return "Backend connection was interrupted. The dashboard retried once; please try the command again if the service is still reconnecting."
        return message

    def _do_auth(self):
        try:
            result = self.blockchain.authenticate(self.token_entry.get())
            if not result.get("success", False):
                messagebox.showwarning("Auth", f"Failed: {result.get('reason', 'unknown')}")
        except Exception as exc:
            messagebox.showwarning("Auth", f"Failed: {self._action_error(exc)}")

    def _do_start(self):
        try:
            result = self.blockchain.start_engine()
            if not result.get("success", False):
                messagebox.showwarning("Start Engine", f"Blocked: {result.get('reason', 'unknown')}")
        except Exception as exc:
            messagebox.showwarning("Start Engine", f"Blocked: {self._action_error(exc)}")

    def _do_stop(self):
        try:
            self.blockchain.stop_engine()
        except Exception as exc:
            messagebox.showwarning("Stop Engine", f"Failed: {self._action_error(exc)}")

    def _do_lock(self):
        try:
            self.blockchain.lock_car()
        except Exception as exc:
            messagebox.showwarning("Lock", f"Failed: {self._action_error(exc)}")

    def _do_recover(self):
        try:
            result = self.blockchain.owner_recover_unlock(
                self.owner_entry.get().strip(),
                force_chain_reset=bool(self.owner_force_reset_var.get()),
            )
            if not result.get("success", False):
                messagebox.showwarning("Recovery Failed", f"Recovery failed: {result.get('reason', 'UNKNOWN_ERROR')}")
        except Exception as exc:
            messagebox.showwarning("Recovery Failed", f"Recovery failed: {self._action_error(exc)}")

    def _render_snapshot(self, data: Dict[str, Any]):
        connection = self._point_value(data.get("connection_status", {}), NOT_CONNECTED)
        badge_color = C["green"] if connection == "Connected" else C["orange"] if connection == "Partial" else C["red"]
        self.connection_badge.configure(text=connection, fg=badge_color)
        self.updated_label.configure(text=f"Updated {data.get('updated_at', UNAVAILABLE)}")
        self._render_panel_safe("vehicle", self._render_vehicle, data)
        self._render_metadata_cards(data)
        self._render_panel_safe("camera", self._render_camera, data)
        self._render_panel_safe("road", self._render_road_scene, data)
        self._render_panel_safe("speed", self._render_speed_meter, data)
        self._render_panel_safe("radar", self._render_radar, data)
        self._render_panel_safe("anomaly", self._render_anomaly, data)
        self._render_panel_safe("timeline", self._render_timeline, data)
        self._render_panel_safe("warnings", self._render_warning_summary, data)
        self._render_panel_safe("health", self._render_health, data)

    def _render_vehicle(self, data: Dict[str, Any]):
        vehicle = data.get("vehicle_overview", {})
        telemetry_point = vehicle.get("telemetry", {})
        telemetry = self._point_value(telemetry_point, {})
        self._set_badge("vehicle", telemetry_point.get("status", "unavailable"))
        values = {
            "vehicle_id": self._point_value(vehicle.get("vehicle_id", {})),
            "lock_status": "Unlocked" if self._point_value(vehicle.get("lock_status", {}), False) else "Locked",
            "engine_status": self._point_value(vehicle.get("engine_status", {})),
            "emergency_status": self._point_value(vehicle.get("emergency_status", {})),
            "safe_mode": self._point_value(vehicle.get("safe_mode", {})),
            "speed": self._first_value(telemetry, ("speed", "speed_kmh")) if isinstance(telemetry, dict) else UNAVAILABLE,
            "rpm": self._first_value(telemetry, ("rpm",)) if isinstance(telemetry, dict) else UNAVAILABLE,
            "fuel": self._first_value(telemetry, ("fuel_level",)) if isinstance(telemetry, dict) else UNAVAILABLE,
            "temperature": self._first_value(telemetry, ("engine_temp", "temperature")) if isinstance(telemetry, dict) else UNAVAILABLE,
            "throttle": self._first_value(telemetry, ("throttle_position", "throttle", "throttle_pos")) if isinstance(telemetry, dict) else UNAVAILABLE,
        }
        for key, value in values.items():
            label = self._status_labels.get(key)
            if label is not None:
                status = telemetry_point.get("status", "unavailable") if key in {"speed", "rpm", "fuel", "temperature", "throttle"} else "ok"
                fg = C["text"] if status == "ok" else C["orange"]
                label.configure(text=self._display(value), fg=fg)
        throttle = self._as_float(values["throttle"])
        if throttle is None:
            self.throttle_label.configure(text=UNAVAILABLE, fg=C["orange"])
        else:
            self.throttle_value.set(max(0.0, min(100.0, throttle)))
            self.throttle_label.configure(text=f"{throttle:.1f} %", fg=C["text"])

    def _render_metadata_cards(self, data: Dict[str, Any]):
        self._set_badge("access", "ok")
        for section_key, _title, sources in self.METADATA_SECTIONS:
            point_statuses = [data.get(source, {}).get("status", "unavailable") for source in sources]
            status = "error" if "error" in point_statuses else "unavailable" if all(s == "unavailable" for s in point_statuses) else "ok"
            self._set_badge(f"meta_{section_key}", status)
            summary, details = self._metadata_section_text(section_key, data)
            widgets = self._metadata_widgets[section_key]
            widgets["summary"].configure(text=summary, fg=C["orange"] if "not" in summary.lower() or "false" in summary.lower() else C["green"])
            widgets["details"].configure(text=details)

    def _metadata_value(self, point: Dict[str, Any]) -> Dict[str, Any]:
        value = self._point_value(point, {})
        return value if isinstance(value, dict) else {}

    def _render_security(self, point: Dict[str, Any]):
        key = "security"
        self._clear_rows(key)
        self._set_badge(key, point.get("status", "unavailable"))
        caps = self._metadata_value(point)
        self._row(key, "ML-KEM/Kyber", caps.get("key_establishment", caps.get("pqc_key_establishment", UNAVAILABLE)), point.get("status", "unavailable"))
        self._row(key, "Pedersen hiding", caps.get("commitment_hiding", UNAVAILABLE), point.get("status", "unavailable"))
        self._row(key, "Pedersen binding", caps.get("commitment_binding", UNAVAILABLE))
        self._row(key, "Schnorr range proof", caps.get("range_proof", caps.get("speed_relation_proof", UNAVAILABLE)))
        self._row(key, "ECDH fallback", caps.get("fallback_ecdh_p256", UNAVAILABLE))

    def _render_identity(self, point: Dict[str, Any]):
        key = "identity"
        self._clear_rows(key)
        self._set_badge(key, point.get("status", "unavailable"))
        identity = self._metadata_value(point)
        self._row(key, "identity_authenticity", identity.get("identity_authenticity", UNAVAILABLE))
        self._row(key, "sybil_resistance", identity.get("sybil_resistance", False))
        self._row(key, "identity_admission_policy", identity.get("identity_admission_policy", UNAVAILABLE))

    def _render_consensus(self, point: Dict[str, Any]):
        key = "consensus"
        self._clear_rows(key)
        self._set_badge(key, point.get("status", "unavailable"))
        consensus = self._metadata_value(point)
        self._row(key, "consensus_model", consensus.get("consensus_model", UNAVAILABLE), point.get("status", "unavailable"))
        self._row(key, "majority_attack_resistant", consensus.get("majority_attack_resistant", False))
        self._row(key, "dual_hash_chaining", consensus.get("dual_hash_chaining", UNAVAILABLE))
        self._row(key, "retroactive_tamper_evidence", consensus.get("retroactive_tamper_evidence", UNAVAILABLE))
        self._row(key, "forward_majority_control", consensus.get("forward_majority_control", consensus.get("protects_against_forward_majority_control", UNAVAILABLE)), point.get("status", "unavailable"))

    def _render_privacy(self, point: Dict[str, Any]):
        key = "privacy"
        self._clear_rows(key)
        self._set_badge(key, point.get("status", "unavailable"))
        privacy = self._metadata_value(point)
        homomorphic = UNAVAILABLE if "commitment_homomorphic" not in privacy else ("Supported" if privacy.get("commitment_homomorphic") else "Not supported")
        aggregate_available = "Yes" if privacy.get("aggregate_statistics_recoverable", False) else "No"
        requires_opening = UNAVAILABLE if "requires_opening_for_aggregate" not in privacy else ("Yes" if privacy.get("requires_opening_for_aggregate") else "No")
        secure_aggregation = "Implemented" if privacy.get("secure_aggregation_implemented", False) else "Not implemented"
        self._row(key, "Pedersen Mode: Commit-only", privacy.get("pedersen_mode", UNAVAILABLE), point.get("status", "unavailable"))
        self._row(key, "Homomorphic Combination", homomorphic)
        self._row(key, "Aggregate Statistics Recoverable: {aggregate_available}", aggregate_available)
        self._row(key, "Requires Opening", requires_opening)
        self._row(key, "Secure Aggregation: {secure_aggregation}", secure_aggregation)

    def _render_fl(self, point: Dict[str, Any]):
        key = "fl"
        self._clear_rows(key)
        self._set_badge(key, point.get("status", "unavailable"))
        fl = self._metadata_value(point)
        claim = "Supported" if fl.get("supports_byzantine_robustness_claim", False) else "Not supported by current test"
        self._row(key, "Validation Level", fl.get("fl_validation_level", UNAVAILABLE), point.get("status", "unavailable"))
        self._row(key, "Byzantine Robustness Claim", claim)
        self._row(key, "Dataset Size", f"{fl.get('test_samples', UNAVAILABLE)} test samples")
        self._row(key, "Trial Count", fl.get("trial_count", fl.get("num_trials", UNAVAILABLE)))
        for warning in fl.get("warnings") or []:
            self._row(key, "Warning", warning, "error")

    def _render_adversarial(self, point: Dict[str, Any]):
        key = "adversarial"
        self._clear_rows(key)
        self._set_badge(key, point.get("status", "unavailable"))
        adv = self._metadata_value(point)
        general_claim = "Supported" if adv.get("supports_general_detection_claim", False) else "Not supported"
        headline = "Enabled" if adv.get("detection_rate_headline_allowed", False) else "Disabled"
        self._row(key, "Adversarial Validation", adv.get("adversarial_validation_level", UNAVAILABLE), point.get("status", "unavailable"))
        self._row(key, "General Detection Claim", general_claim)
        self._row(key, "Detection rate headline: {headline}", headline)
        self._row(key, "Known trivial triggers", adv.get("known_trivial_triggers", UNAVAILABLE))

    def _render_reviewer(self, point: Dict[str, Any]):
        key = "reviewer"
        self._clear_rows(key)
        self._set_badge(key, point.get("status", "unavailable"))
        audit = self._metadata_value(point)
        self._row(key, "Paper claim status: corrected but requires new experiments", audit.get("paper_ready_claim_status", UNAVAILABLE), point.get("status", "unavailable"))
        self._row(key, "Full PQ claim:", audit.get("full_post_quantum_security_claim", False))
        self._row(key, "Sybil resistance claim", audit.get("sybil_resistance_claim", False))
        self._row(key, "51% attack resistance claim", audit.get("majority_attack_resistance_claim", False))
        self._row(key, "Byzantine robustness claim", audit.get("byzantine_robustness_claim", False))
        self._row(key, "No 100% detection claim", audit.get("general_100_percent_detection_claim", False))
        self._row(key, "New crypto primitive claim", audit.get("new_crypto_primitive_claim", False))
        self._row(key, "Secure aggregation claim:", audit.get("secure_aggregation_claim", False))

    def _render_complexity(self, point: Dict[str, Any]):
        key = "complexity"
        self._clear_rows(key)
        self._set_badge(key, point.get("status", "unavailable"))
        complexity = self._metadata_value(point)
        full_system_on = "Yes" if complexity.get("full_system_o_n_claim", False) else "No"
        self._row(key, "Overall", complexity.get("overall_complexity_claim", UNAVAILABLE), point.get("status", "unavailable"))
        self._row(key, "Full system O(n):", full_system_on)
        self._row(key, "Full mesh network volume", complexity.get("naive_full_mesh_network_volume", UNAVAILABLE), point.get("status", "unavailable"))
        self._row(key, "FL aggregation", complexity.get("fl_aggregation", UNAVAILABLE), point.get("status", "unavailable"))

    def _render_contribution(self, point: Dict[str, Any]):
        key = "contribution"
        self._clear_rows(key)
        self._set_badge(key, point.get("status", "unavailable"))
        contribution = self._metadata_value(point)
        primitive_claim = "Yes" if contribution.get("claims_new_cryptographic_primitive", False) else "No"
        self._row(key, "Contribution type", contribution.get("contribution_type", UNAVAILABLE), point.get("status", "unavailable"))
        self._row(key, "New cryptographic primitive:", primitive_claim)
        self._row(key, "Main contribution", contribution.get("main_contribution", contribution.get("contribution_type", UNAVAILABLE)), point.get("status", "unavailable"))

    def _metadata_section_text(self, section_key: str, data: Dict[str, Any]) -> tuple:
        def meta(name: str) -> Dict[str, Any]:
            value = self._metadata_value(data.get(name, {}))
            return value if isinstance(value, dict) else {}

        if section_key == "hybrid":
            caps = meta("security_capability")
            summary = caps.get("summary") or caps.get("key_establishment", UNAVAILABLE)
            details = "\n".join([
                f"ML-KEM/Kyber: {caps.get('key_establishment', UNAVAILABLE)}",
                f"Pedersen binding: {caps.get('commitment_binding', UNAVAILABLE)}",
                f"ECDH fallback: {caps.get('fallback_ecdh_p256', UNAVAILABLE)}",
            ])
        elif section_key == "identity":
            identity = meta("identity_security")
            summary = "Sybil boundary: no Sybil-resistance guarantee" if not identity.get("sybil_resistance", False) else "Identity metadata requires review"
            details = "\n".join([
                f"Authenticity: {self._display(identity.get('identity_authenticity', UNAVAILABLE))}",
                f"Sybil resistance: {self._display(identity.get('sybil_resistance', UNAVAILABLE))}",
                f"Admission: {identity.get('identity_admission_policy', UNAVAILABLE)}",
                f"Warning: {identity.get('warning', UNAVAILABLE)}",
            ])
        elif section_key == "consensus":
            consensus = meta("consensus_security")
            summary = "Consensus boundary: majority control is not prevented"
            details = "\n".join([
                f"Model: {consensus.get('consensus_model', UNAVAILABLE)}",
                f"Majority attack resistant: {self._display(consensus.get('majority_attack_resistant', UNAVAILABLE))}",
                f"Dual hash chaining: {self._display(consensus.get('dual_hash_chaining', UNAVAILABLE))}",
                f"Forward majority control: {self._display(consensus.get('protects_against_forward_majority_control', consensus.get('forward_majority_control', UNAVAILABLE)))}",
            ])
        elif section_key == "validation":
            fl = meta("fl_validation")
            adv = meta("adversarial_validation")
            summary = "FL/adversarial validation is prototype-only; general claims disabled"
            details = "\n".join([
                f"FL level: {fl.get('fl_validation_level', UNAVAILABLE)}",
                f"Byzantine robustness claim: {self._display(fl.get('supports_byzantine_robustness_claim', UNAVAILABLE))}",
                f"Adversarial level: {adv.get('adversarial_validation_level', UNAVAILABLE)}",
                f"Detection rate headline: {self._display(adv.get('detection_rate_headline_allowed', UNAVAILABLE))}",
                f"Known triggers: {self._display(adv.get('known_trivial_triggers', UNAVAILABLE))}",
            ])
        elif section_key == "reviewer":
            audit = meta("reviewer_audit")
            summary = "Reviewer audit: corrected but requires new experiments"
            details = "\n".join([
                f"Paper status: {audit.get('paper_ready_claim_status', UNAVAILABLE)}",
                f"Full PQ claim: {self._display(audit.get('full_post_quantum_security_claim', UNAVAILABLE))}",
                f"51% attack resistance claim: {self._display(audit.get('majority_attack_resistance_claim', UNAVAILABLE))}",
                f"No 100% detection claim: {self._display(audit.get('general_100_percent_detection_claim', UNAVAILABLE))}",
                f"Secure aggregation claim: {self._display(audit.get('secure_aggregation_claim', UNAVAILABLE))}",
            ])
        else:
            complexity = meta("complexity_boundary")
            contribution = meta("contribution_boundary")
            summary = "Complexity and contribution are component-bounded, not whole-system O(n)"
            details = "\n".join([
                f"Overall: {complexity.get('overall_complexity_claim', UNAVAILABLE)}",
                f"Full system O(n): {self._display(complexity.get('full_system_o_n_claim', UNAVAILABLE))}",
                f"Full mesh volume: {complexity.get('naive_full_mesh_network_volume', UNAVAILABLE)}",
                f"New cryptographic primitive: {self._display(contribution.get('claims_new_cryptographic_primitive', UNAVAILABLE))}",
                f"Contribution type: {contribution.get('contribution_type', UNAVAILABLE)}",
            ])
        return summary, details

    def _render_camera(self, data: Dict[str, Any]):
        point = data.get("camera_status", {})
        self._set_badge("camera", point.get("status", "unavailable"))
        if point.get("status") != "ok" and self._camera_photo is None:
            self.camera_label.configure(text="Camera Not Connected", image="", fg=C["orange"])

    def _render_speed_meter(self, data: Dict[str, Any]):
        self._set_badge("speed", data.get("vehicle_overview", {}).get("telemetry", {}).get("status", "unavailable"))
        canvas = self.speed_canvas
        canvas.delete("all")
        w = int(canvas.winfo_width()) if canvas.winfo_width() > 10 else 320
        h = int(canvas.winfo_height()) if canvas.winfo_height() > 10 else 180
        telemetry = self._point_value(data.get("vehicle_overview", {}).get("telemetry", {}), {})
        speed = self._as_float(self._first_value(telemetry, ("speed", "speed_kmh")) if isinstance(telemetry, dict) else None)
        cx, cy = w / 2, h * 0.82
        radius = min(w * 0.42, h * 0.70)
        canvas.create_arc(cx - radius, cy - radius, cx + radius, cy + radius, start=20, extent=140, style="arc", outline=C["border"], width=14)
        for tick in range(0, 181, 30):
            angle = math.radians(200 - (tick / 180.0) * 140)
            x1 = cx + (radius - 16) * math.cos(angle)
            y1 = cy - (radius - 16) * math.sin(angle)
            x2 = cx + radius * math.cos(angle)
            y2 = cy - radius * math.sin(angle)
            canvas.create_line(x1, y1, x2, y2, fill=C["cyan_dim"], width=2)
        if speed is None:
            canvas.create_text(cx, h * 0.48, text="Speed Unavailable", fill=C["orange"], font=self.f_head)
            return
        bounded = max(0.0, min(180.0, speed))
        extent = (bounded / 180.0) * 140.0
        canvas.create_arc(cx - radius, cy - radius, cx + radius, cy + radius, start=200 - extent, extent=extent, style="arc", outline=C["cyan"], width=14)
        needle_angle = math.radians(200 - extent)
        nx = cx + (radius - 28) * math.cos(needle_angle)
        ny = cy - (radius - 28) * math.sin(needle_angle)
        canvas.create_line(cx, cy, nx, ny, fill=C["red"] if speed >= 120 else C["green"], width=3)
        canvas.create_oval(cx - 5, cy - 5, cx + 5, cy + 5, fill=C["text"], outline="")
        canvas.create_text(cx, h * 0.48, text=f"{speed:.1f}", fill=C["text"], font=self.f_big)
        canvas.create_text(cx, h * 0.66, text="km/h", fill=C["dim"], font=self.f_small)

    def _render_road_scene(self, data: Dict[str, Any]):
        self._set_badge("road", "ok")
        canvas = self.road_canvas
        canvas.delete("all")
        w = int(canvas.winfo_width()) if canvas.winfo_width() > 10 else 640
        h = int(canvas.winfo_height()) if canvas.winfo_height() > 10 else 240
        telemetry = self._point_value(data.get("vehicle_overview", {}).get("telemetry", {}), {})
        if not isinstance(telemetry, dict) or not telemetry:
            canvas.create_text(w / 2, h / 2, text="Road Scene Unavailable", fill=C["orange"], font=self.f_head)
            self._set_badge("road", "unavailable")
            return
        canvas.create_rectangle(0, h * 0.20, w, h * 0.80, fill="#111f2a", outline="")
        for y in (h * 0.36, h * 0.50, h * 0.64):
            canvas.create_line(16, y, w - 16, y, fill="#314655", dash=(12, 9))
        speed = self._first_value(telemetry, ("speed", "speed_kmh"), UNAVAILABLE)
        heading = self._first_value(telemetry, ("heading", "steering_angle"), UNAVAILABLE)
        lane = self._first_value(telemetry, ("lane",), UNAVAILABLE)
        ego_x, ego_y = w * 0.22, h * 0.50
        self._draw_vehicle_marker(canvas, ego_x, ego_y, C["cyan"], f"EGO {self._display(speed)} km/h\nlane {lane}\nheading {self._display(heading)}")
        peers = self._point_value(data.get("v2x_peers", {}), [])
        rendered_peer_count = 0
        if isinstance(peers, list):
            for peer in peers:
                if not isinstance(peer, dict):
                    continue
                position = self._peer_road_position(peer, w, h)
                if position is None:
                    continue
                px, py, distance = position
                label = f"{peer.get('peer_id', peer.get('id', 'peer'))}\n{self._display(peer.get('speed', UNAVAILABLE))} km/h\n{self._display(distance)} m"
                self._draw_vehicle_marker(canvas, px, py, C["green"], label)
                rendered_peer_count += 1
        if isinstance(peers, list) and peers and rendered_peer_count == 0:
            canvas.create_text(w * 0.72, h * 0.22, text="Peer position unavailable", fill=C["orange"], font=self.f_small)
        detections = self._point_value(data.get("object_detection", {}), [])
        rendered_detection_count = 0
        if isinstance(detections, list):
            for det in detections:
                if not isinstance(det, dict):
                    continue
                position = self._detection_road_position(det, w, h)
                if position is None:
                    continue
                ox, oy = position
                cls = det.get("class", det.get("object_class", "object"))
                dist = det.get("distance_m", UNAVAILABLE)
                canvas.create_rectangle(ox - 12, oy - 18, ox + 12, oy + 18, outline=C["orange"], width=2)
                canvas.create_text(ox, oy + 30, text=f"{cls}\n{self._display(dist)} m", fill=C["orange"], font=self.f_small)
                rendered_detection_count += 1
        if isinstance(detections, list) and detections and rendered_detection_count == 0:
            canvas.create_text(w * 0.72, h * 0.78, text="Object position unavailable", fill=C["orange"], font=self.f_small)
        if bool(telemetry.get("emergency_brake_active", False)):
            canvas.create_text(w - 18, 18, text="collision warning", fill=C["red"], anchor="ne", font=self.f_head)

    def _draw_vehicle_marker(self, canvas: tk.Canvas, x: float, y: float, color: str, label: str):
        canvas.create_polygon(x, y - 16, x + 28, y, x, y + 16, x - 10, y, fill=color, outline="")
        canvas.create_text(x, y + 34, text=label, fill=color, font=self.f_small)

    def _peer_road_position(self, peer: Dict[str, Any], w: int, h: int) -> Optional[tuple]:
        rel_x = self._as_float(self._first_value(peer, ("relative_x", "rel_x", "x_m", "x")))
        rel_y = self._as_float(self._first_value(peer, ("relative_y", "rel_y", "y_m", "y")))
        if rel_x is not None and rel_y is not None:
            px = w * 0.22 + max(-80.0, min(160.0, rel_x)) / 160.0 * (w * 0.68)
            py = h * 0.50 - max(-24.0, min(24.0, rel_y)) / 24.0 * (h * 0.26)
            return px, py, math.hypot(rel_x, rel_y)

        distance = self._as_float(self._first_value(peer, ("relative_distance", "distance", "distance_m")))
        heading = self._as_float(self._first_value(peer, ("relative_heading", "heading", "bearing")))
        if distance is None or heading is None:
            return None
        rel = min(1.0, max(0.0, distance / 160.0))
        lateral = math.sin(math.radians(heading))
        px = w * (0.30 + rel * 0.62)
        py = h * (0.50 - max(-1.0, min(1.0, lateral)) * 0.24)
        return px, py, distance

    def _detection_road_position(self, detection: Dict[str, Any], w: int, h: int) -> Optional[tuple]:
        bbox = detection.get("bbox")
        if isinstance(bbox, (list, tuple)) and len(bbox) >= 4:
            x, y, bw, bh = (self._as_float(v) for v in bbox[:4])
            if None not in (x, y, bw, bh):
                return w * min(1.0, max(0.0, (x + bw / 2.0) / 720.0)), h * min(1.0, max(0.0, (y + bh) / 480.0))

        distance = self._as_float(self._first_value(detection, ("distance_m", "relative_distance", "distance")))
        angle = self._as_float(self._first_value(detection, ("angle", "relative_heading", "bearing"), 0.0))
        if distance is None:
            return None
        rel = min(1.0, max(0.0, distance / 100.0))
        ox = w * (0.34 + rel * 0.58)
        oy = h * (0.50 - math.sin(math.radians(angle or 0.0)) * 0.24)
        return ox, oy

    def _render_radar(self, data: Dict[str, Any]):
        canvas = self.radar_canvas
        canvas.delete("all")
        peers = self._point_value(data.get("v2x_peers", {}), [])
        self._set_badge("radar", data.get("v2x_peers", {}).get("status", "unavailable"))
        w = int(canvas.winfo_width()) if canvas.winfo_width() > 10 else 440
        h = int(canvas.winfo_height()) if canvas.winfo_height() > 10 else 220
        cx, cy = w / 2, h / 2
        r = min(w, h) / 2 - 16
        for factor in (1.0, 0.66, 0.33):
            rr = r * factor
            canvas.create_oval(cx - rr, cy - rr, cx + rr, cy + rr, outline=C["cyan_dim"])
        canvas.create_oval(cx - 5, cy - 5, cx + 5, cy + 5, fill=C["cyan"], outline="")
        if not peers:
            canvas.create_text(cx, cy + 28, text="No V2X Peer Data", fill=C["dim"], font=self.f_body)
            return
        rendered_peer_count = 0
        for peer in peers:
            if not isinstance(peer, dict):
                continue
            distance = self._as_float(self._first_value(peer, ("relative_distance", "distance", "distance_m")))
            heading = self._as_float(self._first_value(peer, ("relative_heading", "heading", "bearing")))
            if distance is None or heading is None:
                continue
            rr = min(r, (distance / 160.0) * r)
            angle = math.radians(heading)
            x = cx + rr * math.cos(angle)
            y = cy - rr * math.sin(angle)
            canvas.create_oval(x - 5, y - 5, x + 5, y + 5, fill=C["green"], outline="")
            canvas.create_text(x, y - 12, text=str(peer.get("peer_id", peer.get("id", "peer"))), fill=C["green"], font=self.f_small)
            rendered_peer_count += 1
        if rendered_peer_count == 0:
            canvas.create_text(cx, cy + 28, text="V2X Peer Position Unavailable", fill=C["orange"], font=self.f_body)

    def _render_anomaly(self, data: Dict[str, Any]):
        adv = self._metadata_value(data.get("adversarial_validation", {}))
        score = adv.get("score")
        history = adv.get("history")
        threshold = adv.get("threshold")
        state = adv.get("state")
        canvas = self.anomaly_canvas
        canvas.delete("all")
        w = int(canvas.winfo_width()) if canvas.winfo_width() > 10 else 320
        h = int(canvas.winfo_height()) if canvas.winfo_height() > 10 else 180
        if score is None and history is None and threshold is None and state is None:
            self._set_badge("anomaly", "no_data")
            canvas.create_text(w / 2, h / 2, text="No Anomaly Data", fill=C["dim"], font=self.f_body)
            return
        self._set_badge("anomaly", "ok")
        values = history if isinstance(history, list) else [score]
        values = [self._as_float(v) for v in values]
        values = [v for v in values if v is not None]
        if not values:
            canvas.create_text(w / 2, h / 2, text="No Anomaly Data", fill=C["dim"], font=self.f_body)
            return
        pad = 18
        canvas.create_rectangle(pad, pad, w - pad, h - pad, outline=C["border"])
        points = []
        for index, value in enumerate(values[-80:]):
            x = pad + (w - 2 * pad) * (index / max(1, min(len(values), 80) - 1))
            y = h - pad - max(0.0, min(1.0, value)) * (h - 2 * pad)
            points.extend([x, y])
        if len(points) >= 4:
            canvas.create_line(*points, fill=C["orange"], width=2, smooth=True)
        if threshold is not None and self._as_float(threshold) is not None:
            ty = h - pad - max(0.0, min(1.0, float(threshold))) * (h - 2 * pad)
            canvas.create_line(pad, ty, w - pad, ty, fill=C["red"], dash=(6, 5))
        canvas.create_text(pad + 4, pad + 4, text=f"score {self._display(score)} | {self._display(state)}", fill=C["text"], anchor="nw", font=self.f_small)

    def _render_timeline(self, data: Dict[str, Any]):
        chain = getattr(self.blockchain, "chain", []) or []
        lines = []
        for block in list(chain)[-8:]:
            idx = getattr(block, "index", None)
            ts = getattr(block, "timestamp", "")
            event = getattr(block, "event_data", "")
            if isinstance(block, dict):
                idx = block.get("index")
                ts = block.get("timestamp", "")
                event = block.get("event_data", "")
            lines.append(f"[{self._display(idx)}] {str(ts)[11:19]} {event or 'event unavailable'}")
        if not lines:
            telemetry = self._point_value(data.get("vehicle_overview", {}).get("telemetry", {}), {})
            lines = ["No committed events"] if not telemetry else [f"Telemetry source: {data.get('vehicle_overview', {}).get('telemetry', {}).get('source', UNAVAILABLE)}"]
        self.timeline_text.configure(state="normal")
        self.timeline_text.delete("1.0", "end")
        self.timeline_text.insert("end", "\n".join(lines))
        self.timeline_text.configure(state="disabled")
        self._set_badge("timeline", "ok" if lines else "no_data")

    def _render_warning_summary(self, data: Dict[str, Any]):
        lines = []
        for section_key, _title, _sources in self.METADATA_SECTIONS:
            summary, _details = self._metadata_section_text(section_key, data)
            if summary and summary != UNAVAILABLE:
                lines.append(f"- {summary}")
        self.warnings_text.configure(text="\n".join(lines[:8]) if lines else NO_DATA, fg=C["orange"] if lines else C["dim"])
        self._set_badge("warnings", "warning" if lines else "no_data")

    def _render_health(self, data: Dict[str, Any]):
        connection = self._point_value(data.get("connection_status", {}), NOT_CONNECTED)
        peers = self._point_value(data.get("v2x_peers", {}), [])
        detections = self._point_value(data.get("object_detection", {}), [])
        camera = data.get("camera_status", {}).get("status", "unavailable")
        lines = [
            f"Connection: {connection}",
            f"Telemetry: {data.get('vehicle_overview', {}).get('telemetry', {}).get('status', 'unavailable')}",
            f"Camera: {camera}",
            f"V2X peers: {len(peers) if isinstance(peers, list) else 0}",
            f"Detections: {len(detections) if isinstance(detections, list) else 0}",
            f"Updated: {data.get('updated_at', UNAVAILABLE)}",
        ]
        self.health_text.configure(text="\n".join(lines), fg=C["text"])
        self._set_badge("health", "ok" if connection == "Connected" else "warning" if connection == "Partial" else "error")

    def _update_ui(self):
        try:
            self._process_camera()
            self.manual_refresh()
        except Exception as exc:
            now = time.time()
            if now - self._last_ui_error_log_ts > 2.0:
                logger.exception("Dashboard update failed: %s", exc)
                self._last_ui_error_log_ts = now
        self.after(self.refresh_interval_ms, self._update_ui)

    def on_closing(self):
        try:
            if hasattr(self.blockchain, "save"):
                self.blockchain.save()
        except Exception as exc:
            logger.exception("Failed to save blockchain on close: %s", exc)
        if self.cap is not None and hasattr(self.cap, "isOpened") and self.cap.isOpened():
            self.cap.release()
        self.destroy()


if __name__ == "__main__":
    app = SmartCarDashboard()
    app.protocol("WM_DELETE_WINDOW", app.on_closing)
    style = ttk.Style()
    style.theme_use("clam")
    app.mainloop()
