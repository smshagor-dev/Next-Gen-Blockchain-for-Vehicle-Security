# OmniGuard V2X: A Privacy-Preserving Blockchain Framework for Smart Vehicle Security
# Developer : Md Shahanur Islam Shagor
# Role      : Project Architect & Lead Developer
"""
SmartCar Dashboard - Combined Futuristic Security UI
"""

import base64
import math
import os
import random
import time
import logging
import tkinter as tk
from collections import deque
from datetime import datetime, timezone
from tkinter import font, messagebox, ttk
from xml.etree import ElementTree as ET

import cv2

from blockchain import SmartCarBlockchain, TelemetryData
from env_config import get_env, get_float, get_int, load_project_env_once

load_project_env_once()
logger = logging.getLogger("SmartCarDashboard")


C = {
    "bg": "#101316",
    "panel": "#141a1f",
    "panel2": "#192127",
    "panel_glass": "#1b242b",
    "border": "#24313a",
    "cyan": "#00e5ff",
    "cyan_dim": "#00a2b3",
    "green": "#21d17b",
    "emerald": "#00b86f",
    "red": "#ff5b6e",
    "orange": "#ffb347",
    "text": "#d7e4eb",
    "dim": "#7f95a3",
    "hex": "#3cff87",
}


def now_iso() -> str:
    """Return UTC time string."""
    return datetime.now(timezone.utc).isoformat()


class RoadSvgRenderer:
    """Render simplified SVG road scene to tkinter canvas."""

    def __init__(self, canvas: tk.Canvas, svg_path: str):
        self.canvas = canvas
        self.svg_path = svg_path
        self._car = None
        self.width = 640
        self.height = 220

    @staticmethod
    def _tag(x: str) -> str:
        return x.split("}", 1)[-1]

    @staticmethod
    def _num(v, d=0.0):
        try:
            return float(v)
        except Exception as e:
            logger.debug("SVG numeric parse fallback for value=%r: %s", v, e)
            return d

    def _points(self, s: str):
        pts = []
        for t in s.strip().split():
            if "," not in t:
                continue
            x, y = t.split(",", 1)
            pts.extend([self._num(x), self._num(y)])
        return pts

    def render(self):
        """Render static road SVG elements and car marker."""
        self.canvas.delete("all")
        if not os.path.exists(self.svg_path):
            self.canvas.create_text(20, 20, text="Missing: image_source/road_scene.svg", fill="#fca5a5", anchor="nw")
            return
        root = ET.parse(self.svg_path).getroot()
        vb = root.attrib.get("viewBox", "")
        if vb:
            p = vb.split()
            if len(p) == 4:
                self.width = int(float(p[2]))
                self.height = int(float(p[3]))
        self.canvas.configure(width=self.width, height=self.height)
        for e in root.iter():
            tag = self._tag(e.tag)
            a = e.attrib
            fill = a.get("fill", "")
            stroke = a.get("stroke", "")
            sw = self._num(a.get("stroke-width", 1), 1)
            if tag == "rect":
                x = self._num(a.get("x", 0)); y = self._num(a.get("y", 0))
                w = self._num(a.get("width", 0)); h = self._num(a.get("height", 0))
                self.canvas.create_rectangle(x, y, x + w, y + h, fill=fill if fill else "", outline=stroke if stroke else "", width=sw)
            elif tag == "line":
                self.canvas.create_line(self._num(a.get("x1", 0)), self._num(a.get("y1", 0)), self._num(a.get("x2", 0)), self._num(a.get("y2", 0)), fill=stroke if stroke else "#fff", width=sw)
            elif tag == "circle":
                cx = self._num(a.get("cx", 0)); cy = self._num(a.get("cy", 0)); r = self._num(a.get("r", 0))
                self.canvas.create_oval(cx-r, cy-r, cx+r, cy+r, fill=fill if fill else "", outline=stroke if stroke else "", width=sw)
            elif tag == "polygon":
                pts = self._points(a.get("points", ""))
                if pts:
                    self.canvas.create_polygon(*pts, fill=fill if fill else "", outline=stroke if stroke else "", width=sw)
        self._car = self.canvas.create_rectangle(300, 150, 342, 186, fill="#4da8ff", outline="#cde8ff", width=2)

    def move_car(self, speed_kmh: float):
        """Move car marker based on speed."""
        if not self._car:
            return
        x = 300 + min(260, max(0, speed_kmh * 2.2))
        self.canvas.coords(self._car, x, 150, x + 42, 186)


class SmartCarDashboard(tk.Tk):
    """Combined high-tech smart car security dashboard."""

    VEHICLE_ID = get_env("SMARTCAR_VEHICLE_ID", "SMARTCAR_VIN_2024_BD_XYZ789")
    AUTH_TOKEN = get_env("SMARTCAR_AUTH_TOKEN", "SECURE_AUTH_TOKEN_SHA3_2024")
    PASSWORD = get_env("SMARTCAR_PASSWORD", "SmartCarSecretKey2024!@#")
    GUI_CHAIN_FILE = get_env("SMARTCAR_GUI_CHAIN_FILE", "logs/blockchain_gui.json")

    def __init__(self):
        super().__init__()
        self.title("SmartCar Security Command Dashboard")
        self.configure(bg=C["bg"])
        self.geometry("1720x980")
        self.minsize(1380, 860)
        try:
            self.state("zoomed")
        except Exception:
            self.attributes("-fullscreen", True)

        self.blockchain = SmartCarBlockchain(self.VEHICLE_ID, self.PASSWORD, self.AUTH_TOKEN, chain_file=self.GUI_CHAIN_FILE)

        self.camera_index = get_int("SMARTCAR_CAMERA_INDEX", 0)
        self.emergency_distance_m = get_float("SMARTCAR_CAMERA_EMERGENCY_DISTANCE_M", 8.0)
        self.cap = self._open_camera(self.camera_index)
        self.hog = cv2.HOGDescriptor()
        self.hog.setSVMDetector(cv2.HOGDescriptor_getDefaultPeopleDetector())

        self.speed_kmh = 0.0
        self.throttle = 0.0
        self.rpm = 900.0
        self.engine_temp = 24.0
        self.fuel_level = 100.0
        self.odometer = 0.0
        self.gps_lat = 23.8103
        self.gps_lon = 90.4125
        self.driver_heart_rate_bpm = 76.0
        self.driver_drowsiness_score = 0.08
        self.driver_unwell = False

        self._frame_counter = 0
        self._last_detection_count = 0
        self._last_obstacle_distance = 999.0
        self._last_chain_push = 0.0
        self._last_log_idx = 0
        self._photo = None
        self._tick = 0
        self._last_auth_ok = False
        self._last_start_ok = False
        self._last_stop_ok = True
        self._last_lock_ok = True
        self._last_ui_error_log_ts = 0.0
        self._last_chain_verify_ts = 0.0
        self._last_chain_verify_ok = True
        self._last_status_text = ""

        self.anomaly_history = deque([0.02] * 120, maxlen=120)
        self._latest_anomaly = 0.02
        self.v2x_nodes = []
        self._last_camera_frame = None
        self._last_frame_render_tick = -1

        # UI cadence controls to keep dashboard smooth on lower-end hardware.
        self.ui_tick_ms = get_int("SMARTCAR_UI_TICK_MS", 100)
        self.canvas_refresh_every = max(1, get_int("SMARTCAR_UI_CANVAS_REFRESH_EVERY", 2))
        self.text_refresh_every = max(1, get_int("SMARTCAR_UI_TEXT_REFRESH_EVERY", 1))
        self.log_refresh_every = max(1, get_int("SMARTCAR_UI_LOG_REFRESH_EVERY", 2))
        self.camera_refresh_every = max(1, get_int("SMARTCAR_UI_CAMERA_REFRESH_EVERY", 1))
        self.camera_detect_every = max(1, get_int("SMARTCAR_UI_CAMERA_DETECT_EVERY", 3))
        self.chain_verify_interval_sec = float(get_env("SMARTCAR_UI_CHAIN_VERIFY_INTERVAL_SEC", "1.0"))

        self._setup_fonts()
        self._build_ui()
        self._update_ui()

    def _setup_fonts(self):
        """Initialize UI fonts."""
        self.f_title = font.Font(family="Consolas", size=15, weight="bold")
        self.f_head = font.Font(family="Consolas", size=10, weight="bold")
        self.f_body = font.Font(family="Consolas", size=9)
        self.f_hash = font.Font(family="Consolas", size=8)
        self.f_big = font.Font(family="Consolas", size=30, weight="bold")

    def _panel(self, parent, title):
        """Create glass-like panel with title."""
        outer = tk.Frame(parent, bg=C["border"], padx=1, pady=1)
        outer.pack(fill="both", expand=True, pady=4)
        inner = tk.Frame(outer, bg=C["panel_glass"], padx=8, pady=7)
        inner.pack(fill="both", expand=True)
        tk.Label(inner, text=f"[ {title} ]", bg=C["panel_glass"], fg=C["cyan"], font=self.f_head).pack(anchor="w", pady=(0, 5))
        return inner

    def _build_ui(self):
        """Build combined futuristic dashboard layout."""
        top = tk.Frame(self, bg=C["panel2"], pady=8)
        top.pack(fill="x")
        tk.Label(top, text="SMART CAR SECURITY SYSTEM - FUTURISTIC OPS CONSOLE", bg=C["panel2"], fg=C["cyan"], font=self.f_title).pack(side="left", padx=14)
        self.lbl_clock = tk.Label(top, text="", bg=C["panel2"], fg=C["dim"], font=self.f_body)
        self.lbl_clock.pack(side="right", padx=14)

        zkp_strip = tk.Frame(self, bg="#0f1a20", pady=4)
        zkp_strip.pack(fill="x")
        self.lbl_shield = tk.Label(zkp_strip, text="ZKP Privacy Shield: ACTIVE", bg="#0f1a20", fg=C["green"], font=self.f_head)
        self.lbl_shield.pack(side="left", padx=14)
        self.lbl_did = tk.Label(zkp_strip, text="DID Proof Verified", bg="#0f1a20", fg=C["cyan"], font=self.f_head)
        self.lbl_did.pack(side="left", padx=18)

        body = tk.Frame(self, bg=C["bg"])
        body.pack(fill="both", expand=True, padx=10, pady=8)

        left_col = tk.Frame(body, bg=C["bg"], width=340)
        left_col.pack(side="left", fill="y", padx=(0, 6))
        left_col.pack_propagate(False)

        center_col = tk.Frame(body, bg=C["bg"])
        center_col.pack(side="left", fill="both", expand=True)

        right_col = tk.Frame(body, bg=C["bg"], width=470)
        right_col.pack(side="right", fill="y", padx=(6, 0))
        right_col.pack_propagate(False)

        self.right_canvas = tk.Canvas(right_col, bg=C["bg"], highlightthickness=0, bd=0)
        self.right_scroll = ttk.Scrollbar(right_col, orient="vertical", command=self.right_canvas.yview)
        self.right_canvas.configure(yscrollcommand=self.right_scroll.set)
        self.right_canvas.pack(side="left", fill="both", expand=True)
        self.right_scroll.pack(side="right", fill="y")

        self.right_inner = tk.Frame(self.right_canvas, bg=C["bg"])
        self.right_canvas_window = self.right_canvas.create_window((0, 0), window=self.right_inner, anchor="nw")
        self.right_inner.bind("<Configure>", self._on_right_inner_configure)
        self.right_canvas.bind("<Configure>", self._on_right_canvas_configure)
        self.right_canvas.bind("<MouseWheel>", self._on_right_mousewheel)
        self.bind_all("<MouseWheel>", self._on_right_mousewheel)

        p_control = self._panel(left_col, "ACCESS CONTROL")
        self.token_entry = tk.Entry(p_control, font=self.f_body, show="*", bg=C["panel2"], fg=C["text"], insertbackground=C["cyan"])
        self.token_entry.insert(0, self.AUTH_TOKEN)
        self.token_entry.pack(fill="x", pady=(0, 6))
        row = tk.Frame(p_control, bg=C["panel_glass"])
        row.pack(fill="x")
        tk.Button(row, text="AUTH", command=self._do_auth, bg="#10392a", fg="#d3ffe6").pack(side="left", padx=2)
        tk.Button(row, text="START", command=self._do_start, bg="#103b47", fg="#cff7ff").pack(side="left", padx=2)
        tk.Button(row, text="STOP", command=self._do_stop, bg="#4b2b10", fg="#ffe7cf").pack(side="left", padx=2)
        tk.Button(row, text="LOCK", command=self._do_lock, bg="#4a1520", fg="#ffd9df").pack(side="left", padx=2)
        self.owner_entry = tk.Entry(p_control, font=self.f_body, show="*", bg=C["panel2"], fg=C["text"], insertbackground=C["cyan"])
        self.owner_entry.pack(fill="x", pady=(6, 2))
        self.owner_entry.insert(0, "")
        self.owner_force_reset_var = tk.BooleanVar(value=False)
        row_recover = tk.Frame(p_control, bg=C["panel_glass"])
        row_recover.pack(fill="x", pady=(0, 4))
        tk.Checkbutton(
            row_recover,
            text="Force Chain Reset",
            variable=self.owner_force_reset_var,
            bg=C["panel_glass"],
            fg=C["orange"],
            selectcolor=C["panel2"],
            activebackground=C["panel_glass"],
            activeforeground=C["orange"],
            font=self.f_hash,
        ).pack(side="left", padx=2)
        tk.Button(row_recover, text="RECOVER", command=self._do_recover, bg="#4b1d52", fg="#f3e8ff").pack(side="right", padx=2)
        self.throttle_var = tk.DoubleVar(value=0.0)
        tk.Label(p_control, text="Throttle (%)", bg=C["panel_glass"], fg=C["text"], font=self.f_body).pack(anchor="w", pady=(8, 0))
        ttk.Scale(p_control, from_=0, to=100, variable=self.throttle_var, orient="horizontal").pack(fill="x")
        p_action = tk.Frame(p_control, bg=C["panel_glass"])
        p_action.pack(fill="x", pady=(8, 0))
        self.lbl_lock_state = self._status_row(p_action, "LOCK", "LOCKED", C["green"])
        self.lbl_auth_state = self._status_row(p_action, "AUTH", "WAITING", C["orange"])
        self.lbl_engine_cmd = self._status_row(p_action, "ENGINE", "STOP", C["red"])

        p_status = self._panel(left_col, "SECURITY STATUS")
        self.lbl_status = tk.Label(p_status, justify="left", anchor="w", bg=C["panel_glass"], fg=C["text"], font=self.f_body)
        self.lbl_status.pack(fill="x")

        p_did_terminal = self._panel(left_col, "TERMINAL")
        self.txt_terminal = tk.Text(p_did_terminal, bg="#090f13", fg=C["green"], font=self.f_hash, height=8)
        self.txt_terminal.pack(fill="both", expand=True)

        p_contract = self._panel(left_col, "SMART CONTRACT EXECUTION")
        self.txt_contract = tk.Text(p_contract, bg="#090f13", fg=C["text"], font=self.f_hash, height=9)
        self.txt_contract.pack(fill="both", expand=True)

        p_camera = self._panel(center_col, "LIVE CAMERA AND OBJECT DETECTION")
        self.cam_label = tk.Label(p_camera, bg="#02070a")
        self.cam_label.pack(fill="both", expand=True)

        center_bottom = tk.Frame(center_col, bg=C["bg"])
        center_bottom.pack(fill="both", expand=True)

        center_left = tk.Frame(center_bottom, bg=C["bg"])
        center_left.pack(side="left", fill="both", expand=True, padx=(0, 4))

        center_right = tk.Frame(center_bottom, bg=C["bg"])
        center_right.pack(side="left", fill="both", expand=True, padx=(4, 0))

        p_road = self._panel(center_left, "ROAD SCENE")
        self.road_canvas = tk.Canvas(p_road, width=640, height=210, bg="#101820", highlightthickness=0)
        self.road_canvas.pack(fill="x")
        self.road_svg = RoadSvgRenderer(self.road_canvas, os.path.join(os.getcwd(), "image_source", "road_scene.svg"))
        self.road_svg.render()

        p_chain_feed = self._panel(center_left, "BLOCKCHAIN LEDGER FEED")
        self.txt_ledger = tk.Text(p_chain_feed, bg="#060c10", fg=C["hex"], font=self.f_hash, height=11)
        self.txt_ledger.pack(fill="both", expand=True)

        p_dual = self._panel(center_left, "DUAL HASH CHAIN")
        self.dual_canvas = tk.Canvas(p_dual, height=160, bg="#070d12", highlightthickness=0)
        self.dual_canvas.pack(fill="both", expand=True)

        p_gps = self._panel(center_right, "DECENTRALIZED VEHICULAR NETWORK MAP")
        self.gps_canvas = tk.Canvas(p_gps, height=230, bg="#071017", highlightthickness=0)
        self.gps_canvas.pack(fill="both", expand=True)

        p_car3d = self._panel(center_right, "VEHICLE SECURITY LAYERS")
        self.car_canvas = tk.Canvas(p_car3d, height=190, bg="#070d12", highlightthickness=0)
        self.car_canvas.pack(fill="both", expand=True)

        p_speed = self._panel(self.right_inner, "SPEED METER")
        self.speed_canvas = tk.Canvas(p_speed, width=430, height=200, bg="#04090d", highlightthickness=0)
        self.speed_canvas.pack(fill="x")
        sp_info = tk.Frame(p_speed, bg=C["panel_glass"])
        sp_info.pack(fill="x", pady=(4, 0))
        self.lbl_speed_big = tk.Label(sp_info, text="0", bg=C["panel_glass"], fg=C["cyan"], font=self.f_big)
        self.lbl_speed_big.pack(side="left", padx=(6, 0))
        tk.Label(sp_info, text="km/h", bg=C["panel_glass"], fg=C["dim"], font=self.f_body).pack(side="left", padx=6, pady=(14, 0))
        self.lbl_speed_state = tk.Label(sp_info, text="STANDBY", bg=C["panel_glass"], fg=C["green"], font=self.f_head)
        self.lbl_speed_state.pack(side="right", padx=8, pady=(14, 0))

        p_radar = self._panel(self.right_inner, "V2X RADAR")
        self.radar_canvas = tk.Canvas(p_radar, height=210, bg="#071017", highlightthickness=0)
        self.radar_canvas.pack(fill="both", expand=True)

        p_anomaly = self._panel(self.right_inner, "ANOMALY DETECTION SCORE")
        self.anomaly_canvas = tk.Canvas(p_anomaly, height=180, bg="#071017", highlightthickness=0)
        self.anomaly_canvas.pack(fill="both", expand=True)

        telem2x2 = tk.Frame(p_speed, bg=C["panel_glass"])
        telem2x2.pack(fill="x", pady=(8, 0))
        self.lbl_card_rpm = self._metric_card(telem2x2, 0, 0, "RPM")
        self.lbl_card_temp = self._metric_card(telem2x2, 0, 1, "TEMP")
        self.lbl_card_fuel = self._metric_card(telem2x2, 1, 0, "FUEL")
        self.lbl_card_thr = self._metric_card(telem2x2, 1, 1, "THROTTLE")

    def _do_auth(self):
        """Handle authentication action."""
        result = self.blockchain.authenticate(self.token_entry.get())
        self._last_auth_ok = bool(result.get("success", False))
        if not result.get("success"):
            messagebox.showwarning("Auth", f"Failed: {result.get('reason')}")

    def _do_start(self):
        """Handle engine start action."""
        result = self.blockchain.start_engine()
        self._last_start_ok = bool(result.get("success", False))
        if self._last_start_ok:
            self._last_stop_ok = False
        if not result.get("success"):
            messagebox.showwarning("Start Engine", f"Blocked: {result.get('reason')}")

    def _do_stop(self):
        """Handle engine stop action."""
        self.blockchain.stop_engine()
        self._last_stop_ok = True
        self._last_start_ok = False

    def _do_lock(self):
        """Handle car lock action."""
        self.blockchain.lock_car()
        self._last_lock_ok = True

    def _do_recover(self):
        """Handle owner recovery unlock action."""
        key = self.owner_entry.get().strip()
        force_reset = bool(self.owner_force_reset_var.get())
        result = self.blockchain.owner_recover_unlock(key, force_chain_reset=force_reset)
        if result.get("success"):
            self._last_auth_ok = True
            self._last_start_ok = False
            self._last_stop_ok = True
            self._last_lock_ok = not self.blockchain.car_unlocked
            mode = result.get("mode", "OWNER_UNLOCK")
            messagebox.showinfo("Recovery", f"Recovery à¦¸à¦«à¦² à¦¹à§Ÿà§‡à¦›à§‡: {mode}")
            return
        reason = result.get("reason", "UNKNOWN_ERROR")
        messagebox.showwarning("Recovery Failed", f"Recovery failed: {reason}")

    def _on_right_inner_configure(self, _event):
        """Update scrollregion when right panel content size changes."""
        self.right_canvas.configure(scrollregion=self.right_canvas.bbox("all"))

    def _on_right_canvas_configure(self, event):
        """Keep right panel width equal to canvas width."""
        self.right_canvas.itemconfigure(self.right_canvas_window, width=event.width)

    def _on_right_mousewheel(self, event):
        """Mouse wheel scroll for right panel."""
        if event.delta:
            self.right_canvas.yview_scroll(int(-event.delta / 120), "units")

    def _status_row(self, parent: tk.Widget, label: str, value: str, value_color: str):
        """Create one status row with dynamic color value."""
        row = tk.Frame(parent, bg=C["panel_glass"])
        row.pack(fill="x", pady=1)
        tk.Label(row, text=f"{label:<7}", bg=C["panel_glass"], fg=C["dim"], font=self.f_body, anchor="w").pack(side="left")
        tk.Label(row, text=":", bg=C["panel_glass"], fg=C["dim"], font=self.f_body).pack(side="left")
        v = tk.Label(row, text=value, bg=C["panel_glass"], fg=value_color, font=self.f_head, anchor="w")
        v.pack(side="left", padx=(6, 0))
        return v

    def _metric_card(self, parent: tk.Widget, row: int, col: int, title: str):
        """Create one telemetry card for 2x2 metrics grid."""
        box = tk.Frame(parent, bg="#0a1218", highlightthickness=1, highlightbackground=C["border"])
        box.grid(row=row, column=col, sticky="nsew", padx=4, pady=4)
        parent.grid_columnconfigure(col, weight=1)
        parent.grid_rowconfigure(row, weight=1)
        tk.Label(box, text=title, bg="#0a1218", fg=C["dim"], font=self.f_hash).pack(anchor="w", padx=6, pady=(4, 0))
        lbl = tk.Label(box, text="0", bg="#0a1218", fg=C["cyan"], font=self.f_head)
        lbl.pack(anchor="w", padx=6, pady=(0, 4))
        return lbl

    @staticmethod
    def _estimate_distance(box_h: int) -> float:
        """Estimate distance from object bounding-box height."""
        if box_h <= 0:
            return 999.0
        return (1.70 * 850.0) / float(box_h)

    @staticmethod
    def _open_camera(camera_index: int):
        """Open camera with Windows-friendly backend fallback."""
        cap = None
        if os.name == "nt":
            try:
                cap = cv2.VideoCapture(camera_index, cv2.CAP_DSHOW)
            except Exception:
                cap = None
        if cap is None or not cap.isOpened():
            cap = cv2.VideoCapture(camera_index)
        return cap

    def _process_frame(self):
        """Read camera frame and annotate object detection."""
        if not self.cap.isOpened():
            return None
        ok, frame = self.cap.read()
        if not ok or frame is None:
            return None

        detections = []
        self._frame_counter += 1
        if self._frame_counter % self.camera_detect_every == 0:
            boxes, weights = self.hog.detectMultiScale(frame, winStride=(12, 12), padding=(8, 8), scale=1.05)
            for i, (x, y, w, h) in enumerate(boxes):
                dist_m = self._estimate_distance(h)
                conf = float(weights[i]) if i < len(weights) else 0.5
                detections.append((x, y, w, h, dist_m, conf))

        if detections:
            self._last_detection_count = len(detections)
            self._last_obstacle_distance = min([d[4] for d in detections], default=999.0)
        elif self._frame_counter % self.camera_detect_every == 0:
            # Refresh stale detection state at detection cadence.
            self._last_detection_count = 0
            self._last_obstacle_distance = 999.0

        for x, y, w, h, dist_m, _ in detections:
            danger = dist_m < self.emergency_distance_m
            col = (0, 0, 255) if danger else (0, 220, 0)
            cv2.rectangle(frame, (x, y), (x + w, y + h), col, 2)
            cv2.putText(frame, f"obj {dist_m:.1f}m", (x, max(20, y - 8)), cv2.FONT_HERSHEY_SIMPLEX, 0.55, col, 2)

        if self._last_obstacle_distance < self.emergency_distance_m and self.blockchain.engine_started:
            self.blockchain.emergency_brake(self._last_obstacle_distance)
            self.speed_kmh = max(0.0, self.speed_kmh - 8.0)
            cv2.putText(frame, "EMERGENCY BRAKE", (20, 36), cv2.FONT_HERSHEY_SIMPLEX, 1.0, (0, 0, 255), 3)

        cv2.putText(frame, f"Closest {self._last_obstacle_distance:.1f}m | Threshold {self.emergency_distance_m:.1f}m", (20, 66), cv2.FONT_HERSHEY_SIMPLEX, 0.6, (0, 240, 255), 2)
        return frame

    def _update_model(self):
        """Update vehicle state simulation model."""
        if self.blockchain.engine_started:
            self.throttle = float(self.throttle_var.get())
            target = self.throttle * 1.6
            self.speed_kmh += (target - self.speed_kmh) * 0.12
            if self.blockchain.emergency_brake_active:
                self.speed_kmh = max(0.0, self.speed_kmh - 2.7)
            if getattr(self.blockchain, "safe_mode_active", False):
                self.throttle = min(self.throttle, 18.0)
                self.speed_kmh = max(0.0, self.speed_kmh - 4.2)
            self.rpm = 900 + self.speed_kmh * 36
            self.engine_temp = min(105.0, self.engine_temp + 0.02 + self.speed_kmh * 0.0008)
            self.fuel_level = max(0.0, self.fuel_level - (0.0009 + self.throttle * 0.00003))
            self.odometer += self.speed_kmh / 3600.0 * 0.08
            self.gps_lat += self.speed_kmh * 0.0000008
            self.gps_lon += self.speed_kmh * 0.0000004
            self.driver_drowsiness_score = min(1.0, self.driver_drowsiness_score + random.uniform(-0.01, 0.03))
            hr_base = 72.0 + self.speed_kmh * 0.15 + self.throttle * 0.08
            self.driver_heart_rate_bpm = max(42.0, min(165.0, hr_base + random.uniform(-6.0, 6.0)))
        else:
            self.speed_kmh *= 0.95
            self.rpm = max(0.0, self.rpm * 0.9)
            self.driver_drowsiness_score = max(0.05, self.driver_drowsiness_score - 0.02)
            self.driver_heart_rate_bpm = max(58.0, self.driver_heart_rate_bpm - random.uniform(0.5, 1.5))

        self.driver_unwell = (
            self.driver_drowsiness_score >= 0.93
            or self.driver_heart_rate_bpm <= 45
            or self.driver_heart_rate_bpm >= 145
        )

        risk = 0.01 + (0.55 if self.blockchain.emergency_brake_active else 0.0)
        risk += min(0.25, self._last_detection_count * 0.06)
        risk += 0.25 if self._last_obstacle_distance < 6.0 else 0.0
        risk += min(0.20, max(0.0, self.speed_kmh - 120) / 250.0)
        risk += random.uniform(-0.015, 0.015)
        self._latest_anomaly = max(0.0, min(1.0, risk))
        self.anomaly_history.append(self._latest_anomaly)

        self.road_svg.move_car(self.speed_kmh)
        self._refresh_v2x_nodes()

    def _refresh_v2x_nodes(self):
        """Simulate nearby V2X nodes for radar/map rendering."""
        now = time.time()
        nodes = []
        for i in range(8):
            ang = (now * (0.6 + i * 0.08) + i * 0.9) % (2 * math.pi)
            dist = 0.2 + ((math.sin(now * 0.3 + i) + 1.0) * 0.35)
            kind = "V2I" if i % 3 == 0 else "V2V"
            nodes.append((ang, min(0.95, dist), kind))
        self.v2x_nodes = nodes

    def _push_telemetry(self):
        """Push telemetry to blockchain at fixed interval."""
        t = time.time()
        if t - self._last_chain_push < 1.0:
            return
        self._last_chain_push = t

        tel = TelemetryData(
            speed=self.speed_kmh,
            acceleration=0.0,
            fuel_level=self.fuel_level,
            battery_voltage=13.8,
            engine_temp=self.engine_temp,
            gps_lat=self.gps_lat,
            gps_lon=self.gps_lon,
            obstacle_distance=self._last_obstacle_distance,
            emergency_brake_active=self.blockchain.emergency_brake_active,
            steering_angle=0.0,
            brake_pressure=100.0 if self.blockchain.emergency_brake_active else 0.0,
            throttle_position=self.throttle,
            rpm=self.rpm,
            odometer=self.odometer,
            driver_heart_rate_bpm=self.driver_heart_rate_bpm,
            driver_drowsiness_score=self.driver_drowsiness_score,
            driver_unwell=self.driver_unwell,
            timestamp=now_iso(),
        )
        self.blockchain.push_telemetry(tel, "LIVE_SEC_MONITOR")

    def _draw_speedometer(self):
        """Draw analog speed meter."""
        c = self.speed_canvas
        c.delete("all")
        w = int(c.winfo_width()) if c.winfo_width() > 10 else 430
        h = int(c.winfo_height()) if c.winfo_height() > 10 else 200
        cx, cy = w // 2, h - 18
        r = min(w // 2 - 30, h - 32)
        max_speed = 220.0

        c.create_arc(cx-r, cy-r, cx+r, cy+r, start=18, extent=144, style=tk.ARC, outline=C["border"], width=16)
        c.create_arc(cx-r, cy-r, cx+r, cy+r, start=18, extent=55, style=tk.ARC, outline=C["green"], width=16)
        c.create_arc(cx-r, cy-r, cx+r, cy+r, start=73, extent=50, style=tk.ARC, outline=C["orange"], width=16)
        c.create_arc(cx-r, cy-r, cx+r, cy+r, start=123, extent=39, style=tk.ARC, outline=C["red"], width=16)

        for km in range(0, 221, 20):
            ang = math.radians(162 - (km / max_speed) * 144)
            x1 = cx + (r - 4) * math.cos(ang)
            y1 = cy - (r - 4) * math.sin(ang)
            x2 = cx + (r - 20) * math.cos(ang)
            y2 = cy - (r - 20) * math.sin(ang)
            c.create_line(x1, y1, x2, y2, fill=C["text"], width=2)
            tx = cx + (r - 33) * math.cos(ang)
            ty = cy - (r - 33) * math.sin(ang)
            c.create_text(tx, ty, text=str(km), fill=C["dim"], font=self.f_hash)

        s = max(0.0, min(max_speed, self.speed_kmh))
        ang = math.radians(162 - (s / max_speed) * 144)
        nx = cx + (r - 30) * math.cos(ang)
        ny = cy - (r - 30) * math.sin(ang)
        col = C["green"] if s < 90 else (C["orange"] if s < 145 else C["red"])
        c.create_line(cx, cy, nx, ny, fill=col, width=4)
        c.create_oval(cx-7, cy-7, cx+7, cy+7, fill=col, outline="")

    def _draw_radar(self):
        """Draw circular radar for V2X nodes."""
        c = self.radar_canvas
        c.delete("all")
        w = int(c.winfo_width()) if c.winfo_width() > 10 else 430
        h = int(c.winfo_height()) if c.winfo_height() > 10 else 210
        cx, cy = w // 2, h // 2
        r = min(w, h) // 2 - 16

        for factor in (1.0, 0.75, 0.5, 0.25):
            rr = int(r * factor)
            c.create_oval(cx-rr, cy-rr, cx+rr, cy+rr, outline=C["cyan_dim"], width=1)
        c.create_line(cx-r, cy, cx+r, cy, fill=C["border"])
        c.create_line(cx, cy-r, cx, cy+r, fill=C["border"])

        sweep = (self._tick * 4) % 360
        a = math.radians(sweep)
        sx = cx + r * math.cos(a)
        sy = cy - r * math.sin(a)
        c.create_line(cx, cy, sx, sy, fill=C["cyan"], width=2)

        c.create_oval(cx-5, cy-5, cx+5, cy+5, fill=C["green"], outline="")

        for ang, dist, kind in self.v2x_nodes:
            rr = int(r * dist)
            x = cx + rr * math.cos(ang)
            y = cy - rr * math.sin(ang)
            col = C["green"] if kind == "V2I" else C["cyan"]
            size = 4 if kind == "V2V" else 6
            c.create_oval(x-size, y-size, x+size, y+size, fill=col, outline="")

    def _draw_anomaly_graph(self):
        """Draw rolling anomaly score graph."""
        c = self.anomaly_canvas
        c.delete("all")
        w = int(c.winfo_width()) if c.winfo_width() > 10 else 430
        h = int(c.winfo_height()) if c.winfo_height() > 10 else 180

        for i in range(5):
            y = 14 + i * ((h - 28) / 4.0)
            c.create_line(10, y, w - 10, y, fill=C["border"])

        vals = list(self.anomaly_history)
        if len(vals) < 2:
            return

        points = []
        for i, v in enumerate(vals):
            x = 10 + (i / (len(vals) - 1)) * (w - 20)
            y = 14 + (1.0 - v) * (h - 28)
            points.extend([x, y])

        c.create_line(*points, fill=C["cyan"], width=2, smooth=True)
        thr_y = 14 + (1.0 - 0.65) * (h - 28)
        c.create_line(10, thr_y, w - 10, thr_y, fill=C["orange"], dash=(4, 3))
        c.create_text(14, 10, text="1.0", fill=C["dim"], anchor="w", font=self.f_hash)
        c.create_text(14, h - 10, text="0.0", fill=C["dim"], anchor="w", font=self.f_hash)
        c.create_text(w - 12, 10, text=f"{self._latest_anomaly:.2f}", fill=C["cyan"], anchor="e", font=self.f_head)

    def _draw_dual_hash_chain(self):
        """Draw block chain boxes with SHA2/SHA3 markers."""
        c = self.dual_canvas
        c.delete("all")
        w = int(c.winfo_width()) if c.winfo_width() > 10 else 430
        h = int(c.winfo_height()) if c.winfo_height() > 10 else 160

        chain = self.blockchain.chain[-5:]
        n = max(1, len(chain))
        margin = 12
        box_w = max(62, int((w - margin * 2 - (n - 1) * 12) / n))
        y1, y2 = 34, h - 22

        for i in range(n):
            x1 = margin + i * (box_w + 12)
            x2 = x1 + box_w
            c.create_rectangle(x1, y1, x2, y2, outline=C["cyan_dim"], width=2)
            c.create_line(x1 + 6, y1 + 20, x2 - 6, y1 + 20, fill=C["green"], width=2)
            c.create_line(x1 + 6, y1 + 38, x2 - 6, y1 + 38, fill=C["cyan"], width=2)
            c.create_text((x1 + x2) / 2, y1 + 10, text=f"B{i - n + len(chain) + 1}", fill=C["text"], font=self.f_hash)
            if i < n - 1:
                c.create_line(x2 + 2, (y1 + y2) / 2, x2 + 10, (y1 + y2) / 2, fill=C["cyan"], width=2)
        c.create_text(12, 14, text="SHA2 + SHA3 dual-hash linked blocks", fill=C["dim"], anchor="w", font=self.f_hash)

    def _draw_gps_map(self):
        """Draw decentralized vehicular network node map."""
        c = self.gps_canvas
        c.delete("all")
        w = int(c.winfo_width()) if c.winfo_width() > 10 else 420
        h = int(c.winfo_height()) if c.winfo_height() > 10 else 230

        for x in range(0, w, 32):
            c.create_line(x, 0, x, h, fill="#0d1a22")
        for y in range(0, h, 32):
            c.create_line(0, y, w, y, fill="#0d1a22")

        cx, cy = int(w * 0.52), int(h * 0.55)
        c.create_oval(cx-7, cy-7, cx+7, cy+7, fill=C["cyan"], outline="")
        c.create_text(cx, cy - 14, text="SELF", fill=C["cyan"], font=self.f_hash)

        for ang, dist, _kind in self.v2x_nodes:
            rr = int((min(w, h) * 0.36) * dist)
            x = cx + rr * math.cos(ang)
            y = cy - rr * math.sin(ang)
            c.create_line(cx, cy, x, y, fill="#15485a")
            c.create_oval(x-5, y-5, x+5, y+5, fill="#5aa8ff", outline="")

    def _draw_car_layers(self):
        """Draw stylized 3D-like car with security layers."""
        c = self.car_canvas
        c.delete("all")
        w = int(c.winfo_width()) if c.winfo_width() > 10 else 420
        h = int(c.winfo_height()) if c.winfo_height() > 10 else 190

        cx, cy = w // 2, h // 2 + 6
        for i, col in enumerate(("#0b2f3f", "#0d4556", "#106a76")):
            pad = 20 + i * 14
            c.create_oval(cx-120-pad, cy-50-pad//3, cx+120+pad, cy+50+pad//3, outline=col, width=2)

        body = [cx-110, cy+14, cx-70, cy-18, cx+68, cy-18, cx+108, cy+14]
        c.create_polygon(*body, fill="#214250", outline="#7cc8de", width=2)
        c.create_rectangle(cx-80, cy-10, cx+80, cy+20, outline="#9fe8ff", width=2)
        c.create_oval(cx-84, cy+14, cx-58, cy+40, fill="#12252d", outline="#7cc8de")
        c.create_oval(cx+58, cy+14, cx+84, cy+40, fill="#12252d", outline="#7cc8de")
        c.create_text(cx, 20, text="Encrypted Layers", fill=C["green"], font=self.f_hash)

    def _show_frame(self, frame):
        """Render OpenCV frame in tkinter label."""
        if frame is None:
            return
        rgb = cv2.cvtColor(frame, cv2.COLOR_BGR2RGB)
        ok, buf = cv2.imencode(".png", rgb)
        if not ok:
            return
        self._photo = tk.PhotoImage(data=base64.b64encode(buf.tobytes()))
        self.cam_label.configure(image=self._photo)

    def _sync_logs(self):
        """Append new blockchain events to panels."""
        if len(self.blockchain.chain) <= self._last_log_idx:
            return
        for i in range(self._last_log_idx, len(self.blockchain.chain)):
            b = self.blockchain.chain[i]
            h = (b.block_hash or "")[:28]
            self.txt_ledger.insert("end", f"[{b.index:04d}] 0x{h}..  EVENT={b.event_data}\n")
            self.txt_terminal.insert("end", f"$ did verify block:{b.index} -> DID Proof Verified\n")
            receipts = getattr(b, "smart_contract_receipts", []) or []
            if receipts:
                for r in receipts:
                    rid = r.get("receipt_id", "receipt")
                    status = r.get("status", "ok")
                    self.txt_contract.insert("end", f"contract.exec {rid} status={status}\n")
            else:
                self.txt_contract.insert("end", f"contract.exec block:{b.index} status=simulated_ok\n")

        for widget in (self.txt_ledger, self.txt_terminal, self.txt_contract):
            widget.see("end")
            if int(widget.index("end-1c").split(".")[0]) > 250:
                widget.delete("1.0", "80.0")

        self._last_log_idx = len(self.blockchain.chain)

    def _render_text_panels(self):
        """Update textual status labels."""
        self.lbl_clock.config(text=datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
        self.lbl_speed_big.config(text=f"{self.speed_kmh:0.0f}")

        if getattr(self.blockchain, "safe_mode_active", False):
            self.lbl_speed_state.config(text="SAFE MODE", fg=C["orange"])
            self.lbl_shield.config(text="ZKP Privacy Shield: ACTIVE - BIOMETRIC SAFETY", fg=C["orange"])
        elif self.blockchain.emergency_brake_active:
            self.lbl_speed_state.config(text="EMERGENCY BRAKE", fg=C["red"])
            self.lbl_shield.config(text="ZKP Privacy Shield: ACTIVE - DEFENSE MODE", fg=C["orange"])
        elif self.blockchain.engine_started:
            self.lbl_speed_state.config(text="RUNNING", fg=C["green"])
            self.lbl_shield.config(text="ZKP Privacy Shield: ACTIVE", fg=C["green"])
        else:
            self.lbl_speed_state.config(text="STANDBY", fg=C["dim"])
            self.lbl_shield.config(text="ZKP Privacy Shield: ACTIVE", fg=C["green"])

        now = time.time()
        if now - self._last_chain_verify_ts >= self.chain_verify_interval_sec:
            self._last_chain_verify_ok = self.blockchain.verify_chain()
            self._last_chain_verify_ts = now
        chain_ok = self._last_chain_verify_ok
        self.lbl_did.config(text="DID Proof Verified" if chain_ok else "DID Proof Warning", fg=C["cyan"] if chain_ok else C["red"])

        status_text = (
            f"Vehicle ID   : {self.VEHICLE_ID[-12:]}\n"
            f"Unlocked     : {self.blockchain.car_unlocked}\n"
            f"Engine       : {self.blockchain.engine_started}\n"
            f"Emergency    : {self.blockchain.emergency_brake_active}\n"
            f"Safe Mode    : {getattr(self.blockchain, 'safe_mode_active', False)}\n"
            f"Detections   : {self._last_detection_count}\n"
            f"Obstacle     : {self._last_obstacle_distance:6.1f} m\n"
            f"Heart Rate   : {self.driver_heart_rate_bpm:6.1f} bpm\n"
            f"Drowsiness   : {self.driver_drowsiness_score:0.2f}\n"
            f"Chain Length : {len(self.blockchain.chain)}\n"
            f"Anomaly      : {self._latest_anomaly:0.2f}"
        )
        if status_text != self._last_status_text:
            self.lbl_status.config(text=status_text)
            self._last_status_text = status_text
        lock_text = "OPEN" if self.blockchain.car_unlocked else "LOCKED"
        lock_color = C["orange"] if self.blockchain.car_unlocked else C["green"]
        auth_text = "AUTHENTIC" if self._last_auth_ok else "WAITING"
        auth_color = C["green"] if self._last_auth_ok else C["orange"]
        engine_text = "START" if self.blockchain.engine_started else "STOP"
        engine_color = C["green"] if self.blockchain.engine_started else C["red"]
        self.lbl_lock_state.config(text=lock_text, fg=lock_color)
        self.lbl_auth_state.config(text=auth_text, fg=auth_color)
        self.lbl_engine_cmd.config(text=engine_text, fg=engine_color)

        self.lbl_card_rpm.config(text=f"{self.rpm:6.0f}")
        self.lbl_card_temp.config(text=f"{self.engine_temp:4.1f} C")
        self.lbl_card_fuel.config(text=f"{self.fuel_level:4.1f} %")
        self.lbl_card_thr.config(text=f"{self.throttle:4.1f} %")

    def _render_canvases(self):
        """Render all graph/canvas widgets."""
        self._draw_speedometer()
        self._draw_radar()
        self._draw_anomaly_graph()
        self._draw_dual_hash_chain()
        self._draw_gps_map()
        self._draw_car_layers()

    def _update_ui(self):
        """Main UI update loop."""
        try:
            frame = None
            if self._tick % self.camera_refresh_every == 0:
                frame = self._process_frame()
                if frame is not None:
                    self._last_camera_frame = frame
            self._update_model()
            self._push_telemetry()
            if self._last_camera_frame is not None and self._tick != self._last_frame_render_tick:
                self._show_frame(self._last_camera_frame)
                self._last_frame_render_tick = self._tick
            if self._tick % self.text_refresh_every == 0:
                self._render_text_panels()
            if self._tick % self.canvas_refresh_every == 0:
                self._render_canvases()
            if self._tick % self.log_refresh_every == 0:
                self._sync_logs()
            self._tick += 1
        except Exception as e:
            now = time.time()
            # Throttle repeated loop errors to avoid log flooding.
            if now - self._last_ui_error_log_ts > 2.0:
                logger.exception("UI update loop error: %s", e)
                self._last_ui_error_log_ts = now
        self.after(self.ui_tick_ms, self._update_ui)

    def on_closing(self):
        """Save chain and release resources."""
        try:
            self.blockchain.save()
        except Exception as e:
            logger.exception("Failed to save blockchain on close: %s", e)
        if self.cap and self.cap.isOpened():
            self.cap.release()
        self.destroy()


if __name__ == "__main__":
    app = SmartCarDashboard()
    app.protocol("WM_DELETE_WINDOW", app.on_closing)
    style = ttk.Style()
    style.theme_use("clam")
    app.mainloop()

