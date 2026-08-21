"""Modern dark dashboard skin for OmniGuard V2X.

This module intentionally changes presentation only. Runtime data collection,
backend actions, blockchain/security logic, camera processing, and validation
metadata remain implemented by :mod:`dashboard`.
"""

import tkinter as tk
from tkinter import font, ttk
from typing import Any, Dict

from dashboard import (
    C,
    NO_DATA,
    NOT_CONNECTED,
    UNAVAILABLE,
    SmartCarDashboard as LegacySmartCarDashboard,
)


# Shared palette used by inherited renderers as well as this presentation layer.
C.update(
    {
        "bg": "#06111f",
        "card": "#0d1b2b",
        "card_alt": "#112238",
        "border": "#1c3048",
        "cyan": "#4f7cff",
        "cyan_dim": "#244eb5",
        "green": "#24d18b",
        "orange": "#f59e0b",
        "yellow": "#f4c95d",
        "red": "#ff5c6c",
        "text": "#f3f6fb",
        "dim": "#8ca0b8",
        "purple": "#6d5dfc",
    }
)

SIDEBAR_BG = "#081525"
TOPBAR_BG = "#071321"
CANVAS_BG = "#081421"
CARD_DEEP = "#091725"
CARD_HOVER = "#13243a"
BLUE = "#4f7cff"
PURPLE = "#6d5dfc"
GREEN = "#24d18b"


class ModernSmartCarDashboard(LegacySmartCarDashboard):
    """Generated-reference inspired UI that preserves the existing live runtime."""

    def _setup_fonts(self):
        self.f_brand = font.Font(family="Segoe UI", size=15, weight="bold")
        self.f_title = font.Font(family="Segoe UI", size=20, weight="bold")
        self.f_subtitle = font.Font(family="Segoe UI", size=10)
        self.f_head = font.Font(family="Segoe UI", size=11, weight="bold")
        self.f_body = font.Font(family="Segoe UI", size=10)
        self.f_small = font.Font(family="Segoe UI", size=9)
        self.f_tiny = font.Font(family="Segoe UI", size=8)
        self.f_mono = font.Font(family="Consolas", size=9)
        self.f_big = font.Font(family="Segoe UI", size=27, weight="bold")
        self.f_kpi = font.Font(family="Segoe UI", size=22, weight="bold")

    def _configure_styles(self):
        style = ttk.Style()
        try:
            style.theme_use("clam")
        except Exception:
            pass
        style.configure(
            "Ops.Horizontal.TProgressbar",
            troughcolor="#07121e",
            background=BLUE,
            bordercolor=C["border"],
            lightcolor=BLUE,
            darkcolor=PURPLE,
        )
        style.configure(
            "Throttle.Horizontal.TScale",
            troughcolor="#07121e",
            background=C["card"],
        )
        style.configure(
            "Modern.Vertical.TScrollbar",
            background="#14263a",
            troughcolor=C["bg"],
            bordercolor=C["bg"],
            arrowcolor=C["dim"],
        )

    def _build_ui(self):
        self._setup_fonts()
        self._configure_styles()
        self.geometry("1580x960")
        self.minsize(760, 640)

        self.shell = tk.Frame(self, bg=C["bg"])
        self.shell.pack(fill="both", expand=True)

        self._build_sidebar()
        self.content_shell = tk.Frame(self.shell, bg=C["bg"])
        self.content_shell.pack(side="right", fill="both", expand=True)
        self._build_topbar()

        self.main_canvas = tk.Canvas(self.content_shell, bg=C["bg"], highlightthickness=0)
        self.main_scrollbar = ttk.Scrollbar(
            self.content_shell,
            orient="vertical",
            command=self.main_canvas.yview,
            style="Modern.Vertical.TScrollbar",
        )
        self.main_canvas.configure(yscrollcommand=self.main_scrollbar.set)
        self.main_canvas.pack(side="left", fill="both", expand=True)
        self.main_scrollbar.pack(side="right", fill="y")

        self.command_grid = tk.Frame(self.main_canvas, bg=C["bg"], padx=18, pady=16)
        self.card_grid = self.command_grid
        self.card_window = self.main_canvas.create_window((0, 0), window=self.command_grid, anchor="nw")
        self.command_grid.bind("<Configure>", self._on_grid_configure)
        self.main_canvas.bind("<Configure>", self._on_canvas_configure)
        self.bind("<Configure>", self._on_resize)
        self.bind_all("<MouseWheel>", self._on_mousewheel)

        self._build_kpi_row()
        self._build_primary_row()
        self._build_insights_row()
        self._build_operations_row()
        self._build_security_details()
        self._build_footer()

        # Compatibility aliases retained for inherited behavior and integrations.
        self.left_column = self.security_left
        self.center_column = self.primary_left
        self.right_column = self.primary_right
        self._apply_responsive_layout()

    def _build_sidebar(self):
        self.sidebar = tk.Frame(self.shell, bg=SIDEBAR_BG, width=238, padx=14, pady=18)
        self.sidebar.pack(side="left", fill="y")
        self.sidebar.pack_propagate(False)

        brand = tk.Frame(self.sidebar, bg=SIDEBAR_BG)
        brand.pack(fill="x", pady=(0, 22))
        shield = tk.Canvas(brand, width=42, height=50, bg=SIDEBAR_BG, highlightthickness=0)
        shield.pack(side="left", padx=(0, 10))
        shield.create_polygon(21, 3, 38, 11, 35, 32, 21, 46, 7, 32, 4, 11, fill="#172d62", outline=PURPLE, width=2)
        shield.create_oval(14, 15, 28, 29, outline=BLUE, width=2)
        shield.create_line(17, 22, 20, 25, 26, 18, fill=GREEN, width=2)

        brand_text = tk.Frame(brand, bg=SIDEBAR_BG)
        brand_text.pack(side="left", fill="x", expand=True)
        tk.Label(brand_text, text="Next-Gen", bg=SIDEBAR_BG, fg=C["text"], font=self.f_small).pack(anchor="w")
        tk.Label(brand_text, text="Vehicle Security", bg=SIDEBAR_BG, fg=C["text"], font=self.f_brand).pack(anchor="w")
        tk.Label(brand_text, text="Blockchain-Powered Protection", bg=SIDEBAR_BG, fg=C["dim"], font=self.f_tiny).pack(anchor="w", pady=(2, 0))

        self.sidebar_buttons = []
        self._sidebar_group("CORE")
        self._sidebar_item("Dashboard", "▣", active=True)
        self._sidebar_item("Vehicles", "◇")
        self._sidebar_item("Transactions", "◌")
        self._sidebar_item("Access Control", "▱")
        self._sidebar_item("Ownership", "⬡")
        self._sidebar_item("Audit Logs", "≡")

        self._sidebar_group("SECURITY")
        self._sidebar_item("Threat Detection", "◈")
        self._sidebar_item("Alerts", "△")
        self._sidebar_item("Security Scan", "◎")

        self._sidebar_group("SYSTEM")
        self._sidebar_item("Smart Contract", "⌘")
        self._sidebar_item("Nodes", "⬢")
        self._sidebar_item("Settings", "⚙")

        spacer = tk.Frame(self.sidebar, bg=SIDEBAR_BG)
        spacer.pack(fill="both", expand=True)
        status = tk.Frame(spacer, bg="#0e2032", padx=10, pady=10)
        status.pack(side="bottom", fill="x", pady=(12, 0))
        tk.Label(status, text="◆", bg="#0e2032", fg=GREEN, font=self.f_head).pack(side="left", padx=(0, 8))
        status_text = tk.Frame(status, bg="#0e2032")
        status_text.pack(side="left")
        tk.Label(status_text, text="System Status", bg="#0e2032", fg=C["text"], font=self.f_small).pack(anchor="w")
        self.sidebar_status = tk.Label(status_text, text="Checking runtime…", bg="#0e2032", fg=GREEN, font=self.f_tiny)
        self.sidebar_status.pack(anchor="w")

        tk.Label(self.sidebar, text="OmniGuard V2X • Research UI", bg=SIDEBAR_BG, fg="#62758d", font=self.f_tiny).pack(anchor="w", pady=(12, 0))

    def _sidebar_group(self, title: str):
        tk.Label(self.sidebar, text=title, bg=SIDEBAR_BG, fg="#62758d", font=self.f_tiny).pack(anchor="w", padx=8, pady=(11, 5))

    def _sidebar_item(self, title: str, icon: str, active: bool = False):
        bg = "#4d45e7" if active else SIDEBAR_BG
        fg = "#ffffff" if active else "#b7c4d5"
        row = tk.Frame(self.sidebar, bg=bg, padx=9, pady=8)
        row.pack(fill="x", pady=2)
        tk.Label(row, text=icon, width=2, bg=bg, fg=fg, font=self.f_body).pack(side="left")
        tk.Label(row, text=title, bg=bg, fg=fg, font=self.f_body).pack(side="left", padx=(7, 0))
        self.sidebar_buttons.append(row)

    def _build_topbar(self):
        top = tk.Frame(self.content_shell, bg=TOPBAR_BG, padx=20, pady=14)
        top.pack(fill="x")

        greeting = tk.Frame(top, bg=TOPBAR_BG)
        greeting.pack(side="left", fill="x", expand=True)
        tk.Label(greeting, text="Welcome back, Shagor!", bg=TOPBAR_BG, fg=C["text"], font=self.f_title).pack(anchor="w")
        tk.Label(greeting, text="Secure. Transparent. Decentralized.", bg=TOPBAR_BG, fg=C["dim"], font=self.f_subtitle).pack(anchor="w", pady=(2, 0))

        controls = tk.Frame(top, bg=TOPBAR_BG)
        controls.pack(side="right")
        network = tk.Frame(controls, bg="#0d1d2f", padx=10, pady=7)
        network.pack(side="left", padx=(0, 8))
        tk.Label(network, text="●", bg="#0d1d2f", fg=GREEN, font=self.f_small).pack(side="left", padx=(0, 6))
        network_text = tk.Frame(network, bg="#0d1d2f")
        network_text.pack(side="left")
        tk.Label(network_text, text="Blockchain Network", bg="#0d1d2f", fg=C["dim"], font=self.f_tiny).pack(anchor="w")
        self.connection_badge = tk.Label(network_text, text=NOT_CONNECTED, bg="#0d1d2f", fg=C["orange"], font=self.f_small)
        self.connection_badge.pack(anchor="w")

        backend_card = tk.Frame(controls, bg="#0d1d2f", padx=10, pady=7)
        backend_card.pack(side="left", padx=(0, 8))
        tk.Label(backend_card, text="Runtime", bg="#0d1d2f", fg=C["dim"], font=self.f_tiny).pack(anchor="w")
        self.backend_label = tk.Label(backend_card, text=type(self.blockchain).__name__, bg="#0d1d2f", fg=C["text"], font=self.f_small)
        self.backend_label.pack(anchor="w")

        tk.Button(
            controls,
            text="↻ Refresh",
            command=self.manual_refresh,
            bg="#172741",
            fg=C["text"],
            activebackground="#213652",
            activeforeground="#ffffff",
            relief="flat",
            bd=0,
            padx=12,
            pady=8,
            font=self.f_small,
        ).pack(side="left")

        self.updated_label = tk.Label(top, text="Updated --", bg=TOPBAR_BG, fg="#62758d", font=self.f_tiny)
        self.updated_label.pack(side="bottom", anchor="e")

    def _build_kpi_row(self):
        self.kpi_row = tk.Frame(self.command_grid, bg=C["bg"])
        self.kpi_row.grid(row=0, column=0, columnspan=12, sticky="ew", pady=(0, 12))
        self._kpi_widgets: Dict[str, Dict[str, tk.Label]] = {}
        specs = [
            ("vehicles", "Network Vehicles", "1", "vehicle + observed peers", "◈", PURPLE),
            ("transactions", "Blockchain Records", "—", "live chain length", "▱", GREEN),
            ("nodes", "Active V2X Nodes", "—", "ego + live peers", "⬢", BLUE),
            ("security", "Security Status", "CHECK", "runtime metadata", "◇", PURPLE),
        ]
        for idx, (key, title, value, note, icon, accent) in enumerate(specs):
            card = tk.Frame(self.kpi_row, bg=C["border"], padx=1, pady=1)
            inner = tk.Frame(card, bg=C["card"], padx=14, pady=12)
            inner.pack(fill="both", expand=True)
            top = tk.Frame(inner, bg=C["card"])
            top.pack(fill="x")
            tk.Label(top, text=title, bg=C["card"], fg="#b9c6d6", font=self.f_small).pack(side="left")
            tk.Label(top, text=icon, bg=C["card"], fg=accent, font=self.f_head).pack(side="right")
            value_label = tk.Label(inner, text=value, bg=C["card"], fg=C["text"], font=self.f_kpi)
            value_label.pack(anchor="w", pady=(5, 0))
            note_label = tk.Label(inner, text=note, bg=C["card"], fg=C["dim"], font=self.f_tiny)
            note_label.pack(anchor="w", pady=(2, 0))
            self._kpi_widgets[key] = {"card": card, "value": value_label, "note": note_label}

    def _build_primary_row(self):
        self.primary_left = tk.Frame(self.command_grid, bg=C["bg"])
        self.primary_right = tk.Frame(self.command_grid, bg=C["bg"])

        vehicle = self._create_panel(self.primary_left, "vehicle", "Vehicle Status Overview", 430)
        body = vehicle["body"]
        visual = tk.Frame(body, bg=C["card"])
        visual.pack(side="left", fill="both", expand=True, padx=(0, 12))
        info = tk.Frame(body, bg=C["card"], width=245)
        info.pack(side="right", fill="y")
        info.pack_propagate(False)

        self.vehicle_art = tk.Canvas(visual, height=205, bg=CARD_DEEP, highlightthickness=0)
        self.vehicle_art.pack(fill="x", expand=False)
        self.vehicle_art.bind("<Configure>", self._draw_vehicle_art)

        road_header = tk.Frame(visual, bg=C["card"], pady=6)
        road_header.pack(fill="x")
        tk.Label(road_header, text="Live V2X Scene", bg=C["card"], fg=C["dim"], font=self.f_small).pack(side="left")
        road_badge = tk.Label(road_header, text="No Data", bg=C["card_alt"], fg=C["dim"], font=self.f_tiny, padx=6, pady=2)
        road_badge.pack(side="right")
        self._cards["road"] = {"badge": road_badge, "body": visual, "rows": {}}
        self.road_canvas = tk.Canvas(visual, height=155, bg=CARD_DEEP, highlightthickness=0)
        self.road_canvas.pack(fill="both", expand=True)

        status_title = tk.Label(info, text="Current Vehicle", bg=C["card"], fg=C["text"], font=self.f_head)
        status_title.pack(anchor="w", pady=(0, 8))
        fields = [
            ("vehicle_id", "Vehicle ID"),
            ("lock_status", "Ownership / Lock"),
            ("engine_status", "Engine"),
            ("safe_mode", "Safe Mode"),
            ("emergency_status", "Emergency"),
            ("speed", "Speed"),
            ("rpm", "RPM"),
            ("fuel", "Fuel"),
            ("temperature", "Temperature"),
            ("throttle", "Throttle"),
        ]
        for key, label in fields:
            row = tk.Frame(info, bg="#102033", padx=8, pady=5)
            row.pack(fill="x", pady=2)
            tk.Label(row, text=label, bg="#102033", fg=C["dim"], font=self.f_tiny).pack(side="left")
            value = tk.Label(row, text=UNAVAILABLE, bg="#102033", fg=C["text"], font=self.f_tiny)
            value.pack(side="right")
            self._status_labels[key] = value

        tk.Button(
            info,
            text="View Vehicle Details",
            command=self.manual_refresh,
            bg="#5546ee",
            fg="#ffffff",
            relief="flat",
            bd=0,
            pady=7,
            font=self.f_small,
        ).pack(side="bottom", fill="x", pady=(10, 0))

        activity = self._create_panel(self.primary_right, "timeline", "Recent Blockchain Activity", 430)
        self.timeline_text = tk.Text(
            activity["body"],
            bg=CARD_DEEP,
            fg=C["text"],
            insertbackground=BLUE,
            relief="flat",
            bd=0,
            font=self.f_mono,
            wrap="word",
            padx=10,
            pady=10,
        )
        self.timeline_text.pack(fill="both", expand=True)
        self.timeline_text.configure(state="disabled")

    def _build_insights_row(self):
        self.network_column = tk.Frame(self.command_grid, bg=C["bg"])
        self.alert_column = tk.Frame(self.command_grid, bg=C["bg"])
        self.telemetry_column = tk.Frame(self.command_grid, bg=C["bg"])

        radar = self._create_panel(self.network_column, "radar", "Network Status", 300)
        self.radar_canvas = tk.Canvas(radar["body"], height=185, bg=CARD_DEEP, highlightthickness=0)
        self.radar_canvas.pack(fill="both", expand=True)
        health_header = tk.Frame(radar["body"], bg=C["card"], pady=5)
        health_header.pack(fill="x")
        tk.Label(health_header, text="System Health / Connection", bg=C["card"], fg=C["dim"], font=self.f_tiny).pack(side="left")
        health_badge = tk.Label(health_header, text="No Data", bg=C["card_alt"], fg=C["dim"], font=self.f_tiny, padx=6, pady=2)
        health_badge.pack(side="right")
        self.health_text = tk.Label(radar["body"], text=NO_DATA, bg=C["card"], fg=C["dim"], font=self.f_tiny, justify="left", anchor="nw")
        self.health_text.pack(fill="x")
        self._cards["health"] = {"badge": health_badge, "body": radar["body"], "rows": {}}

        anomaly = self._create_panel(self.alert_column, "anomaly", "Security Alerts", 300)
        self.anomaly_canvas = tk.Canvas(anomaly["body"], height=145, bg=CARD_DEEP, highlightthickness=0)
        self.anomaly_canvas.pack(fill="both", expand=True)
        warnings_header = tk.Frame(anomaly["body"], bg=C["card"], pady=5)
        warnings_header.pack(fill="x")
        tk.Label(warnings_header, text="Reviewer / Security Warnings", bg=C["card"], fg=C["dim"], font=self.f_tiny).pack(side="left")
        warning_badge = tk.Label(warnings_header, text="No Data", bg=C["card_alt"], fg=C["dim"], font=self.f_tiny, padx=6, pady=2)
        warning_badge.pack(side="right")
        self.warnings_text = tk.Label(anomaly["body"], text=NO_DATA, bg=C["card"], fg=C["orange"], font=self.f_tiny, justify="left", anchor="nw", wraplength=340)
        self.warnings_text.pack(fill="x")
        self._cards["warnings"] = {"badge": warning_badge, "body": anomaly["body"], "rows": {}}

        speed = self._create_panel(self.telemetry_column, "speed", "Transaction / Vehicle Telemetry", 300)
        self.speed_canvas = tk.Canvas(speed["body"], height=220, bg=CARD_DEEP, highlightthickness=0)
        self.speed_canvas.pack(fill="both", expand=True)

    def _build_operations_row(self):
        self.operations_left = tk.Frame(self.command_grid, bg=C["bg"])
        self.operations_right = tk.Frame(self.command_grid, bg=C["bg"])

        access = self._create_panel(self.operations_left, "access", "Access Control", 270)
        self._build_access_panel()

        camera = self._create_panel(self.operations_right, "camera", "Live Camera / Object Detection", 270)
        self.camera_label = tk.Label(camera["body"], text="Camera Not Connected", bg=CARD_DEEP, fg=C["orange"], font=self.f_head)
        self.camera_label.pack(fill="both", expand=True)

    def _build_security_details(self):
        self.security_section = tk.Frame(self.command_grid, bg=C["bg"])
        self.security_left = tk.Frame(self.security_section, bg=C["bg"])
        self.security_right = tk.Frame(self.security_section, bg=C["bg"])
        self.security_left.pack(side="left", fill="both", expand=True, padx=(0, 6))
        self.security_right.pack(side="left", fill="both", expand=True, padx=(6, 0))

        for idx, (key, title, _sources) in enumerate(self.METADATA_SECTIONS):
            parent = self.security_left if idx % 2 == 0 else self.security_right
            panel = self._create_panel(parent, f"meta_{key}", title, 0)
            button = tk.Button(
                panel["body"],
                text="Expand",
                command=lambda k=key: self._toggle_metadata(k),
                bg=C["card_alt"],
                fg=BLUE,
                activebackground=CARD_HOVER,
                activeforeground="#ffffff",
                relief="flat",
                bd=0,
                font=self.f_tiny,
                padx=8,
                pady=3,
            )
            button.pack(anchor="e")
            summary = tk.Label(panel["body"], text=NO_DATA, bg=C["card"], fg=C["orange"], font=self.f_tiny, justify="left", anchor="nw", wraplength=520)
            summary.pack(fill="x", pady=(0, 4))
            details = tk.Label(panel["body"], text="", bg=CARD_DEEP, fg=C["text"], font=self.f_tiny, justify="left", anchor="nw", wraplength=520, padx=8, pady=8)
            self._metadata_widgets[key] = {"button": button, "summary": summary, "details": details}

    def _build_footer(self):
        self.footer = tk.Label(
            self.command_grid,
            text="Blockchain technology • live runtime data • validation-aware security UI",
            bg=C["bg"],
            fg="#62758d",
            font=self.f_tiny,
            pady=14,
        )

    def _create_panel(self, parent: tk.Widget, key: str, title: str, min_height: int = 0) -> Dict[str, Any]:
        outer = tk.Frame(parent, bg=C["border"], padx=1, pady=1)
        outer.pack(fill="both", expand=True)
        inner = tk.Frame(outer, bg=C["card"], padx=13, pady=11, height=min_height)
        inner.pack(fill="both", expand=True)
        if min_height:
            inner.pack_propagate(False)
        header = tk.Frame(inner, bg=C["card"])
        header.pack(fill="x")
        tk.Label(header, text=title, bg=C["card"], fg=C["text"], font=self.f_head).pack(side="left")
        badge = tk.Label(header, text="No Data", bg=C["card_alt"], fg=C["dim"], font=self.f_tiny, padx=7, pady=2)
        badge.pack(side="right")
        body = tk.Frame(inner, bg=C["card"])
        body.pack(fill="both", expand=True, pady=(9, 0))
        panel = {"outer": outer, "inner": inner, "badge": badge, "body": body, "rows": {}}
        self._cards[key] = panel
        return panel

    def _draw_vehicle_art(self, event=None):
        canvas = self.vehicle_art
        canvas.delete("all")
        w = max(520, canvas.winfo_width())
        h = max(190, canvas.winfo_height())
        cx = w * 0.48
        cy = h * 0.58

        # Soft concentric telemetry rings.
        for offset, color in ((0, "#15345f"), (10, "#102746"), (20, "#0c2039")):
            canvas.create_oval(cx - 165 - offset, cy + 35 - offset / 3, cx + 165 + offset, cy + 80 + offset / 3, outline=color, width=1)

        # Shield silhouette behind the vehicle.
        shield = [cx, 20, cx + 78, 48, cx + 66, 119, cx, 155, cx - 66, 119, cx - 78, 48]
        canvas.create_polygon(shield, fill="", outline="#17365f", width=2)
        canvas.create_line(cx, 35, cx, 139, fill="#112c50")

        # Stylized neon coupe. Decorative only; telemetry values are shown separately.
        body = [cx - 150, cy + 22, cx - 118, cy - 10, cx - 52, cy - 24, cx + 45, cy - 25, cx + 105, cy - 6, cx + 148, cy + 20, cx + 128, cy + 44, cx - 128, cy + 44]
        canvas.create_polygon(body, fill="#0d2951", outline="#2d7cff", width=2)
        roof = [cx - 72, cy - 22, cx - 34, cy - 55, cx + 43, cy - 55, cx + 82, cy - 18]
        canvas.create_polygon(roof, fill="#0b2346", outline="#3b82ff", width=2)
        canvas.create_line(cx - 30, cy - 52, cx - 18, cy - 18, fill="#2d7cff")
        canvas.create_line(cx + 45, cy - 52, cx + 58, cy - 18, fill="#2d7cff")
        canvas.create_oval(cx - 112, cy + 24, cx - 72, cy + 64, fill="#07111e", outline="#3b82ff", width=2)
        canvas.create_oval(cx + 73, cy + 24, cx + 113, cy + 64, fill="#07111e", outline="#3b82ff", width=2)
        canvas.create_line(cx - 145, cy + 8, cx - 115, cy + 2, fill="#76a8ff", width=3)
        canvas.create_line(cx + 113, cy + 2, cx + 142, cy + 11, fill="#76a8ff", width=3)
        canvas.create_text(18, 16, text="OMNIGUARD V2X • LIVE VEHICLE", fill="#6f86a2", anchor="nw", font=self.f_tiny)

    def _apply_responsive_layout(self):
        self._resize_after_id = None
        width = max(1, self.winfo_width())
        mode = "desktop" if width >= 1250 else "medium" if width >= 930 else "small"
        if mode == self._last_layout_mode:
            return
        self._last_layout_mode = mode

        if mode == "small":
            if self.sidebar.winfo_manager():
                self.sidebar.pack_forget()
        elif not self.sidebar.winfo_manager():
            self.sidebar.pack(side="left", fill="y", before=self.content_shell)

        for child in (
            self.primary_left,
            self.primary_right,
            self.network_column,
            self.alert_column,
            self.telemetry_column,
            self.operations_left,
            self.operations_right,
            self.security_section,
            self.footer,
        ):
            child.grid_forget()

        for i in range(12):
            self.command_grid.grid_columnconfigure(i, weight=1, minsize=0)

        kpi_cols = 4 if mode == "desktop" else 2 if mode == "medium" else 1
        for idx, widget in enumerate(self._kpi_widgets.values()):
            widget["card"].grid_forget()
            row, col = divmod(idx, kpi_cols)
            widget["card"].grid(row=row, column=col, sticky="nsew", padx=5, pady=5)
        for col in range(kpi_cols):
            self.kpi_row.grid_columnconfigure(col, weight=1)

        if mode == "desktop":
            self.primary_left.grid(row=1, column=0, columnspan=7, sticky="nsew", padx=(0, 6), pady=(0, 12))
            self.primary_right.grid(row=1, column=7, columnspan=5, sticky="nsew", padx=(6, 0), pady=(0, 12))
            self.network_column.grid(row=2, column=0, columnspan=4, sticky="nsew", padx=(0, 6), pady=(0, 12))
            self.alert_column.grid(row=2, column=4, columnspan=4, sticky="nsew", padx=6, pady=(0, 12))
            self.telemetry_column.grid(row=2, column=8, columnspan=4, sticky="nsew", padx=(6, 0), pady=(0, 12))
            self.operations_left.grid(row=3, column=0, columnspan=5, sticky="nsew", padx=(0, 6), pady=(0, 12))
            self.operations_right.grid(row=3, column=5, columnspan=7, sticky="nsew", padx=(6, 0), pady=(0, 12))
            self.security_section.grid(row=4, column=0, columnspan=12, sticky="nsew")
            footer_row = 5
        elif mode == "medium":
            self.primary_left.grid(row=1, column=0, columnspan=12, sticky="nsew", pady=(0, 12))
            self.primary_right.grid(row=2, column=0, columnspan=12, sticky="nsew", pady=(0, 12))
            self.network_column.grid(row=3, column=0, columnspan=6, sticky="nsew", padx=(0, 6), pady=(0, 12))
            self.alert_column.grid(row=3, column=6, columnspan=6, sticky="nsew", padx=(6, 0), pady=(0, 12))
            self.telemetry_column.grid(row=4, column=0, columnspan=12, sticky="nsew", pady=(0, 12))
            self.operations_left.grid(row=5, column=0, columnspan=12, sticky="nsew", pady=(0, 12))
            self.operations_right.grid(row=6, column=0, columnspan=12, sticky="nsew", pady=(0, 12))
            self.security_section.grid(row=7, column=0, columnspan=12, sticky="nsew")
            footer_row = 8
        else:
            widgets = [self.primary_left, self.primary_right, self.network_column, self.alert_column, self.telemetry_column, self.operations_left, self.operations_right, self.security_section]
            for row, child in enumerate(widgets, start=1):
                child.grid(row=row, column=0, columnspan=12, sticky="nsew", pady=(0, 12))
            footer_row = 9

        self.footer.grid(row=footer_row, column=0, columnspan=12, sticky="ew")

    def _render_snapshot(self, data: Dict[str, Any]):
        super()._render_snapshot(data)

        connection = self._point_value(data.get("connection_status", {}), NOT_CONNECTED)
        peers = self._point_value(data.get("v2x_peers", {}), [])
        peers = peers if isinstance(peers, list) else []
        chain = getattr(self.blockchain, "chain", None)
        chain_count = len(chain) if isinstance(chain, (list, tuple)) else None

        self._kpi_widgets["vehicles"]["value"].configure(text=str(1 + len(peers)))
        self._kpi_widgets["nodes"]["value"].configure(text=str(1 + len(peers)))
        self._kpi_widgets["transactions"]["value"].configure(text=str(chain_count) if chain_count is not None else "LIVE")

        security_points = [
            data.get("security_capability", {}),
            data.get("identity_security", {}),
            data.get("consensus_security", {}),
            data.get("privacy_pedersen", {}),
            data.get("fl_validation", {}),
            data.get("adversarial_validation", {}),
        ]
        errors = sum(1 for point in security_points if point.get("status") == "error")
        unavailable = sum(1 for point in security_points if point.get("status") == "unavailable")
        security_text = "ACTIVE" if not errors and not unavailable else "PARTIAL" if errors + unavailable < len(security_points) else "CHECK"
        security_color = GREEN if security_text == "ACTIVE" else C["yellow"] if security_text == "PARTIAL" else C["orange"]
        self._kpi_widgets["security"]["value"].configure(text=security_text, fg=security_color)
        self._kpi_widgets["security"]["note"].configure(text="metadata availability; not a security score")

        status_text = "All live sources operational" if connection == "Connected" else f"Runtime {connection.lower()}"
        self.sidebar_status.configure(text=status_text, fg=GREEN if connection == "Connected" else C["orange"])


# Keep the familiar class name for launchers while making the skin explicit.
SmartCarDashboard = ModernSmartCarDashboard
