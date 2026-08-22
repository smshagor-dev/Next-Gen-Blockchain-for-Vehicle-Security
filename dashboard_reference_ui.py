"""Reference-style production dashboard for OmniGuard V2X.

The visual composition follows the supplied premium dark vehicle-security dashboard
reference while preserving the existing runtime/provider/backend implementation.
All runtime values are source-backed. Missing values render as Unavailable/No Data;
no screenshot/demo KPI values are injected.
"""

from __future__ import annotations

import math
import tkinter as tk
from datetime import datetime
from tkinter import font, ttk
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple

from dashboard import C, NO_DATA, NOT_CONNECTED, UNAVAILABLE
from dashboard_production_ui import ProductionSmartCarDashboard


# Premium navy / electric-indigo palette inspired by the user-supplied reference.
BG = "#050b16"
SIDEBAR = "#091426"
TOPBAR = "#06101f"
CARD = "#0b1729"
CARD_2 = "#0d1b31"
CARD_3 = "#101f38"
BORDER = "#182b49"
GRID = "#183154"
TEXT = "#f6f8ff"
MUTED = "#8798b7"
DIM = "#657795"
INDIGO = "#6557ff"
INDIGO_2 = "#814fff"
BLUE = "#3979ff"
CYAN = "#35a9ff"
GREEN = "#24d98b"
ORANGE = "#f5a524"
RED = "#ff6176"
YELLOW = "#f0c94f"
PURPLE = "#8b63ff"

C.update(
    {
        "bg": BG,
        "card": CARD,
        "card_alt": CARD_2,
        "border": BORDER,
        "text": TEXT,
        "dim": MUTED,
        "cyan": CYAN,
        "green": GREEN,
        "orange": ORANGE,
        "yellow": YELLOW,
        "red": RED,
        "purple": PURPLE,
    }
)


MENU_GROUPS: Tuple[Tuple[str, Tuple[Tuple[str, str, str], ...]], ...] = (
    (
        "CORE",
        (
            ("overview", "Dashboard", "⌂"),
            ("vehicles", "Vehicles", "◇"),
            ("transactions", "Transactions", "⇄"),
            ("access", "Access Control", "⌾"),
            ("ownership", "Ownership", "♙"),
            ("audit", "Audit Logs", "≣"),
        ),
    ),
    (
        "SECURITY",
        (
            ("threats", "Threat Detection", "⛨"),
            ("alerts", "Alerts", "△"),
            ("scan", "Security Scan", "✓"),
        ),
    ),
    (
        "SYSTEM",
        (
            ("contracts", "Smart Contract", "◇"),
            ("nodes", "Nodes", "◎"),
            ("settings", "Settings", "⚙"),
        ),
    ),
)

PAGE_TITLES: Dict[str, Tuple[str, str]] = {
    "overview": ("Dashboard", "Secure. Transparent. Source-backed."),
    "vehicles": ("Vehicles", "Live vehicle state, telemetry and camera context."),
    "transactions": ("Transactions", "Blockchain activity and persisted ledger records."),
    "access": ("Access Control", "Authenticated vehicle actions and owner recovery."),
    "ownership": ("Ownership", "Vehicle identity, lock state and ownership evidence."),
    "audit": ("Audit Logs", "Runtime, blockchain and reviewer-facing audit trail."),
    "threats": ("Threat Detection", "Source-derived warnings and ledger anomaly signals."),
    "alerts": ("Alerts", "Current provider, runtime and security-boundary alerts."),
    "scan": ("Security Scan", "Cryptographic, identity, consensus and privacy metadata."),
    "contracts": ("Smart Contract", "Consensus, contribution and chain-head metadata."),
    "nodes": ("Nodes", "Observed V2X peers and local backend health."),
    "settings": ("Settings", "Safe runtime configuration and dashboard controls."),
}


class ReferenceSmartCarDashboard(ProductionSmartCarDashboard):
    """Full reference-inspired shell with functional multi-page navigation."""

    # ------------------------------------------------------------------ shell

    def _setup_reference_fonts(self) -> None:
        self.f_brand_small = font.Font(family="Segoe UI", size=10, weight="bold")
        self.f_brand = font.Font(family="Segoe UI", size=16, weight="bold")
        self.f_title = font.Font(family="Segoe UI", size=18, weight="bold")
        self.f_page_title = font.Font(family="Segoe UI", size=18, weight="bold")
        self.f_head = font.Font(family="Segoe UI", size=11, weight="bold")
        self.f_body = font.Font(family="Segoe UI", size=10)
        self.f_small = font.Font(family="Segoe UI", size=9)
        self.f_tiny = font.Font(family="Segoe UI", size=8)
        self.f_kpi = font.Font(family="Segoe UI", size=23, weight="bold")
        self.f_big = font.Font(family="Segoe UI", size=27, weight="bold")
        self.f_mono = font.Font(family="Consolas", size=9)

    def _configure_reference_styles(self) -> None:
        style = ttk.Style()
        try:
            style.theme_use("clam")
        except Exception:
            pass
        style.configure(
            "Reference.Treeview",
            background="#071426",
            fieldbackground="#071426",
            foreground=TEXT,
            rowheight=30,
            borderwidth=0,
            font=("Segoe UI", 9),
        )
        style.configure(
            "Reference.Treeview.Heading",
            background="#101f38",
            foreground="#d5def0",
            relief="flat",
            borderwidth=0,
            font=("Segoe UI", 9, "bold"),
        )
        style.map(
            "Reference.Treeview",
            background=[("selected", "#253b70")],
            foreground=[("selected", "#ffffff")],
        )

    def _build_ui(self) -> None:
        self._setup_reference_fonts()
        self._configure_reference_styles()
        self.title("OmniGuard V2X — Next-Gen Vehicle Security")
        self.geometry("1600x960")
        self.minsize(1320, 820)
        self.configure(bg=BG)

        self._reference_pages: Dict[str, tk.Frame] = {}
        self._reference_buttons: Dict[str, tk.Button] = {}
        self._active_page = "overview"

        self.shell = tk.Frame(self, bg=BG)
        self.shell.pack(fill="both", expand=True)

        self._build_reference_sidebar()

        self.reference_main = tk.Frame(self.shell, bg=BG)
        self.reference_main.pack(side="right", fill="both", expand=True)

        self._build_reference_topbar()

        self.reference_host = tk.Frame(self.reference_main, bg=BG)
        self.reference_host.pack(fill="both", expand=True, padx=18, pady=(0, 14))
        self.reference_host.grid_rowconfigure(0, weight=1)
        self.reference_host.grid_columnconfigure(0, weight=1)

        for key in PAGE_TITLES:
            frame = tk.Frame(self.reference_host, bg=BG)
            frame.grid(row=0, column=0, sticky="nsew")
            self._reference_pages[key] = frame

        self._build_dashboard_page()
        self._build_vehicles_page()
        self._build_transactions_page()
        self._build_access_page()
        self._build_ownership_page()
        self._build_audit_page()
        self._build_threats_page()
        self._build_alerts_page()
        self._build_scan_page()
        self._build_contracts_page()
        self._build_nodes_page()
        self._build_settings_page()

        self._show_reference_page("overview")

    def _build_reference_sidebar(self) -> None:
        self.sidebar = tk.Frame(self.shell, bg=SIDEBAR, width=250)
        self.sidebar.pack(side="left", fill="y")
        self.sidebar.pack_propagate(False)

        brand = tk.Frame(self.sidebar, bg=SIDEBAR, padx=20, pady=20)
        brand.pack(fill="x")
        shield = tk.Canvas(brand, width=44, height=48, bg=SIDEBAR, highlightthickness=0)
        shield.pack(side="left", padx=(0, 12))
        shield.create_polygon(22, 3, 39, 12, 36, 33, 22, 45, 8, 33, 5, 12, fill="#15254c", outline=INDIGO, width=2)
        shield.create_text(22, 23, text="⛨", fill=INDIGO, font=("Segoe UI Symbol", 18))

        brand_text = tk.Frame(brand, bg=SIDEBAR)
        brand_text.pack(side="left", fill="x", expand=True)
        tk.Label(brand_text, text="Next-Gen", bg=SIDEBAR, fg=TEXT, font=self.f_brand_small).pack(anchor="w")
        tk.Label(brand_text, text="Vehicle Security", bg=SIDEBAR, fg=TEXT, font=self.f_brand).pack(anchor="w")
        tk.Label(brand_text, text="Blockchain-Powered Protection", bg=SIDEBAR, fg=MUTED, font=self.f_tiny).pack(anchor="w", pady=(2, 0))

        for group, items in MENU_GROUPS:
            tk.Label(self.sidebar, text=group, bg=SIDEBAR, fg="#7082a2", font=self.f_tiny, anchor="w", padx=22, pady=8).pack(fill="x")
            for key, title, icon in items:
                button = tk.Button(
                    self.sidebar,
                    text=f"  {icon}    {title}",
                    command=lambda p=key: self._show_reference_page(p),
                    anchor="w",
                    bg=SIDEBAR,
                    fg="#d3dced",
                    activebackground="#17284a",
                    activeforeground="#ffffff",
                    relief="flat",
                    bd=0,
                    highlightthickness=0,
                    padx=14,
                    pady=9,
                    font=self.f_body,
                    cursor="hand2",
                )
                button.pack(fill="x", padx=14, pady=1)
                self._reference_buttons[key] = button

        spacer = tk.Frame(self.sidebar, bg=SIDEBAR)
        spacer.pack(fill="both", expand=True)

        system = tk.Frame(self.sidebar, bg="#0c1b30", highlightthickness=1, highlightbackground="#183155", padx=12, pady=11)
        system.pack(fill="x", padx=18, pady=(8, 14))
        self.system_status_icon = tk.Label(system, text="◉", bg="#0c1b30", fg=ORANGE, font=("Segoe UI Symbol", 17))
        self.system_status_icon.pack(side="left", padx=(0, 10))
        status_text = tk.Frame(system, bg="#0c1b30")
        status_text.pack(side="left", fill="x", expand=True)
        tk.Label(status_text, text="System Status", bg="#0c1b30", fg=TEXT, font=self.f_head).pack(anchor="w")
        self.system_status_label = tk.Label(status_text, text="Checking runtime…", bg="#0c1b30", fg=ORANGE, font=self.f_tiny)
        self.system_status_label.pack(anchor="w", pady=(2, 0))

        footer = tk.Frame(self.sidebar, bg=SIDEBAR, padx=20, pady=13)
        footer.pack(fill="x")
        tk.Label(footer, text="© 2026 OmniGuard V2X", bg=SIDEBAR, fg="#667794", font=self.f_tiny).pack(anchor="w")
        tk.Label(footer, text="v3.0.3", bg=SIDEBAR, fg="#667794", font=self.f_tiny).pack(anchor="w", pady=(2, 0))

    def _build_reference_topbar(self) -> None:
        top = tk.Frame(self.reference_main, bg=TOPBAR, padx=20, pady=14)
        top.pack(fill="x", padx=18, pady=(14, 14))

        heading = tk.Frame(top, bg=TOPBAR)
        heading.pack(side="left", fill="x", expand=True)
        self.reference_title = tk.Label(heading, text="Dashboard", bg=TOPBAR, fg=TEXT, font=self.f_title)
        self.reference_title.pack(anchor="w")
        self.reference_subtitle = tk.Label(heading, text=PAGE_TITLES["overview"][1], bg=TOPBAR, fg=MUTED, font=self.f_body)
        self.reference_subtitle.pack(anchor="w", pady=(3, 0))

        controls = tk.Frame(top, bg=TOPBAR)
        controls.pack(side="right")

        network = tk.Frame(controls, bg=CARD, highlightthickness=1, highlightbackground=BORDER, padx=12, pady=8)
        network.pack(side="left", padx=(0, 10))
        tk.Label(network, text="BLOCKCHAIN NETWORK", bg=CARD, fg=MUTED, font=self.f_tiny).pack(anchor="w")
        self.top_connection = tk.Label(network, text=NOT_CONNECTED, bg=CARD, fg=ORANGE, font=self.f_small)
        self.top_connection.pack(anchor="w")
        self.connection_badge = self.top_connection

        backend = tk.Button(
            controls,
            text="Network  •  Nodes",
            command=lambda: self._show_reference_page("nodes"),
            bg=CARD,
            fg="#dce4f3",
            activebackground=CARD_3,
            activeforeground="#ffffff",
            relief="flat",
            bd=0,
            padx=16,
            pady=12,
            cursor="hand2",
            font=self.f_small,
        )
        backend.pack(side="left", padx=(0, 10))

        tk.Button(
            controls,
            text="△",
            command=lambda: self._show_reference_page("alerts"),
            bg=CARD,
            fg=TEXT,
            activebackground=CARD_3,
            activeforeground="#ffffff",
            relief="flat",
            bd=0,
            width=3,
            pady=11,
            cursor="hand2",
            font=self.f_head,
        ).pack(side="left", padx=(0, 10))

        avatar = tk.Canvas(controls, width=40, height=40, bg=TOPBAR, highlightthickness=0)
        avatar.pack(side="left")
        avatar.create_oval(3, 3, 37, 37, fill="#d5dce8", outline="#ffffff")
        avatar.create_text(20, 20, text="OI", fill="#18233a", font=("Segoe UI", 9, "bold"))

        self.backend_label = tk.Label(top, text=type(self.blockchain).__name__, bg=TOPBAR, fg="#5f7190", font=self.f_tiny)
        self.backend_label.pack(side="bottom", anchor="e")
        self.updated_label = tk.Label(top, text="Updated --", bg=TOPBAR, fg="#5f7190", font=self.f_tiny)
        self.updated_label.pack(side="bottom", anchor="e", padx=(0, 125))

    def _show_reference_page(self, key: str) -> None:
        page = self._reference_pages.get(key)
        if page is None:
            return
        self._active_page = key
        page.tkraise()
        title, subtitle = PAGE_TITLES[key]
        self.reference_title.configure(text=title)
        self.reference_subtitle.configure(text=subtitle)
        for page_key, button in self._reference_buttons.items():
            active = page_key == key
            button.configure(
                bg=INDIGO if active else SIDEBAR,
                fg="#ffffff" if active else "#d3dced",
                activebackground=INDIGO if active else "#17284a",
            )

    # ------------------------------------------------------------- UI helpers

    def _card(self, parent: tk.Widget, title: str, min_height: int = 0) -> Dict[str, Any]:
        outer = tk.Frame(parent, bg=BORDER, padx=1, pady=1)
        inner = tk.Frame(outer, bg=CARD, padx=14, pady=12, height=min_height)
        inner.pack(fill="both", expand=True)
        if min_height:
            inner.pack_propagate(False)
        header = tk.Frame(inner, bg=CARD)
        header.pack(fill="x")
        tk.Label(header, text=title, bg=CARD, fg=TEXT, font=self.f_head).pack(side="left")
        body = tk.Frame(inner, bg=CARD)
        body.pack(fill="both", expand=True, pady=(10, 0))
        return {"outer": outer, "inner": inner, "body": body, "header": header}

    def _metric_tile(self, parent: tk.Widget, title: str, accent: str, icon: str) -> Dict[str, tk.Label]:
        outer = tk.Frame(parent, bg=BORDER, padx=1, pady=1)
        inner = tk.Frame(outer, bg=CARD, padx=14, pady=12)
        inner.pack(fill="both", expand=True)
        left = tk.Frame(inner, bg=CARD)
        left.pack(side="left", fill="both", expand=True)
        tk.Label(left, text=title, bg=CARD, fg="#c7d1e5", font=self.f_small).pack(anchor="w")
        value = tk.Label(left, text=UNAVAILABLE, bg=CARD, fg=TEXT, font=self.f_kpi)
        value.pack(anchor="w", pady=(5, 1))
        note = tk.Label(left, text="Waiting for source", bg=CARD, fg=MUTED, font=self.f_tiny)
        note.pack(anchor="w")

        bubble = tk.Canvas(inner, width=58, height=58, bg=CARD, highlightthickness=0)
        bubble.pack(side="right")
        bubble.create_oval(4, 4, 54, 54, fill=accent, outline="")
        bubble.create_oval(10, 10, 48, 48, outline="#ffffff", width=1)
        bubble.create_text(29, 29, text=icon, fill="#ffffff", font=("Segoe UI Symbol", 16))
        return {"outer": outer, "value": value, "note": note}

    def _status_row(self, parent: tk.Widget, label: str) -> tk.Label:
        row = tk.Frame(parent, bg=CARD_2, padx=10, pady=7)
        row.pack(fill="x", pady=2)
        tk.Label(row, text=label, bg=CARD_2, fg="#c5d0e4", font=self.f_small).pack(side="left")
        value = tk.Label(row, text=UNAVAILABLE, bg=CARD_2, fg=TEXT, font=self.f_small)
        value.pack(side="right")
        return value

    def _feed_row(self, parent: tk.Widget, title: str, subtitle: str = "", right: str = "", severity: str = "") -> None:
        row = tk.Frame(parent, bg=CARD_2, padx=10, pady=8)
        row.pack(fill="x", pady=3)
        icon_color = {"high": RED, "medium": ORANGE, "ok": GREEN, "boundary": PURPLE}.get(severity, CYAN)
        icon = tk.Canvas(row, width=30, height=30, bg=CARD_2, highlightthickness=0)
        icon.pack(side="left", padx=(0, 9))
        icon.create_oval(3, 3, 27, 27, fill="#122740", outline="")
        icon.create_text(15, 15, text="◇", fill=icon_color, font=("Segoe UI Symbol", 10))
        copy = tk.Frame(row, bg=CARD_2)
        copy.pack(side="left", fill="both", expand=True)
        tk.Label(copy, text=title, bg=CARD_2, fg=TEXT, font=self.f_small, anchor="w").pack(anchor="w")
        if subtitle:
            tk.Label(copy, text=subtitle, bg=CARD_2, fg=MUTED, font=self.f_tiny, anchor="w").pack(anchor="w", pady=(2, 0))
        if right:
            tk.Label(row, text=right, bg=CARD_2, fg="#b9c5da", font=self.f_tiny).pack(side="right")

    def _page_header(self, parent: tk.Widget, title: str, subtitle: str) -> None:
        box = tk.Frame(parent, bg=BG)
        box.pack(fill="x", pady=(0, 12))
        tk.Label(box, text=title, bg=BG, fg=TEXT, font=self.f_page_title).pack(anchor="w")
        tk.Label(box, text=subtitle, bg=BG, fg=MUTED, font=self.f_small).pack(anchor="w", pady=(2, 0))

    # --------------------------------------------------------------- Dashboard

    def _build_dashboard_page(self) -> None:
        page = self._reference_pages["overview"]
        page.grid_columnconfigure(0, weight=1)
        page.grid_rowconfigure(1, weight=4)
        page.grid_rowconfigure(2, weight=3)

        metrics = tk.Frame(page, bg=BG)
        metrics.grid(row=0, column=0, sticky="ew", pady=(0, 12))
        self.dashboard_metrics: Dict[str, Dict[str, tk.Label]] = {}
        metric_specs = (
            ("vehicles", "Total Vehicles", INDIGO, "◇"),
            ("transactions", "Total Transactions", "#138a5d", "⇄"),
            ("nodes", "Active Nodes", "#1459c8", "≋"),
            ("security", "Security Score", "#4930a8", "⛨"),
        )
        for idx, (key, title, accent, icon) in enumerate(metric_specs):
            metrics.grid_columnconfigure(idx, weight=1, uniform="metric")
            tile = self._metric_tile(metrics, title, accent, icon)
            tile["outer"].grid(row=0, column=idx, sticky="nsew", padx=(0 if idx == 0 else 5, 0 if idx == 3 else 5))
            self.dashboard_metrics[key] = tile

        middle = tk.Frame(page, bg=BG)
        middle.grid(row=1, column=0, sticky="nsew")
        middle.grid_columnconfigure(0, weight=5)
        middle.grid_columnconfigure(1, weight=5)
        middle.grid_rowconfigure(0, weight=1)

        vehicle = self._card(middle, "Vehicle Status Overview", 350)
        vehicle["outer"].grid(row=0, column=0, sticky="nsew", padx=(0, 7))
        visual_side = tk.Frame(vehicle["body"], bg=CARD)
        visual_side.pack(side="left", fill="both", expand=True, padx=(0, 10))
        self.dashboard_vehicle_canvas = tk.Canvas(visual_side, bg="#071325", highlightthickness=0)
        self.dashboard_vehicle_canvas.pack(fill="both", expand=True)
        self.dashboard_vehicle_canvas.bind("<Configure>", lambda _e: self._draw_vehicle_art(self.dashboard_vehicle_canvas))

        status_side = tk.Frame(vehicle["body"], bg=CARD, width=230)
        status_side.pack(side="left", fill="y")
        status_side.pack_propagate(False)
        self.dashboard_vehicle_rows = {
            "vehicle_id": self._status_row(status_side, "Vehicle ID"),
            "ownership": self._status_row(status_side, "Ownership"),
            "access": self._status_row(status_side, "Access Control"),
            "integrity": self._status_row(status_side, "Data Integrity"),
            "updated": self._status_row(status_side, "Last Updated"),
        }
        tk.Button(
            status_side,
            text="View Vehicle Details",
            command=lambda: self._show_reference_page("vehicles"),
            bg=INDIGO,
            fg="#ffffff",
            activebackground=INDIGO_2,
            activeforeground="#ffffff",
            relief="flat",
            bd=0,
            pady=8,
            cursor="hand2",
            font=self.f_small,
        ).pack(fill="x", pady=(9, 0))

        activity = self._card(middle, "Recent Blockchain Activity", 350)
        activity["outer"].grid(row=0, column=1, sticky="nsew", padx=(7, 0))
        tk.Button(
            activity["header"],
            text="View All",
            command=lambda: self._show_reference_page("transactions"),
            bg=CARD_2,
            fg="#d8e1f1",
            activebackground=CARD_3,
            activeforeground="#ffffff",
            relief="flat",
            bd=0,
            padx=11,
            pady=5,
            cursor="hand2",
            font=self.f_tiny,
        ).pack(side="right")
        self.dashboard_activity_feed = tk.Frame(activity["body"], bg=CARD)
        self.dashboard_activity_feed.pack(fill="both", expand=True)

        bottom = tk.Frame(page, bg=BG)
        bottom.grid(row=2, column=0, sticky="nsew", pady=(12, 0))
        for col in range(3):
            bottom.grid_columnconfigure(col, weight=1, uniform="bottom")
        bottom.grid_rowconfigure(0, weight=1)

        network = self._card(bottom, "Network Status", 270)
        network["outer"].grid(row=0, column=0, sticky="nsew", padx=(0, 7))
        self.dashboard_network_canvas = tk.Canvas(network["body"], bg="#071325", highlightthickness=0, height=170)
        self.dashboard_network_canvas.pack(fill="both", expand=True)
        self.dashboard_network_footer = tk.Label(network["body"], text=NO_DATA, bg=CARD, fg=GREEN, font=self.f_small, anchor="w", justify="left")
        self.dashboard_network_footer.pack(fill="x", pady=(7, 0))

        alerts = self._card(bottom, "Security Alerts", 270)
        alerts["outer"].grid(row=0, column=1, sticky="nsew", padx=7)
        self.dashboard_alert_feed = tk.Frame(alerts["body"], bg=CARD)
        self.dashboard_alert_feed.pack(fill="both", expand=True)
        tk.Button(
            alerts["body"],
            text="View All Alerts",
            command=lambda: self._show_reference_page("alerts"),
            bg=INDIGO,
            fg="#ffffff",
            activebackground=INDIGO_2,
            activeforeground="#ffffff",
            relief="flat",
            bd=0,
            pady=7,
            cursor="hand2",
            font=self.f_small,
        ).pack(fill="x", pady=(6, 0))

        transactions = self._card(bottom, "Transaction Overview", 270)
        transactions["outer"].grid(row=0, column=2, sticky="nsew", padx=(7, 0))
        self.dashboard_transaction_canvas = tk.Canvas(transactions["body"], bg="#071325", highlightthickness=0, height=170)
        self.dashboard_transaction_canvas.pack(fill="both", expand=True)
        self.dashboard_transaction_footer = tk.Label(transactions["body"], text=NO_DATA, bg=CARD, fg="#c7d3e7", font=self.f_small, anchor="w")
        self.dashboard_transaction_footer.pack(fill="x", pady=(7, 0))

    # ------------------------------------------------------------- other pages

    def _build_vehicles_page(self) -> None:
        page = self._reference_pages["vehicles"]
        self._page_header(page, *PAGE_TITLES["vehicles"])
        row = tk.Frame(page, bg=BG)
        row.pack(fill="both", expand=True)
        left = tk.Frame(row, bg=BG)
        left.pack(side="left", fill="both", expand=True, padx=(0, 7))
        right = tk.Frame(row, bg=BG)
        right.pack(side="left", fill="both", expand=True, padx=(7, 0))

        state = self._card(left, "Vehicle State", 330)
        state["outer"].pack(fill="both", expand=True)
        self.vehicle_rows = {
            "vehicle_id": self._status_row(state["body"], "Vehicle ID"),
            "lock": self._status_row(state["body"], "Ownership / Lock"),
            "engine": self._status_row(state["body"], "Engine"),
            "emergency": self._status_row(state["body"], "Emergency Brake"),
            "safe": self._status_row(state["body"], "Safe Mode"),
            "speed": self._status_row(state["body"], "Speed"),
            "rpm": self._status_row(state["body"], "RPM"),
            "fuel": self._status_row(state["body"], "Fuel"),
            "temperature": self._status_row(state["body"], "Temperature"),
            "throttle": self._status_row(state["body"], "Throttle"),
        }
        tk.Button(state["body"], text="Open Access Control", command=lambda: self._show_reference_page("access"), bg=INDIGO, fg="#fff", relief="flat", pady=8, cursor="hand2").pack(fill="x", pady=(8, 0))

        speed = self._card(right, "Live Speed", 330)
        speed["outer"].pack(fill="both", expand=True)
        self.speed_canvas = tk.Canvas(speed["body"], bg="#071325", highlightthickness=0)
        self.speed_canvas.pack(fill="both", expand=True)

        lower = tk.Frame(page, bg=BG)
        lower.pack(fill="both", expand=True, pady=(12, 0))
        camera = self._card(lower, "Live Camera / Object Detection", 300)
        camera["outer"].pack(side="left", fill="both", expand=True, padx=(0, 7))
        self.camera_label = tk.Label(camera["body"], text="Camera Not Connected", bg="#071325", fg=ORANGE, font=self.f_head)
        self.camera_label.pack(fill="both", expand=True)
        self.vehicle_detection_label = tk.Label(camera["body"], text=NO_DATA, bg=CARD, fg=MUTED, font=self.f_tiny, anchor="w")
        self.vehicle_detection_label.pack(fill="x", pady=(5, 0))

        scene = self._card(lower, "V2X Road Scene", 300)
        scene["outer"].pack(side="left", fill="both", expand=True, padx=(7, 0))
        self.road_canvas = tk.Canvas(scene["body"], bg="#071325", highlightthickness=0)
        self.road_canvas.pack(fill="both", expand=True)

    def _build_transactions_page(self) -> None:
        page = self._reference_pages["transactions"]
        self._page_header(page, *PAGE_TITLES["transactions"])
        top = tk.Frame(page, bg=BG)
        top.pack(fill="both", expand=True)
        chart = self._card(top, "Transaction History", 280)
        chart["outer"].pack(side="left", fill="both", expand=True, padx=(0, 7))
        self.transactions_canvas = tk.Canvas(chart["body"], bg="#071325", highlightthickness=0)
        self.transactions_canvas.pack(fill="both", expand=True)
        activity = self._card(top, "Recent Activity", 280)
        activity["outer"].pack(side="left", fill="both", expand=True, padx=(7, 0))
        self.transactions_activity = tk.Frame(activity["body"], bg=CARD)
        self.transactions_activity.pack(fill="both", expand=True)

        ledger = self._card(page, "Ledger Records", 330)
        ledger["outer"].pack(fill="both", expand=True, pady=(12, 0))
        self.ledger_tree = ttk.Treeview(ledger["body"], columns=("index", "time", "event", "hash"), show="headings", style="Reference.Treeview", height=9)
        for col, title, width in (("index", "Index", 80), ("time", "Timestamp", 190), ("event", "Event", 430), ("hash", "Block Hash", 340)):
            self.ledger_tree.heading(col, text=title)
            self.ledger_tree.column(col, width=width, anchor="w")
        self.ledger_tree.pack(fill="both", expand=True)

    def _build_access_page(self) -> None:
        page = self._reference_pages["access"]
        self._page_header(page, *PAGE_TITLES["access"])
        row = tk.Frame(page, bg=BG)
        row.pack(fill="both", expand=True)

        auth = self._card(row, "Authentication", 340)
        auth["outer"].pack(side="left", fill="both", expand=True, padx=(0, 7))
        tk.Label(auth["body"], text="Authentication Token", bg=CARD, fg=MUTED, font=self.f_small).pack(anchor="w")
        self.token_entry = tk.Entry(auth["body"], bg="#071325", fg=TEXT, insertbackground=TEXT, relief="flat", show="•", font=self.f_body)
        self.token_entry.pack(fill="x", pady=(5, 10), ipady=8)
        tk.Button(auth["body"], text="AUTH", command=self._do_auth, bg=INDIGO, fg="#fff", activebackground=INDIGO_2, relief="flat", pady=9, cursor="hand2").pack(fill="x")
        tk.Label(auth["body"], text="The configured secret is never displayed by the dashboard.", bg=CARD, fg=MUTED, font=self.f_tiny, wraplength=420, justify="left").pack(anchor="w", pady=(10, 0))

        actions = self._card(row, "Authenticated Vehicle Actions", 340)
        actions["outer"].pack(side="left", fill="both", expand=True, padx=7)
        for title, command, tone in (
            ("START ENGINE", self._do_start, GREEN),
            ("STOP ENGINE", self._do_stop, ORANGE),
            ("LOCK VEHICLE", self._do_lock, BLUE),
        ):
            tk.Button(actions["body"], text=title, command=command, bg=CARD_2, fg=TEXT, activebackground=tone, activeforeground="#fff", relief="flat", pady=10, cursor="hand2").pack(fill="x", pady=4)
        self.access_state_label = tk.Label(actions["body"], text=NO_DATA, bg=CARD, fg=MUTED, font=self.f_small, justify="left", anchor="nw")
        self.access_state_label.pack(fill="x", pady=(12, 0))

        recovery = self._card(row, "Owner Recovery", 340)
        recovery["outer"].pack(side="left", fill="both", expand=True, padx=(7, 0))
        tk.Label(recovery["body"], text="Owner / Recovery Identifier", bg=CARD, fg=MUTED, font=self.f_small).pack(anchor="w")
        self.owner_entry = tk.Entry(recovery["body"], bg="#071325", fg=TEXT, insertbackground=TEXT, relief="flat", font=self.f_body)
        self.owner_entry.pack(fill="x", pady=(5, 9), ipady=8)
        self.owner_force_reset_var = tk.BooleanVar(value=False)
        tk.Checkbutton(recovery["body"], text="Force Chain Reset", variable=self.owner_force_reset_var, bg=CARD, fg="#d6deed", selectcolor="#071325", activebackground=CARD, activeforeground="#fff", font=self.f_small).pack(anchor="w")
        tk.Button(recovery["body"], text="RECOVER", command=self._do_recover, bg=INDIGO, fg="#fff", activebackground=INDIGO_2, relief="flat", pady=9, cursor="hand2").pack(fill="x", pady=(10, 0))

    def _build_ownership_page(self) -> None:
        page = self._reference_pages["ownership"]
        self._page_header(page, *PAGE_TITLES["ownership"])
        row = tk.Frame(page, bg=BG)
        row.pack(fill="both", expand=True)
        status = self._card(row, "Ownership State", 350)
        status["outer"].pack(side="left", fill="both", expand=True, padx=(0, 7))
        self.ownership_rows = {
            "vehicle_id": self._status_row(status["body"], "Vehicle ID"),
            "lock": self._status_row(status["body"], "Lock State"),
            "authenticity": self._status_row(status["body"], "Identity Authenticity"),
            "admission": self._status_row(status["body"], "Admission Policy"),
            "sybil": self._status_row(status["body"], "Sybil Resistance"),
        }
        events = self._card(row, "Ownership Ledger Activity", 350)
        events["outer"].pack(side="left", fill="both", expand=True, padx=(7, 0))
        self.ownership_feed = tk.Frame(events["body"], bg=CARD)
        self.ownership_feed.pack(fill="both", expand=True)

    def _build_audit_page(self) -> None:
        page = self._reference_pages["audit"]
        self._page_header(page, *PAGE_TITLES["audit"])
        audit = self._card(page, "Audit Trail", 430)
        audit["outer"].pack(fill="both", expand=True)
        self.audit_text = tk.Text(audit["body"], bg="#071325", fg=TEXT, insertbackground=TEXT, relief="flat", bd=0, font=self.f_mono, wrap="word", padx=12, pady=10)
        self.audit_text.pack(fill="both", expand=True)
        self.audit_text.configure(state="disabled")
        reviewer = self._card(page, "Reviewer / Security Boundary", 190)
        reviewer["outer"].pack(fill="both", expand=True, pady=(12, 0))
        self.audit_boundary_label = tk.Label(reviewer["body"], text=NO_DATA, bg=CARD, fg=MUTED, font=self.f_body, justify="left", anchor="nw", wraplength=1100)
        self.audit_boundary_label.pack(fill="both", expand=True)

    def _build_threats_page(self) -> None:
        page = self._reference_pages["threats"]
        self._page_header(page, *PAGE_TITLES["threats"])
        row = tk.Frame(page, bg=BG)
        row.pack(fill="both", expand=True)
        chart = self._card(row, "Ledger / Runtime Signal", 390)
        chart["outer"].pack(side="left", fill="both", expand=True, padx=(0, 7))
        self.anomaly_canvas = tk.Canvas(chart["body"], bg="#071325", highlightthickness=0)
        self.anomaly_canvas.pack(fill="both", expand=True)
        summary = self._card(row, "Threat & Boundary Summary", 390)
        summary["outer"].pack(side="left", fill="both", expand=True, padx=(7, 0))
        self.threat_feed = tk.Frame(summary["body"], bg=CARD)
        self.threat_feed.pack(fill="both", expand=True)

    def _build_alerts_page(self) -> None:
        page = self._reference_pages["alerts"]
        self._page_header(page, *PAGE_TITLES["alerts"])
        card = self._card(page, "Current Alerts", 560)
        card["outer"].pack(fill="both", expand=True)
        self.alerts_feed = tk.Frame(card["body"], bg=CARD)
        self.alerts_feed.pack(fill="both", expand=True)

    def _build_scan_page(self) -> None:
        page = self._reference_pages["scan"]
        self._page_header(page, *PAGE_TITLES["scan"])
        grid = tk.Frame(page, bg=BG)
        grid.pack(fill="both", expand=True)
        for col in range(2):
            grid.grid_columnconfigure(col, weight=1)
        for row in range(2):
            grid.grid_rowconfigure(row, weight=1)
        self.scan_labels: Dict[str, tk.Label] = {}
        for idx, (key, title) in enumerate((
            ("security", "Cryptographic Capability"),
            ("identity", "Identity / Sybil Boundary"),
            ("consensus", "Consensus Boundary"),
            ("privacy", "Privacy / FL Validation"),
        )):
            card = self._card(grid, title, 270)
            card["outer"].grid(row=idx // 2, column=idx % 2, sticky="nsew", padx=(0 if idx % 2 == 0 else 6, 6 if idx % 2 == 0 else 0), pady=(0 if idx < 2 else 6, 6 if idx < 2 else 0))
            label = tk.Label(card["body"], text=NO_DATA, bg=CARD, fg="#dce5f4", font=self.f_body, justify="left", anchor="nw", wraplength=560)
            label.pack(fill="both", expand=True)
            self.scan_labels[key] = label

    def _build_contracts_page(self) -> None:
        page = self._reference_pages["contracts"]
        self._page_header(page, *PAGE_TITLES["contracts"])
        row = tk.Frame(page, bg=BG)
        row.pack(fill="both", expand=True)
        consensus = self._card(row, "Consensus / Contract Metadata", 360)
        consensus["outer"].pack(side="left", fill="both", expand=True, padx=(0, 7))
        self.contract_consensus_label = tk.Label(consensus["body"], text=NO_DATA, bg=CARD, fg="#dce5f4", font=self.f_body, justify="left", anchor="nw", wraplength=520)
        self.contract_consensus_label.pack(fill="both", expand=True)
        boundary = self._card(row, "Complexity / Contribution", 360)
        boundary["outer"].pack(side="left", fill="both", expand=True, padx=(7, 0))
        self.contract_boundary_label = tk.Label(boundary["body"], text=NO_DATA, bg=CARD, fg="#dce5f4", font=self.f_body, justify="left", anchor="nw", wraplength=520)
        self.contract_boundary_label.pack(fill="both", expand=True)
        chain = self._card(page, "Current Chain Head", 210)
        chain["outer"].pack(fill="both", expand=True, pady=(12, 0))
        self.contract_chain_label = tk.Label(chain["body"], text=NO_DATA, bg=CARD, fg=MUTED, font=self.f_mono, justify="left", anchor="nw", wraplength=1100)
        self.contract_chain_label.pack(fill="both", expand=True)

    def _build_nodes_page(self) -> None:
        page = self._reference_pages["nodes"]
        self._page_header(page, *PAGE_TITLES["nodes"])
        row = tk.Frame(page, bg=BG)
        row.pack(fill="both", expand=True)
        network = self._card(row, "V2X Node Map", 380)
        network["outer"].pack(side="left", fill="both", expand=True, padx=(0, 7))
        self.radar_canvas = tk.Canvas(network["body"], bg="#071325", highlightthickness=0)
        self.radar_canvas.pack(fill="both", expand=True)
        health = self._card(row, "Network Health", 380)
        health["outer"].pack(side="left", fill="both", expand=True, padx=(7, 0))
        self.health_text = tk.Label(health["body"], text=NO_DATA, bg=CARD, fg="#dce5f4", font=self.f_body, justify="left", anchor="nw")
        self.health_text.pack(fill="both", expand=True)
        peers = self._card(page, "Observed Peers", 270)
        peers["outer"].pack(fill="both", expand=True, pady=(12, 0))
        self.peer_tree = ttk.Treeview(peers["body"], columns=("id", "distance", "heading", "speed"), show="headings", style="Reference.Treeview", height=7)
        for col, title, width in (("id", "Peer", 240), ("distance", "Distance", 170), ("heading", "Heading", 170), ("speed", "Speed", 170)):
            self.peer_tree.heading(col, text=title)
            self.peer_tree.column(col, width=width, anchor="w")
        self.peer_tree.pack(fill="both", expand=True)

    def _build_settings_page(self) -> None:
        page = self._reference_pages["settings"]
        self._page_header(page, *PAGE_TITLES["settings"])
        row = tk.Frame(page, bg=BG)
        row.pack(fill="both", expand=True)
        runtime = self._card(row, "Runtime Configuration", 360)
        runtime["outer"].pack(side="left", fill="both", expand=True, padx=(0, 7))
        self.settings_rows = {
            "backend": self._status_row(runtime["body"], "Backend"),
            "vehicle": self._status_row(runtime["body"], "Vehicle ID"),
            "camera": self._status_row(runtime["body"], "Camera Index"),
            "refresh": self._status_row(runtime["body"], "Refresh Interval"),
            "chain": self._status_row(runtime["body"], "GUI Chain File"),
            "auth": self._status_row(runtime["body"], "Auth Credential"),
            "password": self._status_row(runtime["body"], "Password Credential"),
        }
        controls = self._card(row, "Dashboard Controls", 360)
        controls["outer"].pack(side="left", fill="both", expand=True, padx=(7, 0))
        tk.Label(controls["body"], text="Runtime secrets are never displayed. Missing provider values remain explicitly unavailable.", bg=CARD, fg=MUTED, font=self.f_body, justify="left", wraplength=480).pack(anchor="w")
        tk.Button(controls["body"], text="Refresh Now", command=self.manual_refresh, bg=INDIGO, fg="#fff", activebackground=INDIGO_2, relief="flat", pady=9, cursor="hand2").pack(fill="x", pady=(15, 7))
        tk.Button(controls["body"], text="Open Nodes", command=lambda: self._show_reference_page("nodes"), bg=CARD_2, fg=TEXT, activebackground=CARD_3, relief="flat", pady=9, cursor="hand2").pack(fill="x", pady=7)
        tk.Button(controls["body"], text="Open Security Scan", command=lambda: self._show_reference_page("scan"), bg=CARD_2, fg=TEXT, activebackground=CARD_3, relief="flat", pady=9, cursor="hand2").pack(fill="x", pady=7)

    # --------------------------------------------------------------- data truth

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
    def _bool_text(cls, point: Any, true_text: str, false_text: str) -> str:
        value, ready = cls._point_result(point)
        if not ready or not isinstance(value, bool):
            return UNAVAILABLE
        return true_text if value else false_text

    @staticmethod
    def _metadata(point: Any) -> Dict[str, Any]:
        if not isinstance(point, dict) or point.get("status") in {"error", "unavailable"}:
            return {}
        value = point.get("value")
        return value if isinstance(value, dict) else {}

    @staticmethod
    def _chain_rows(chain: Any) -> Tuple[List[Any], bool]:
        if isinstance(chain, (list, tuple)):
            return list(chain), True
        return [], False

    @staticmethod
    def _block_fields(block: Any) -> Dict[str, Any]:
        if isinstance(block, dict):
            return {
                "index": block.get("index", UNAVAILABLE),
                "timestamp": block.get("timestamp", UNAVAILABLE),
                "event": block.get("event_data", block.get("event", "event unavailable")),
                "hash": block.get("block_hash", block.get("hash", "")),
                "vehicle": block.get("vehicle_id", UNAVAILABLE),
            }
        return {
            "index": getattr(block, "index", UNAVAILABLE),
            "timestamp": getattr(block, "timestamp", UNAVAILABLE),
            "event": getattr(block, "event_data", "event unavailable"),
            "hash": getattr(block, "block_hash", getattr(block, "hash", "")),
            "vehicle": getattr(block, "vehicle_id", UNAVAILABLE),
        }

    @staticmethod
    def _numeric(mapping: Dict[str, Any], *names: str) -> Optional[float]:
        for name in names:
            value = mapping.get(name) if isinstance(mapping, dict) else None
            if isinstance(value, (int, float)) and not isinstance(value, bool):
                return float(value)
            try:
                if value not in (None, "", UNAVAILABLE):
                    return float(value)
            except (TypeError, ValueError):
                pass
        return None

    def _security_score(self, data: Dict[str, Any]) -> Optional[float]:
        # Only display an explicitly exposed numeric score; never synthesize one.
        for point_name in ("security_capability", "reviewer_audit", "adversarial_validation"):
            metadata = self._metadata(data.get(point_name, {}))
            score = self._numeric(metadata, "security_score", "security_score_percent", "score_percent")
            if score is not None:
                return score
        return None

    def _security_alerts(self, data: Dict[str, Any]) -> List[Tuple[str, str, str]]:
        alerts: List[Tuple[str, str, str]] = []
        connection, connection_ready = self._point_result(data.get("connection_status", {}))
        if not connection_ready or connection != "Connected":
            alerts.append(("Runtime Connection", str(connection) if connection_ready else NOT_CONNECTED, "high"))

        for key, title in (("security_capability", "Security Metadata"), ("identity_security", "Identity Metadata"), ("consensus_security", "Consensus Metadata")):
            point = data.get(key, {})
            status = point.get("status") if isinstance(point, dict) else "unavailable"
            if status in {"error", "unavailable"}:
                alerts.append((title, f"Source status: {status}", "medium"))

        identity = self._metadata(data.get("identity_security", {}))
        if identity and identity.get("sybil_resistance") is False:
            alerts.append(("Sybil Boundary", "Sybil-resistance guarantee is not claimed", "boundary"))

        consensus = self._metadata(data.get("consensus_security", {}))
        if consensus and consensus.get("majority_attack_resistant") is False:
            alerts.append(("Consensus Boundary", "Majority-control resistance is not claimed", "boundary"))

        reviewer = self._metadata(data.get("reviewer_audit", {}))
        paper_status = reviewer.get("paper_ready_claim_status")
        if paper_status not in (None, "", UNAVAILABLE):
            alerts.append(("Reviewer Audit", str(paper_status), "boundary"))

        return alerts

    # --------------------------------------------------------------- rendering

    def manual_refresh(self) -> None:
        self._snapshot = self.provider.collect()
        self._render_snapshot(self._snapshot)

    def _render_snapshot(self, data: Dict[str, Any]) -> None:
        connection, connection_ready = self._point_result(data.get("connection_status", {}))
        connection_text = str(connection) if connection_ready else NOT_CONNECTED
        connection_color = GREEN if connection_text == "Connected" else YELLOW if connection_text == "Partial" else RED
        self.top_connection.configure(text=connection_text, fg=connection_color)
        self.system_status_icon.configure(fg=connection_color)
        self.system_status_label.configure(text=f"Runtime {connection_text.lower()}", fg=connection_color)
        self.backend_label.configure(text=type(self.blockchain).__name__)
        self.updated_label.configure(text=f"Updated {data.get('updated_at', UNAVAILABLE)}")

        vehicle = data.get("vehicle_overview", {}) if isinstance(data.get("vehicle_overview"), dict) else {}
        vehicle_id, vehicle_id_ready = self._point_result(vehicle.get("vehicle_id", {}))
        lock_text = self._bool_text(vehicle.get("lock_status", {}), "Unlocked", "Locked")
        engine_text = self._bool_text(vehicle.get("engine_status", {}), "On", "Off")
        emergency_text = self._bool_text(vehicle.get("emergency_status", {}), "Active", "Inactive")
        safe_text = self._bool_text(vehicle.get("safe_mode", {}), "Active", "Inactive")

        telemetry_value, telemetry_ready = self._point_result(vehicle.get("telemetry", {}))
        telemetry = telemetry_value if telemetry_ready and isinstance(telemetry_value, dict) else {}
        speed = self._numeric(telemetry, "speed", "speed_kmh") if telemetry_ready else None
        rpm = self._numeric(telemetry, "rpm") if telemetry_ready else None
        fuel = self._numeric(telemetry, "fuel_level", "fuel") if telemetry_ready else None
        temperature = self._numeric(telemetry, "temperature", "engine_temp") if telemetry_ready else None
        throttle = self._numeric(telemetry, "throttle", "throttle_pct") if telemetry_ready else None

        peers_value, peers_ready = self._point_result(data.get("v2x_peers", {}))
        peers = peers_value if peers_ready and isinstance(peers_value, list) else []
        detections_value, detections_ready = self._point_result(data.get("object_detection", {}))
        detections = detections_value if detections_ready and isinstance(detections_value, list) else []
        camera_value, camera_ready = self._point_result(data.get("camera_status", {}))
        camera_connected = bool(camera_value.get("connected")) if isinstance(camera_value, dict) else False

        chain, chain_ready = self._chain_rows(getattr(self.blockchain, "chain", None))
        security_score = self._security_score(data)

        self.dashboard_metrics["vehicles"]["value"].configure(text="1" if vehicle_id_ready else UNAVAILABLE)
        self.dashboard_metrics["vehicles"]["note"].configure(text=self._point_source(vehicle.get("vehicle_id", {})))
        self.dashboard_metrics["transactions"]["value"].configure(text=str(len(chain)) if chain_ready else UNAVAILABLE)
        self.dashboard_metrics["transactions"]["note"].configure(text="backend.chain" if chain_ready else "chain unavailable")
        self.dashboard_metrics["nodes"]["value"].configure(text=str(len(peers)) if peers_ready else UNAVAILABLE)
        self.dashboard_metrics["nodes"]["note"].configure(text=self._point_source(data.get("v2x_peers", {})))
        self.dashboard_metrics["security"]["value"].configure(text=f"{security_score:.1f}%" if security_score is not None else UNAVAILABLE)
        self.dashboard_metrics["security"]["note"].configure(text="explicit backend score" if security_score is not None else "no explicit numeric score")

        identity = self._metadata(data.get("identity_security", {}))
        reviewer = self._metadata(data.get("reviewer_audit", {}))
        integrity_text = "Verified" if identity.get("identity_authenticity") is True else UNAVAILABLE
        self.dashboard_vehicle_rows["vehicle_id"].configure(text=self._display(vehicle_id) if vehicle_id_ready else UNAVAILABLE)
        self.dashboard_vehicle_rows["ownership"].configure(text=lock_text)
        self.dashboard_vehicle_rows["access"].configure(text=engine_text)
        self.dashboard_vehicle_rows["integrity"].configure(text=integrity_text)
        self.dashboard_vehicle_rows["updated"].configure(text=str(data.get("updated_at", UNAVAILABLE)))

        self._render_activity_feed(self.dashboard_activity_feed, chain, 5)
        self._draw_peer_map(self.dashboard_network_canvas, peers if peers_ready else [])
        self.dashboard_network_footer.configure(
            text=(
                f"{len(peers)} active nodes  •  {connection_text}  •  block height {len(chain) - 1 if chain_ready and chain else UNAVAILABLE}"
                if peers_ready or chain_ready
                else NO_DATA
            )
        )
        alerts = self._security_alerts(data)
        self._render_alert_feed(self.dashboard_alert_feed, alerts, 3)
        self._draw_transaction_chart(self.dashboard_transaction_canvas, chain if chain_ready else [])
        self.dashboard_transaction_footer.configure(text=f"{len(chain)} total records  •  source: backend.chain" if chain_ready else NO_DATA)

        # Vehicles page.
        self.vehicle_rows["vehicle_id"].configure(text=self._display(vehicle_id) if vehicle_id_ready else UNAVAILABLE)
        self.vehicle_rows["lock"].configure(text=lock_text)
        self.vehicle_rows["engine"].configure(text=engine_text)
        self.vehicle_rows["emergency"].configure(text=emergency_text)
        self.vehicle_rows["safe"].configure(text=safe_text)
        self.vehicle_rows["speed"].configure(text=f"{speed:.1f} km/h" if speed is not None else UNAVAILABLE)
        self.vehicle_rows["rpm"].configure(text=f"{rpm:.0f}" if rpm is not None else UNAVAILABLE)
        self.vehicle_rows["fuel"].configure(text=f"{fuel:.1f}%" if fuel is not None else UNAVAILABLE)
        self.vehicle_rows["temperature"].configure(text=f"{temperature:.1f}°C" if temperature is not None else UNAVAILABLE)
        self.vehicle_rows["throttle"].configure(text=f"{throttle:.1f}%" if throttle is not None else UNAVAILABLE)
        self._draw_speed_gauge(self.speed_canvas, speed)
        self._draw_road_scene(self.road_canvas, telemetry, peers if peers_ready else [])
        self.vehicle_detection_label.configure(text=f"{len(detections)} live detections" if detections_ready else NO_DATA)
        if not camera_connected:
            self.camera_label.configure(text="Camera Not Connected" if isinstance(camera_value, dict) or camera_ready else UNAVAILABLE, image="", fg=ORANGE)
        elif self._camera_photo is None:
            self.camera_label.configure(text="Camera Connected", image="", fg=GREEN)

        # Transactions.
        self._draw_transaction_chart(self.transactions_canvas, chain if chain_ready else [])
        self._render_activity_feed(self.transactions_activity, chain, 6)
        self._render_ledger_tree(chain if chain_ready else [])

        # Access control.
        self.access_state_label.configure(
            text="\n".join((
                f"Vehicle: {self._display(vehicle_id) if vehicle_id_ready else UNAVAILABLE}",
                f"Lock: {lock_text}",
                f"Engine: {engine_text}",
                f"Safe mode: {safe_text}",
                f"Backend: {type(self.blockchain).__name__}",
            ))
        )

        # Ownership.
        self.ownership_rows["vehicle_id"].configure(text=self._display(vehicle_id) if vehicle_id_ready else UNAVAILABLE)
        self.ownership_rows["lock"].configure(text=lock_text)
        self.ownership_rows["authenticity"].configure(text=self._display(identity.get("identity_authenticity", UNAVAILABLE)))
        self.ownership_rows["admission"].configure(text=self._display(identity.get("identity_admission_policy", UNAVAILABLE)))
        self.ownership_rows["sybil"].configure(text=self._display(identity.get("sybil_resistance", UNAVAILABLE)))
        self._render_ownership_feed(chain if chain_ready else [])

        # Audit.
        self._render_audit(chain if chain_ready else [], data, connection_text)
        self.audit_boundary_label.configure(
            text="\n".join((
                f"Paper claim status: {reviewer.get('paper_ready_claim_status', UNAVAILABLE)}",
                f"Full PQ claim: {self._display(reviewer.get('full_post_quantum_security_claim', UNAVAILABLE))}",
                f"Majority attack resistance claim: {self._display(reviewer.get('majority_attack_resistance_claim', UNAVAILABLE))}",
                f"Secure aggregation claim: {self._display(reviewer.get('secure_aggregation_claim', UNAVAILABLE))}",
            ))
        )

        # Threats and alerts.
        self._draw_threat_signal(self.anomaly_canvas, chain if chain_ready else [], alerts)
        self._render_alert_feed(self.threat_feed, alerts, 8)
        self._render_alert_feed(self.alerts_feed, alerts, 20)

        # Security scan.
        security = self._metadata(data.get("security_capability", {}))
        consensus = self._metadata(data.get("consensus_security", {}))
        privacy = self._metadata(data.get("privacy_pedersen", {}))
        fl = self._metadata(data.get("fl_validation", {}))
        self.scan_labels["security"].configure(text="\n".join((
            f"Key establishment: {security.get('key_establishment', UNAVAILABLE)}",
            f"Commitment binding: {security.get('commitment_binding', UNAVAILABLE)}",
            f"ECDH fallback: {security.get('fallback_ecdh_p256', UNAVAILABLE)}",
            f"Summary: {security.get('summary', UNAVAILABLE)}",
        )))
        self.scan_labels["identity"].configure(text="\n".join((
            f"Identity authenticity: {self._display(identity.get('identity_authenticity', UNAVAILABLE))}",
            f"Sybil resistance: {self._display(identity.get('sybil_resistance', UNAVAILABLE))}",
            f"Admission policy: {identity.get('identity_admission_policy', UNAVAILABLE)}",
            f"Warning: {identity.get('warning', UNAVAILABLE)}",
        )))
        self.scan_labels["consensus"].configure(text="\n".join((
            f"Consensus model: {consensus.get('consensus_model', UNAVAILABLE)}",
            f"Majority attack resistant: {self._display(consensus.get('majority_attack_resistant', UNAVAILABLE))}",
            f"Dual hash chaining: {self._display(consensus.get('dual_hash_chaining', UNAVAILABLE))}",
            f"Forward majority control: {self._display(consensus.get('protects_against_forward_majority_control', consensus.get('forward_majority_control', UNAVAILABLE)))}",
        )))
        self.scan_labels["privacy"].configure(text="\n".join((
            f"Pedersen mode: {privacy.get('pedersen_mode', UNAVAILABLE)}",
            f"Aggregate statistics recoverable: {self._display(privacy.get('aggregate_statistics_recoverable', UNAVAILABLE))}",
            f"Secure aggregation implemented: {self._display(privacy.get('secure_aggregation_implemented', UNAVAILABLE))}",
            f"FL validation level: {fl.get('fl_validation_level', UNAVAILABLE)}",
            f"Byzantine robustness claim: {self._display(fl.get('supports_byzantine_robustness_claim', UNAVAILABLE))}",
        )))

        # Smart Contract / boundaries.
        complexity = self._metadata(data.get("complexity_boundary", {}))
        contribution = self._metadata(data.get("contribution_boundary", {}))
        self.contract_consensus_label.configure(text="\n".join((
            f"Consensus model: {consensus.get('consensus_model', UNAVAILABLE)}",
            f"Majority attack resistant: {self._display(consensus.get('majority_attack_resistant', UNAVAILABLE))}",
            f"Dual hash chaining: {self._display(consensus.get('dual_hash_chaining', UNAVAILABLE))}",
            f"Visible chain records: {len(chain) if chain_ready else UNAVAILABLE}",
        )))
        self.contract_boundary_label.configure(text="\n".join((
            f"Overall complexity claim: {complexity.get('overall_complexity_claim', UNAVAILABLE)}",
            f"Full system O(n): {self._display(complexity.get('full_system_o_n_claim', UNAVAILABLE))}",
            f"Full mesh network volume: {complexity.get('naive_full_mesh_network_volume', UNAVAILABLE)}",
            f"Contribution type: {contribution.get('contribution_type', UNAVAILABLE)}",
            f"New cryptographic primitive: {self._display(contribution.get('claims_new_cryptographic_primitive', UNAVAILABLE))}",
        )))
        self.contract_chain_label.configure(text=self._chain_head_text(chain if chain_ready else []))

        # Nodes.
        self._draw_peer_map(self.radar_canvas, peers if peers_ready else [])
        self._render_peer_tree(peers if peers_ready else [])
        self.health_text.configure(text="\n".join((
            f"Connection: {connection_text}",
            f"Backend: {type(self.blockchain).__name__}",
            f"Peer source: {self._point_source(data.get('v2x_peers', {}))}",
            f"Observed peers: {len(peers) if peers_ready else UNAVAILABLE}",
            f"Visible chain records: {len(chain) if chain_ready else UNAVAILABLE}",
            f"Telemetry source: {self._point_source(vehicle.get('telemetry', {}))}",
        )))

        # Settings: secret values are intentionally not surfaced.
        self.settings_rows["backend"].configure(text=type(self.blockchain).__name__)
        self.settings_rows["vehicle"].configure(text=str(self.VEHICLE_ID))
        self.settings_rows["camera"].configure(text=str(self.camera_index))
        self.settings_rows["refresh"].configure(text=f"{self.refresh_interval_ms} ms")
        self.settings_rows["chain"].configure(text=str(self.GUI_CHAIN_FILE))
        self.settings_rows["auth"].configure(text="Configured" if bool(self.AUTH_TOKEN) else UNAVAILABLE)
        self.settings_rows["password"].configure(text="Configured" if bool(self.PASSWORD) else UNAVAILABLE)

    # ------------------------------------------------------------ render utils

    def _render_activity_feed(self, parent: tk.Widget, chain: Sequence[Any], limit: int) -> None:
        for child in parent.winfo_children():
            child.destroy()
        rows = list(chain)[-limit:]
        if not rows:
            tk.Label(parent, text=NO_DATA, bg=CARD, fg=MUTED, font=self.f_body).pack(anchor="w")
            return
        for block in reversed(rows):
            fields = self._block_fields(block)
            self._feed_row(parent, str(fields["event"]), f"Block #{fields['index']} • {fields['vehicle']}", str(fields["timestamp"]))

    def _render_alert_feed(self, parent: tk.Widget, alerts: Sequence[Tuple[str, str, str]], limit: int) -> None:
        for child in parent.winfo_children():
            child.destroy()
        if not alerts:
            self._feed_row(parent, "No explicit alerts", "No source-backed runtime/security warning is currently exposed.", "", "ok")
            return
        for title, detail, severity in list(alerts)[:limit]:
            self._feed_row(parent, title, detail, severity.title() if severity else "", severity)

    def _render_ownership_feed(self, chain: Sequence[Any]) -> None:
        for child in self.ownership_feed.winfo_children():
            child.destroy()
        matches: List[Dict[str, Any]] = []
        for block in reversed(list(chain)[-30:]):
            fields = self._block_fields(block)
            event = str(fields["event"])
            if any(term in event.lower() for term in ("owner", "ownership", "transfer", "lock", "unlock")):
                matches.append(fields)
        if not matches:
            tk.Label(self.ownership_feed, text=NO_DATA, bg=CARD, fg=MUTED, font=self.f_body).pack(anchor="w")
            return
        for fields in matches[:7]:
            self._feed_row(self.ownership_feed, str(fields["event"]), f"Block #{fields['index']}", str(fields["timestamp"]))

    def _render_audit(self, chain: Sequence[Any], data: Dict[str, Any], connection: str) -> None:
        lines = [
            f"Connection: {connection}",
            f"Backend: {type(self.blockchain).__name__}",
            f"Snapshot: {data.get('updated_at', UNAVAILABLE)}",
            f"Visible chain records: {len(chain)}",
            "",
        ]
        for block in reversed(list(chain)[-15:]):
            fields = self._block_fields(block)
            lines.append(f"[{fields['timestamp']}] Block #{fields['index']}  {fields['event']}")
        self.audit_text.configure(state="normal")
        self.audit_text.delete("1.0", "end")
        self.audit_text.insert("end", "\n".join(lines))
        self.audit_text.configure(state="disabled")

    def _render_ledger_tree(self, chain: Sequence[Any]) -> None:
        for item in self.ledger_tree.get_children():
            self.ledger_tree.delete(item)
        for block in reversed(list(chain)[-50:]):
            fields = self._block_fields(block)
            block_hash = str(fields["hash"])
            self.ledger_tree.insert("", "end", values=(
                self._display(fields["index"]),
                str(fields["timestamp"]),
                str(fields["event"]),
                block_hash[:32] + ("…" if len(block_hash) > 32 else ""),
            ))

    def _render_peer_tree(self, peers: Sequence[Any]) -> None:
        for item in self.peer_tree.get_children():
            self.peer_tree.delete(item)
        for peer in peers:
            if not isinstance(peer, dict):
                continue
            self.peer_tree.insert("", "end", values=(
                peer.get("peer_id", peer.get("id", "peer")),
                self._display(self._first_value(peer, ("relative_distance", "distance", "distance_m"), UNAVAILABLE)),
                self._display(self._first_value(peer, ("relative_heading", "heading", "bearing"), UNAVAILABLE)),
                self._display(self._first_value(peer, ("speed", "speed_kmh"), UNAVAILABLE)),
            ))

    def _chain_head_text(self, chain: Sequence[Any]) -> str:
        if not chain:
            return NO_DATA
        fields = self._block_fields(chain[-1])
        return "\n".join((
            f"Index: {fields['index']}",
            f"Timestamp: {fields['timestamp']}",
            f"Event: {fields['event']}",
            f"Hash: {fields['hash'] or UNAVAILABLE}",
        ))

    # --------------------------------------------------------------- graphics

    def _draw_vehicle_art(self, canvas: tk.Canvas) -> None:
        canvas.delete("all")
        w = max(canvas.winfo_width(), 360)
        h = max(canvas.winfo_height(), 250)
        cx = w / 2
        cy = h / 2 + 25
        canvas.create_polygon(cx, 18, cx + 55, 45, cx + 50, 115, cx, 145, cx - 50, 115, cx - 55, 45, outline="#113466", fill="", width=1)
        for radius in (150, 122, 95):
            canvas.create_oval(cx - radius, cy + 62 - radius / 6, cx + radius, cy + 62 + radius / 6, outline="#0d3f77")
        body = [cx - 128, cy + 18, cx - 112, cy - 10, cx - 48, cy - 30, cx + 50, cy - 27, cx + 100, cy - 4, cx + 126, cy + 23, cx + 104, cy + 37, cx - 120, cy + 37]
        canvas.create_polygon(body, outline="#1788ff", fill="#082047", width=2, smooth=True)
        canvas.create_line(cx - 50, cy - 29, cx - 20, cy - 60, cx + 38, cy - 58, cx + 72, cy - 25, fill="#39b6ff", width=2, smooth=True)
        canvas.create_line(cx - 109, cy + 12, cx - 72, cy + 2, fill="#58d5ff", width=3)
        canvas.create_line(cx + 82, cy + 6, cx + 110, cy + 15, fill="#58d5ff", width=2)
        for wheel_x in (cx - 72, cx + 61):
            canvas.create_oval(wheel_x - 19, cy + 22, wheel_x + 19, cy + 60, fill="#040914", outline="#1a477b", width=3)
            canvas.create_oval(wheel_x - 9, cy + 32, wheel_x + 9, cy + 50, outline="#ff425f")

    def _draw_speed_gauge(self, canvas: tk.Canvas, speed: Optional[float]) -> None:
        canvas.delete("all")
        w = max(canvas.winfo_width(), 420)
        h = max(canvas.winfo_height(), 260)
        cx, cy = w / 2, h * 0.78
        radius = min(w * 0.34, h * 0.62)
        canvas.create_arc(cx - radius, cy - radius, cx + radius, cy + radius, start=20, extent=140, style="arc", outline="#15345d", width=14)
        if speed is None:
            canvas.create_text(cx, cy - 55, text=UNAVAILABLE, fill=ORANGE, font=self.f_head)
            return
        bounded = min(max(speed, 0.0), 180.0)
        extent = (bounded / 180.0) * 140.0
        canvas.create_arc(cx - radius, cy - radius, cx + radius, cy + radius, start=200 - extent, extent=extent, style="arc", outline=INDIGO, width=14)
        angle = math.radians(200 - extent)
        nx = cx + (radius - 25) * math.cos(angle)
        ny = cy - (radius - 25) * math.sin(angle)
        canvas.create_line(cx, cy, nx, ny, fill=GREEN if speed < 120 else RED, width=4)
        canvas.create_oval(cx - 6, cy - 6, cx + 6, cy + 6, fill=TEXT, outline="")
        canvas.create_text(cx, cy - 55, text=f"{speed:.1f}", fill=TEXT, font=self.f_big)
        canvas.create_text(cx, cy - 27, text="km/h", fill=MUTED, font=self.f_small)

    def _draw_road_scene(self, canvas: tk.Canvas, telemetry: Dict[str, Any], peers: Sequence[Any]) -> None:
        canvas.delete("all")
        w = max(canvas.winfo_width(), 500)
        h = max(canvas.winfo_height(), 250)
        if not telemetry:
            canvas.create_text(w / 2, h / 2, text="Telemetry unavailable", fill=ORANGE, font=self.f_head)
            return
        canvas.create_rectangle(0, h * 0.2, w, h * 0.82, fill="#0b1a27", outline="")
        for y in (h * 0.38, h * 0.52, h * 0.66):
            canvas.create_line(14, y, w - 14, y, fill="#30445b", dash=(12, 9))
        ego_x, ego_y = w * 0.25, h * 0.52
        canvas.create_rectangle(ego_x - 25, ego_y - 13, ego_x + 25, ego_y + 13, fill=INDIGO, outline="#8aa4ff")
        canvas.create_text(ego_x, ego_y, text="EGO", fill="#fff", font=self.f_tiny)
        for peer in peers[:6]:
            if not isinstance(peer, dict):
                continue
            distance = self._as_float(self._first_value(peer, ("relative_distance", "distance", "distance_m"), None))
            heading = self._as_float(self._first_value(peer, ("relative_heading", "heading", "bearing"), None))
            if distance is None or heading is None:
                continue
            px = ego_x + min(distance, 100.0) / 100.0 * (w * 0.62)
            py = ego_y + max(-1.0, min(1.0, heading / 90.0)) * (h * 0.23)
            canvas.create_rectangle(px - 13, py - 8, px + 13, py + 8, fill="#0f7656", outline=GREEN)

    def _draw_peer_map(self, canvas: tk.Canvas, peers: Sequence[Any]) -> None:
        canvas.delete("all")
        w = max(canvas.winfo_width(), 420)
        h = max(canvas.winfo_height(), 180)
        cx, cy = w / 2, h / 2
        for radius in (45, 85, 125):
            canvas.create_oval(cx - radius, cy - radius, cx + radius, cy + radius, outline="#143155")
        canvas.create_line(cx, 10, cx, h - 10, fill="#102948")
        canvas.create_line(10, cy, w - 10, cy, fill="#102948")
        canvas.create_oval(cx - 9, cy - 9, cx + 9, cy + 9, fill=INDIGO, outline="")
        canvas.create_text(cx, cy - 18, text="EGO", fill="#dce5f4", font=self.f_tiny)
        if not peers:
            canvas.create_text(cx, h - 18, text=NO_DATA, fill=MUTED, font=self.f_small)
            return
        for idx, peer in enumerate(peers[:10]):
            if not isinstance(peer, dict):
                continue
            distance = self._as_float(self._first_value(peer, ("relative_distance", "distance", "distance_m"), None))
            heading = self._as_float(self._first_value(peer, ("relative_heading", "heading", "bearing"), None))
            if distance is None or heading is None:
                continue
            radial = min(distance, 100.0) / 100.0 * min(125.0, min(w, h) * 0.36)
            angle = math.radians(heading - 90.0)
            px = cx + math.cos(angle) * radial
            py = cy + math.sin(angle) * radial
            canvas.create_line(cx, cy, px, py, fill="#1d4b67")
            canvas.create_oval(px - 5, py - 5, px + 5, py + 5, fill=GREEN, outline="")
            canvas.create_text(px + 8, py - 8, text=str(peer.get("peer_id", peer.get("id", idx + 1))), fill="#b9c9df", font=self.f_tiny, anchor="w")

    def _draw_transaction_chart(self, canvas: tk.Canvas, chain: Sequence[Any]) -> None:
        values: List[float] = []
        for block in list(chain)[-16:]:
            index = self._block_fields(block)["index"]
            try:
                values.append(float(index))
            except (TypeError, ValueError):
                values.append(float(len(values) + 1))
        self._draw_line_chart(canvas, values, PURPLE, "No transaction history")

    def _draw_threat_signal(self, canvas: tk.Canvas, chain: Sequence[Any], alerts: Sequence[Tuple[str, str, str]]) -> None:
        severity_weight = {"high": 4.0, "medium": 3.0, "boundary": 2.0, "ok": 1.0}
        values: List[float] = []
        for block in list(chain)[-14:]:
            event = str(self._block_fields(block)["event"]).lower()
            score = 1.0
            if any(term in event for term in ("alert", "attack", "error", "denied")):
                score = 4.0
            elif any(term in event for term in ("warning", "scan", "recover")):
                score = 2.5
            values.append(score)
        if alerts:
            values.append(max(severity_weight.get(item[2], 1.0) for item in alerts))
        self._draw_line_chart(canvas, values, RED, "No source-backed threat signal")

    def _draw_line_chart(self, canvas: tk.Canvas, values: Sequence[float], color: str, empty_text: str) -> None:
        canvas.delete("all")
        w = max(canvas.winfo_width(), 420)
        h = max(canvas.winfo_height(), 170)
        pad = 28
        for row in range(4):
            y = pad + row * ((h - 2 * pad) / 3)
            canvas.create_line(pad, y, w - pad, y, fill=GRID)
        if len(values) < 2:
            canvas.create_text(w / 2, h / 2, text=empty_text, fill=MUTED, font=self.f_small)
            return
        lo = min(values)
        hi = max(values)
        span = max(hi - lo, 1.0)
        step = (w - 2 * pad) / max(len(values) - 1, 1)
        points: List[float] = []
        for idx, value in enumerate(values):
            x = pad + idx * step
            y = h - pad - ((value - lo) / span) * (h - 2 * pad)
            points.extend((x, y))
        canvas.create_line(*points, fill=color, width=3, smooth=True)
        for idx in range(0, len(points), 2):
            x, y = points[idx], points[idx + 1]
            canvas.create_oval(x - 3, y - 3, x + 3, y + 3, fill=color, outline="")


SmartCarDashboard = ReferenceSmartCarDashboard
