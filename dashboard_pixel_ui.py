"""Pixel-closer reference dashboard shell for OmniGuard V2X.

This module changes presentation only. Runtime values still come from the existing
DashboardDataProvider/backend and missing values remain explicit. The supplied
reference screenshot is treated as visual guidance, never as a source of data.
"""

from __future__ import annotations

import math
import os
import tkinter as tk
from datetime import datetime
from tkinter import font
from typing import Any, Dict, List, Optional, Sequence, Tuple

from dashboard import NO_DATA, NOT_CONNECTED, UNAVAILABLE
from dashboard_reference_ui import (
    BG,
    BORDER,
    CARD,
    CARD_2,
    CARD_3,
    CYAN,
    DIM,
    GREEN,
    GRID,
    INDIGO,
    INDIGO_2,
    MENU_GROUPS,
    MUTED,
    ORANGE,
    PAGE_TITLES,
    PURPLE,
    RED,
    SIDEBAR,
    TEXT,
    TOPBAR,
    YELLOW,
    ReferenceSmartCarDashboard,
)


PANEL_BG = "#0a1628"
PANEL_DEEP = "#071326"
PANEL_HOVER = "#112440"
SOFT_BORDER = "#172a47"
BLUE_GLOW = "#1687ff"
BLUE_BRIGHT = "#3dc6ff"
BLUE_BODY = "#073c83"
BLUE_BODY_2 = "#0d5fc4"
WHEEL = "#030812"
MAP_FILL = "#183354"
MAP_EDGE = "#294c70"


class PixelMatchedSmartCarDashboard(ReferenceSmartCarDashboard):
    """Reference-inspired desktop shell with source-backed runtime data."""

    # ---------------------------------------------------------------- fonts

    def _setup_reference_fonts(self) -> None:
        self.f_brand_small = font.Font(family="Segoe UI", size=10, weight="bold")
        self.f_brand = font.Font(family="Segoe UI", size=17, weight="bold")
        self.f_title = font.Font(family="Segoe UI", size=15)
        self.f_page_title = font.Font(family="Segoe UI", size=17, weight="bold")
        self.f_head = font.Font(family="Segoe UI", size=11, weight="bold")
        self.f_body = font.Font(family="Segoe UI", size=10)
        self.f_small = font.Font(family="Segoe UI", size=9)
        self.f_tiny = font.Font(family="Segoe UI", size=8)
        self.f_kpi = font.Font(family="Segoe UI", size=22, weight="bold")
        self.f_big = font.Font(family="Segoe UI", size=27, weight="bold")
        self.f_mono = font.Font(family="Consolas", size=9)
        self.dashboard_user = os.getenv("SMARTCAR_DASHBOARD_USER", "Shagor").strip() or "Operator"

    # --------------------------------------------------------------- sidebar

    def _build_reference_sidebar(self) -> None:
        self.sidebar = tk.Frame(self.shell, bg=SIDEBAR, width=250)
        self.sidebar.pack(side="left", fill="y")
        self.sidebar.pack_propagate(False)

        brand = tk.Frame(self.sidebar, bg=SIDEBAR, padx=27, pady=24)
        brand.pack(fill="x")

        shield = tk.Canvas(brand, width=42, height=48, bg=SIDEBAR, highlightthickness=0)
        shield.pack(side="left", padx=(0, 12))
        shield.create_polygon(
            21, 2, 38, 11, 35, 33, 21, 45, 7, 33, 4, 11,
            fill="#111e44", outline="#6757ff", width=2,
        )
        shield.create_polygon(
            21, 10, 30, 15, 28, 27, 21, 33, 14, 27, 12, 15,
            fill="#142a63", outline="#3979ff", width=1,
        )
        shield.create_text(21, 21, text="✓", fill="#55a5ff", font=("Segoe UI", 12, "bold"))

        brand_text = tk.Frame(brand, bg=SIDEBAR)
        brand_text.pack(side="left", fill="x", expand=True)
        tk.Label(brand_text, text="Next-Gen", bg=SIDEBAR, fg=TEXT, font=self.f_brand_small).pack(anchor="w")
        tk.Label(brand_text, text="Vehicle Security", bg=SIDEBAR, fg=TEXT, font=self.f_brand).pack(anchor="w", pady=(1, 0))
        tk.Label(
            brand_text,
            text="Blockchain-Powered Protection",
            bg=SIDEBAR,
            fg="#a4b2ca",
            font=self.f_tiny,
        ).pack(anchor="w", pady=(3, 0))

        nav_wrap = tk.Frame(self.sidebar, bg=SIDEBAR)
        nav_wrap.pack(fill="x", padx=17)

        for group, items in MENU_GROUPS:
            tk.Label(
                nav_wrap,
                text=group,
                bg=SIDEBAR,
                fg="#7385a5",
                font=self.f_tiny,
                anchor="w",
                pady=8,
            ).pack(fill="x", padx=10, pady=(4, 0))

            for key, title, icon in items:
                button = tk.Button(
                    nav_wrap,
                    text=f"  {icon}    {title}",
                    command=lambda p=key: self._show_reference_page(p),
                    anchor="w",
                    bg=SIDEBAR,
                    fg="#d8e0ef",
                    activebackground="#17294d",
                    activeforeground="#ffffff",
                    relief="flat",
                    bd=0,
                    highlightthickness=0,
                    padx=10,
                    pady=10,
                    font=self.f_body,
                    cursor="hand2",
                )
                button.pack(fill="x", pady=1)
                self._reference_buttons[key] = button

        spacer = tk.Frame(self.sidebar, bg=SIDEBAR)
        spacer.pack(fill="both", expand=True)

        status_outer = tk.Frame(
            self.sidebar,
            bg="#0c1a2f",
            highlightthickness=1,
            highlightbackground=SOFT_BORDER,
        )
        status_outer.pack(fill="x", padx=27, pady=(8, 16))
        status = tk.Frame(status_outer, bg="#0c1a2f", padx=14, pady=13)
        status.pack(fill="both", expand=True)

        status_icon = tk.Canvas(status, width=42, height=42, bg="#0c1a2f", highlightthickness=0)
        status_icon.pack(side="left", padx=(0, 10))
        status_icon.create_oval(2, 2, 40, 40, fill="#0a3b36", outline="")
        status_icon.create_oval(10, 10, 32, 32, outline=GREEN, width=2)
        status_icon.create_text(21, 21, text="✓", fill=GREEN, font=("Segoe UI", 11, "bold"))
        self.system_status_canvas = status_icon

        status_text = tk.Frame(status, bg="#0c1a2f")
        status_text.pack(side="left", fill="x", expand=True)
        tk.Label(status_text, text="System Status", bg="#0c1a2f", fg=TEXT, font=self.f_head).pack(anchor="w")
        self.system_status_label = tk.Label(
            status_text,
            text="Checking runtime...",
            bg="#0c1a2f",
            fg=ORANGE,
            font=self.f_tiny,
        )
        self.system_status_label.pack(anchor="w", pady=(3, 0))
        # Compatibility target used by inherited renderer.
        self.system_status_icon = tk.Label(status_text, text="", bg="#0c1a2f", fg=ORANGE)

        footer = tk.Frame(self.sidebar, bg=SIDEBAR, padx=27, pady=13)
        footer.pack(fill="x")
        tk.Label(footer, text="© 2026 OmniGuard V2X", bg=SIDEBAR, fg="#687994", font=self.f_tiny).pack(anchor="w")
        tk.Label(footer, text="v3.0.3", bg=SIDEBAR, fg="#687994", font=self.f_tiny).pack(anchor="w", pady=(3, 0))

    # ---------------------------------------------------------------- topbar

    def _build_reference_topbar(self) -> None:
        # The reference uses the page background itself as the top bar.
        top = tk.Frame(self.reference_main, bg=BG, padx=28, pady=10)
        top.pack(fill="x", pady=(10, 9))

        heading = tk.Frame(top, bg=BG)
        heading.pack(side="left", fill="x", expand=True)
        self.reference_title = tk.Label(
            heading,
            text=f"Welcome back, {self.dashboard_user}! 👋",
            bg=BG,
            fg=TEXT,
            font=self.f_title,
        )
        self.reference_title.pack(anchor="w")
        self.reference_subtitle = tk.Label(
            heading,
            text="Secure. Transparent. Decentralized.",
            bg=BG,
            fg="#c6d0e1",
            font=self.f_body,
        )
        self.reference_subtitle.pack(anchor="w", pady=(3, 0))

        controls = tk.Frame(top, bg=BG)
        controls.pack(side="right")

        network = self._top_pill(controls, "Blockchain Network", NOT_CONNECTED, "●")
        network.pack(side="left", padx=(0, 10))
        self.top_connection = network.value_label
        self.connection_badge = self.top_connection

        backend = self._top_pill(controls, "Network", type(self.blockchain).__name__, "⌘")
        backend.pack(side="left", padx=(0, 10))
        self.backend_value_label = backend.value_label

        bell = tk.Button(
            controls,
            text="♧",
            command=lambda: self._show_reference_page("alerts"),
            bg=CARD,
            fg="#eaf0fb",
            activebackground=CARD_3,
            activeforeground="#ffffff",
            relief="flat",
            bd=0,
            width=3,
            pady=12,
            cursor="hand2",
            font=("Segoe UI Symbol", 13),
        )
        bell.pack(side="left", padx=(0, 10))

        avatar = tk.Canvas(controls, width=44, height=44, bg=BG, highlightthickness=0)
        avatar.pack(side="left")
        avatar.create_oval(3, 3, 41, 41, fill="#d9e0e9", outline="#ffffff")
        avatar.create_oval(15, 10, 29, 24, fill="#2a3650", outline="")
        avatar.create_arc(10, 19, 34, 39, start=0, extent=180, fill="#2a3650", outline="")

        # Compatibility labels retained but visually unobtrusive.
        self.backend_label = tk.Label(top, text="", bg=BG, fg=BG, font=self.f_tiny)
        self.updated_label = tk.Label(top, text="", bg=BG, fg=BG, font=self.f_tiny)

    def _top_pill(self, parent: tk.Widget, title: str, value: str, icon: str) -> tk.Frame:
        pill = tk.Frame(parent, bg=CARD, highlightthickness=1, highlightbackground=SOFT_BORDER, padx=13, pady=8)
        icon_label = tk.Label(pill, text=icon, bg=CARD, fg=GREEN if "Blockchain" in title else "#8eb8ff", font=("Segoe UI Symbol", 11, "bold"))
        icon_label.pack(side="left", padx=(0, 9))
        copy = tk.Frame(pill, bg=CARD)
        copy.pack(side="left")
        tk.Label(copy, text=title, bg=CARD, fg=MUTED, font=self.f_tiny).pack(anchor="w")
        value_label = tk.Label(copy, text=value, bg=CARD, fg=TEXT, font=self.f_small)
        value_label.pack(anchor="w", pady=(1, 0))
        pill.value_label = value_label  # type: ignore[attr-defined]
        return pill

    def _show_reference_page(self, key: str) -> None:
        page = self._reference_pages.get(key)
        if page is None:
            return
        self._active_page = key
        page.tkraise()

        if key == "overview":
            self.reference_title.configure(text=f"Welcome back, {self.dashboard_user}! 👋", font=self.f_title)
            self.reference_subtitle.configure(text="Secure. Transparent. Decentralized.")
        else:
            title, subtitle = PAGE_TITLES[key]
            self.reference_title.configure(text=title, font=self.f_page_title)
            self.reference_subtitle.configure(text=subtitle)

        for page_key, button in self._reference_buttons.items():
            active = page_key == key
            button.configure(
                bg=INDIGO if active else SIDEBAR,
                fg="#ffffff" if active else "#d8e0ef",
                activebackground=INDIGO if active else "#17294d",
            )

    # -------------------------------------------------------------- components

    def _card(self, parent: tk.Widget, title: str, min_height: int = 0) -> Dict[str, Any]:
        outer = tk.Frame(parent, bg=SOFT_BORDER, padx=1, pady=1)
        inner = tk.Frame(outer, bg=CARD, padx=16, pady=14, height=min_height)
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
        outer = tk.Frame(parent, bg=SOFT_BORDER, padx=1, pady=1)
        inner = tk.Frame(outer, bg=CARD, padx=16, pady=13, height=108)
        inner.pack(fill="both", expand=True)
        inner.pack_propagate(False)

        left = tk.Frame(inner, bg=CARD)
        left.pack(side="left", fill="both", expand=True)
        tk.Label(left, text=title, bg=CARD, fg="#d0d8e7", font=self.f_small).pack(anchor="w")
        value = tk.Label(left, text=UNAVAILABLE, bg=CARD, fg=TEXT, font=self.f_kpi)
        value.pack(anchor="w", pady=(5, 1))
        note = tk.Label(left, text="Waiting for source", bg=CARD, fg=MUTED, font=self.f_tiny)
        note.pack(anchor="w")

        bubble = tk.Canvas(inner, width=62, height=62, bg=CARD, highlightthickness=0)
        bubble.pack(side="right", padx=(8, 0))
        bubble.create_oval(3, 3, 59, 59, fill=self._mix_dark(accent), outline="")
        bubble.create_oval(11, 11, 51, 51, fill=accent, outline="")
        bubble.create_text(31, 31, text=icon, fill="#ffffff", font=("Segoe UI Symbol", 16, "bold"))
        return {"outer": outer, "value": value, "note": note}

    @staticmethod
    def _mix_dark(color: str) -> str:
        # Fixed palette values only; this is visual decoration, not runtime data.
        return {
            INDIGO: "#28245d",
            "#138a5d": "#0a4934",
            "#1459c8": "#0b316d",
            "#4930a8": "#281d5e",
        }.get(color, "#162b4a")

    def _status_row(self, parent: tk.Widget, label: str) -> tk.Label:
        row = tk.Frame(parent, bg=CARD_2, padx=10, pady=7)
        row.pack(fill="x", pady=2)

        icon = tk.Canvas(row, width=30, height=30, bg=CARD_2, highlightthickness=0)
        icon.pack(side="left", padx=(0, 8))
        icon.create_oval(2, 2, 28, 28, fill="#172841", outline="")
        icon.create_text(15, 15, text=self._row_icon(label), fill="#c8d7ec", font=("Segoe UI Symbol", 10))

        tk.Label(row, text=label, bg=CARD_2, fg="#ccd6e7", font=self.f_small).pack(side="left")
        value = tk.Label(row, text=UNAVAILABLE, bg=CARD_2, fg=TEXT, font=self.f_small)
        value.pack(side="right")
        return value

    @staticmethod
    def _row_icon(label: str) -> str:
        lowered = label.lower()
        if "vehicle" in lowered:
            return "▣"
        if "owner" in lowered or "identity" in lowered:
            return "♙"
        if "access" in lowered or "lock" in lowered:
            return "⌾"
        if "integrity" in lowered or "security" in lowered:
            return "✓"
        if "updated" in lowered or "time" in lowered:
            return "◷"
        return "◇"

    def _feed_row(self, parent: tk.Widget, title: str, subtitle: str = "", right: str = "", severity: str = "") -> None:
        row = tk.Frame(parent, bg=CARD_2, padx=10, pady=7)
        row.pack(fill="x", pady=2)
        icon_color = {"high": RED, "medium": ORANGE, "ok": GREEN, "boundary": PURPLE}.get(severity, "#90c8ff")
        icon = tk.Canvas(row, width=32, height=32, bg=CARD_2, highlightthickness=0)
        icon.pack(side="left", padx=(0, 9))
        icon.create_oval(3, 3, 29, 29, fill="#142a43", outline="")
        icon.create_polygon(16, 8, 24, 13, 24, 22, 16, 27, 8, 22, 8, 13, outline=icon_color, fill="", width=1)

        copy = tk.Frame(row, bg=CARD_2)
        copy.pack(side="left", fill="both", expand=True)
        tk.Label(copy, text=title, bg=CARD_2, fg=TEXT, font=self.f_small, anchor="w").pack(anchor="w")
        if subtitle:
            tk.Label(copy, text=subtitle, bg=CARD_2, fg=MUTED, font=self.f_tiny, anchor="w").pack(anchor="w", pady=(2, 0))
        if right:
            tk.Label(row, text=right, bg=CARD_2, fg="#bcc8dc", font=self.f_tiny).pack(side="right")

    # --------------------------------------------------------------- overview

    def _build_dashboard_page(self) -> None:
        page = self._reference_pages["overview"]
        page.grid_columnconfigure(0, weight=1)
        page.grid_rowconfigure(1, weight=5)
        page.grid_rowconfigure(2, weight=4)
        page.grid_rowconfigure(3, weight=0)

        metrics = tk.Frame(page, bg=BG)
        metrics.grid(row=0, column=0, sticky="ew", pady=(0, 12))
        self.dashboard_metrics: Dict[str, Dict[str, tk.Label]] = {}
        specs = (
            ("vehicles", "Total Vehicles", INDIGO, "▣"),
            ("transactions", "Total Transactions", "#138a5d", "⇄"),
            ("nodes", "Active Nodes", "#1459c8", "≋"),
            ("security", "Security Score", "#4930a8", "✓"),
        )
        for idx, (key, title, accent, icon) in enumerate(specs):
            metrics.grid_columnconfigure(idx, weight=1, uniform="metric")
            tile = self._metric_tile(metrics, title, accent, icon)
            tile["outer"].grid(
                row=0,
                column=idx,
                sticky="nsew",
                padx=(0 if idx == 0 else 6, 0 if idx == len(specs) - 1 else 6),
            )
            self.dashboard_metrics[key] = tile

        middle = tk.Frame(page, bg=BG)
        middle.grid(row=1, column=0, sticky="nsew")
        middle.grid_columnconfigure(0, weight=5, uniform="middle")
        middle.grid_columnconfigure(1, weight=5, uniform="middle")
        middle.grid_rowconfigure(0, weight=1)

        vehicle = self._card(middle, "Vehicle Status Overview", 355)
        vehicle["outer"].grid(row=0, column=0, sticky="nsew", padx=(0, 7))
        visual = tk.Frame(vehicle["body"], bg=CARD)
        visual.pack(side="left", fill="both", expand=True, padx=(0, 12))
        self.dashboard_vehicle_canvas = tk.Canvas(visual, bg=PANEL_DEEP, highlightthickness=0)
        self.dashboard_vehicle_canvas.pack(fill="both", expand=True)
        self.dashboard_vehicle_canvas.bind("<Configure>", lambda _e: self._draw_vehicle_art(self.dashboard_vehicle_canvas))

        status = tk.Frame(vehicle["body"], bg=CARD, width=245)
        status.pack(side="left", fill="y")
        status.pack_propagate(False)
        self.dashboard_vehicle_rows = {
            "vehicle_id": self._status_row(status, "Vehicle ID"),
            "ownership": self._status_row(status, "Ownership"),
            "access": self._status_row(status, "Access Control"),
            "integrity": self._status_row(status, "Data Integrity"),
            "updated": self._status_row(status, "Last Updated"),
        }
        tk.Button(
            status,
            text="View Vehicle Details",
            command=lambda: self._show_reference_page("vehicles"),
            bg=INDIGO,
            fg="#ffffff",
            activebackground=INDIGO_2,
            activeforeground="#ffffff",
            relief="flat",
            bd=0,
            pady=9,
            cursor="hand2",
            font=self.f_small,
        ).pack(fill="x", pady=(8, 0))

        activity = self._card(middle, "Recent Blockchain Activity", 355)
        activity["outer"].grid(row=0, column=1, sticky="nsew", padx=(7, 0))
        tk.Button(
            activity["header"],
            text="View All",
            command=lambda: self._show_reference_page("transactions"),
            bg=CARD_2,
            fg="#dce5f3",
            activebackground=CARD_3,
            activeforeground="#ffffff",
            relief="flat",
            bd=0,
            padx=12,
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

        network = self._card(bottom, "Network Status", 285)
        network["outer"].grid(row=0, column=0, sticky="nsew", padx=(0, 7))
        self.dashboard_network_canvas = tk.Canvas(network["body"], bg=PANEL_DEEP, highlightthickness=0, height=185)
        self.dashboard_network_canvas.pack(fill="both", expand=True)
        self.dashboard_network_footer = tk.Label(
            network["body"], text=NO_DATA, bg=CARD, fg=GREEN, font=self.f_small, anchor="center"
        )
        self.dashboard_network_footer.pack(fill="x", pady=(8, 0))

        alerts = self._card(bottom, "Security Alerts", 285)
        alerts["outer"].grid(row=0, column=1, sticky="nsew", padx=7)
        tk.Button(
            alerts["header"],
            text="View All",
            command=lambda: self._show_reference_page("alerts"),
            bg=CARD_2,
            fg="#dce5f3",
            relief="flat",
            bd=0,
            padx=11,
            pady=5,
            font=self.f_tiny,
            cursor="hand2",
        ).pack(side="right")
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
            pady=8,
            cursor="hand2",
            font=self.f_small,
        ).pack(fill="x", pady=(7, 0))

        transactions = self._card(bottom, "Transaction Overview", 285)
        transactions["outer"].grid(row=0, column=2, sticky="nsew", padx=(7, 0))
        self.dashboard_transaction_canvas = tk.Canvas(
            transactions["body"], bg=PANEL_DEEP, highlightthickness=0, height=185
        )
        self.dashboard_transaction_canvas.pack(fill="both", expand=True)
        self.dashboard_transaction_footer = tk.Label(
            transactions["body"], text=NO_DATA, bg=CARD, fg="#d4deed", font=self.f_small, anchor="center"
        )
        self.dashboard_transaction_footer.pack(fill="x", pady=(8, 0))

        footer = tk.Label(
            page,
            text="Built with ♥ using Blockchain Technology for a Secure Future",
            bg=BG,
            fg="#71819d",
            font=self.f_small,
        )
        footer.grid(row=3, column=0, sticky="ew", pady=(12, 0))

    # --------------------------------------------------------------- rendering

    def _render_snapshot(self, data: Dict[str, Any]) -> None:
        super()._render_snapshot(data)

        connection, connection_ready = self._point_result(data.get("connection_status", {}))
        connection_text = str(connection) if connection_ready else NOT_CONNECTED
        self.top_connection.configure(
            text=connection_text,
            fg=GREEN if connection_text == "Connected" else YELLOW if connection_text == "Partial" else RED,
        )
        self.backend_value_label.configure(text=self._backend_display_name())

        # Convert source strings into concise reference-style notes while preserving provenance.
        vehicle = data.get("vehicle_overview", {}) if isinstance(data.get("vehicle_overview"), dict) else {}
        self.dashboard_metrics["vehicles"]["note"].configure(text=self._compact_source(vehicle.get("vehicle_id", {})))
        self.dashboard_metrics["transactions"]["note"].configure(text="backend.chain")
        self.dashboard_metrics["nodes"]["note"].configure(text=self._compact_source(data.get("v2x_peers", {})))

        chain, chain_ready = self._chain_rows(getattr(self.blockchain, "chain", None))
        if chain_ready:
            self.dashboard_transaction_footer.configure(text=self._transaction_footer(chain))

        peers_value, peers_ready = self._point_result(data.get("v2x_peers", {}))
        peers = peers_value if peers_ready and isinstance(peers_value, list) else []
        self.dashboard_network_footer.configure(
            text=(
                f"{len(peers)} Active Nodes    •    {connection_text}    •    Block Height {max(len(chain) - 1, 0)}"
                if chain_ready or peers_ready
                else NO_DATA
            )
        )

    def _backend_display_name(self) -> str:
        name = type(self.blockchain).__name__
        return name.replace("Backend", " Backend") if "Backend" in name else name

    @staticmethod
    def _compact_source(point: Any) -> str:
        if not isinstance(point, dict):
            return "source unavailable"
        source = str(point.get("source") or "source unavailable")
        return source.replace("DashboardDataProvider", "runtime provider")

    def _transaction_footer(self, chain: Sequence[Any]) -> str:
        if not chain:
            return "No ledger records"
        if len(chain) == 1:
            fields = self._block_fields(chain[-1])
            return f"1 Total Record    •    Latest Block #{fields['index']}    •    Trend unavailable"

        timestamps: List[datetime] = []
        for block in chain:
            raw = self._block_fields(block).get("timestamp")
            try:
                timestamps.append(datetime.fromisoformat(str(raw).replace("Z", "+00:00")))
            except (TypeError, ValueError):
                continue
        avg_text = "Avg. Block Time unavailable"
        if len(timestamps) >= 2:
            intervals = [
                max((timestamps[i] - timestamps[i - 1]).total_seconds(), 0.0)
                for i in range(1, len(timestamps))
            ]
            if intervals:
                avg_text = f"Avg. Block Time {sum(intervals) / len(intervals):.1f}s"
        latest = self._block_fields(chain[-1])
        return f"{len(chain)} Total Records    •    Latest Block #{latest['index']}    •    {avg_text}"

    # -------------------------------------------------------------- feed slots

    def _render_activity_feed(self, parent: tk.Widget, chain: Sequence[Any], limit: int) -> None:
        for child in parent.winfo_children():
            child.destroy()

        rows = list(chain)[-limit:]
        for block in reversed(rows):
            fields = self._block_fields(block)
            self._feed_row(
                parent,
                str(fields["event"]),
                f"Block #{fields['index']} • {fields['vehicle']}",
                str(fields["timestamp"]),
            )

        if not rows:
            self._empty_activity_slot(parent, "No blockchain activity yet")
            rows = []

        # Keep the reference's five-row visual rhythm without inventing events.
        if parent is getattr(self, "dashboard_activity_feed", None):
            for _ in range(max(0, limit - len(rows))):
                self._empty_activity_slot(parent, "No additional ledger activity")

    def _empty_activity_slot(self, parent: tk.Widget, text: str) -> None:
        row = tk.Frame(parent, bg=CARD_2, padx=10, pady=7)
        row.pack(fill="x", pady=2)
        icon = tk.Canvas(row, width=32, height=32, bg=CARD_2, highlightthickness=0)
        icon.pack(side="left", padx=(0, 9))
        icon.create_oval(3, 3, 29, 29, fill="#102139", outline="")
        icon.create_text(16, 16, text="◇", fill="#49617f", font=("Segoe UI Symbol", 10))
        tk.Label(row, text=text, bg=CARD_2, fg="#667a99", font=self.f_small).pack(side="left")

    # --------------------------------------------------------------- graphics

    def _draw_vehicle_art(self, canvas: tk.Canvas) -> None:
        """Draw a layered electric-blue sports car entirely with Canvas code."""
        canvas.delete("all")
        w = max(canvas.winfo_width(), 390)
        h = max(canvas.winfo_height(), 270)
        cx = w * 0.49
        base_y = h * 0.70

        # Shield background.
        shield_top = h * 0.10
        shield_w = min(w * 0.26, 105)
        shield_h = min(h * 0.43, 120)
        canvas.create_polygon(
            cx, shield_top,
            cx + shield_w, shield_top + 30,
            cx + shield_w * 0.88, shield_top + shield_h * 0.68,
            cx, shield_top + shield_h,
            cx - shield_w * 0.88, shield_top + shield_h * 0.68,
            cx - shield_w, shield_top + 30,
            outline="#12355f",
            fill="",
            width=1,
        )
        canvas.create_polygon(
            cx, shield_top + 18,
            cx + shield_w * 0.72, shield_top + 40,
            cx + shield_w * 0.62, shield_top + shield_h * 0.62,
            cx, shield_top + shield_h * 0.87,
            cx - shield_w * 0.62, shield_top + shield_h * 0.62,
            cx - shield_w * 0.72, shield_top + 40,
            outline="#0c294f",
            fill="",
        )

        # Holographic platform rings.
        for rx, ry, tone in (
            (150, 27, "#0758a3"),
            (127, 22, "#0b4c8c"),
            (105, 17, "#123c69"),
        ):
            canvas.create_oval(cx - rx, base_y + 48 - ry, cx + rx, base_y + 48 + ry, outline=tone, width=1)
        canvas.create_line(cx - 142, base_y + 47, cx + 142, base_y + 47, fill="#0d2a4d")

        # Soft glow layers around the car.
        for offset, color in ((10, "#06254c"), (6, "#07376d"), (3, "#0758a7")):
            canvas.create_line(
                cx - 128 - offset, base_y + 3,
                cx - 108, base_y - 24 - offset / 3,
                cx - 45, base_y - 43 - offset / 4,
                cx + 52, base_y - 40 - offset / 4,
                cx + 109, base_y - 15,
                cx + 132 + offset, base_y + 13,
                fill=color,
                width=max(1, int(offset / 2)),
                smooth=True,
            )

        # Main body silhouette: low-slung sports coupe.
        body = [
            cx - 139, base_y + 13,
            cx - 131, base_y - 4,
            cx - 110, base_y - 22,
            cx - 70, base_y - 33,
            cx - 38, base_y - 51,
            cx + 34, base_y - 52,
            cx + 69, base_y - 39,
            cx + 103, base_y - 27,
            cx + 132, base_y - 7,
            cx + 140, base_y + 13,
            cx + 123, base_y + 26,
            cx - 124, base_y + 26,
        ]
        canvas.create_polygon(body, fill=BLUE_BODY, outline=BLUE_BRIGHT, width=2, smooth=True)

        # Hood and side highlights.
        canvas.create_line(cx - 127, base_y - 3, cx - 55, base_y - 24, cx + 23, base_y - 24, fill="#4dd8ff", width=2, smooth=True)
        canvas.create_line(cx + 32, base_y - 23, cx + 107, base_y - 8, cx + 126, base_y + 4, fill="#198df5", width=2, smooth=True)
        canvas.create_line(cx - 115, base_y + 9, cx - 28, base_y + 4, cx + 91, base_y + 7, fill="#0f8ce5", width=1, smooth=True)
        canvas.create_line(cx - 35, base_y + 3, cx - 29, base_y + 22, fill="#2baaf9", width=1)
        canvas.create_line(cx + 47, base_y - 22, cx + 51, base_y + 21, fill="#1e83d4", width=1)

        # Roof / windshield cabin.
        canvas.create_polygon(
            cx - 62, base_y - 35,
            cx - 30, base_y - 67,
            cx + 33, base_y - 66,
            cx + 73, base_y - 37,
            fill="#08295a",
            outline="#42c7ff",
            width=2,
        )
        canvas.create_polygon(
            cx - 51, base_y - 38,
            cx - 25, base_y - 60,
            cx + 1, base_y - 60,
            cx - 3, base_y - 39,
            fill="#071a36",
            outline="#18598c",
        )
        canvas.create_polygon(
            cx + 4, base_y - 60,
            cx + 31, base_y - 59,
            cx + 61, base_y - 39,
            cx + 2, base_y - 39,
            fill="#071a36",
            outline="#18598c",
        )

        # Front grille/headlamp details.
        canvas.create_polygon(
            cx - 134, base_y + 6,
            cx - 91, base_y - 6,
            cx - 99, base_y + 7,
            cx - 132, base_y + 15,
            fill="#07182f",
            outline="#158ef3",
        )
        canvas.create_line(cx - 119, base_y - 5, cx - 88, base_y - 14, fill="#a8f2ff", width=3)
        canvas.create_line(cx + 95, base_y - 14, cx + 119, base_y - 4, fill="#52cfff", width=2)
        canvas.create_polygon(
            cx - 92, base_y + 10,
            cx - 56, base_y + 7,
            cx - 61, base_y + 19,
            cx - 96, base_y + 20,
            fill="#04101f",
            outline="#106ab8",
        )

        # Wheels, rims, brake accents.
        for wheel_x in (cx - 84, cx + 83):
            canvas.create_oval(wheel_x - 23, base_y + 5, wheel_x + 23, base_y + 51, fill=WHEEL, outline="#15426f", width=3)
            canvas.create_oval(wheel_x - 15, base_y + 13, wheel_x + 15, base_y + 43, fill="#0b1727", outline="#4f6c88", width=2)
            canvas.create_oval(wheel_x - 7, base_y + 21, wheel_x + 7, base_y + 35, fill="#ad2940", outline="#ff516b")
            for angle in range(0, 360, 60):
                rad = math.radians(angle)
                canvas.create_line(
                    wheel_x,
                    base_y + 28,
                    wheel_x + math.cos(rad) * 12,
                    base_y + 28 + math.sin(rad) * 12,
                    fill="#6b7f96",
                    width=1,
                )

        # Ground glow.
        canvas.create_arc(cx - 120, base_y + 28, cx + 120, base_y + 62, start=180, extent=180, style="arc", outline="#0d79d9", width=2)

    def _draw_peer_map(self, canvas: tk.Canvas, peers: Sequence[Any]) -> None:
        """Reference-like world backdrop with real relative peer markers only."""
        canvas.delete("all")
        w = max(canvas.winfo_width(), 430)
        h = max(canvas.winfo_height(), 180)

        # Decorative world topology background; these polygons are not peer coordinates.
        sx = w / 430.0
        sy = h / 180.0
        continents = (
            [(28, 56), (52, 42), (82, 45), (97, 57), (88, 73), (66, 76), (58, 92), (40, 84), (29, 70)],
            [(89, 94), (106, 101), (119, 124), (113, 154), (98, 142), (92, 119)],
            [(154, 51), (183, 38), (218, 43), (239, 55), (263, 46), (295, 53), (323, 48), (357, 61), (377, 77), (352, 87), (328, 84), (309, 97), (284, 91), (260, 78), (239, 84), (220, 72), (198, 76), (176, 66)],
            [(207, 82), (230, 90), (240, 112), (227, 146), (210, 155), (195, 132), (188, 105)],
            [(342, 117), (370, 111), (391, 125), (379, 143), (351, 142)],
        )
        for points in continents:
            scaled = [(x * sx, y * sy) for x, y in points]
            flat = [coord for point in scaled for coord in point]
            canvas.create_polygon(*flat, fill=MAP_FILL, outline=MAP_EDGE, width=1, smooth=True)

        # Sparse decorative grid dots, intentionally non-semantic.
        for x in range(22, 420, 18):
            for y in range(28, 158, 18):
                if (x + y) % 54 == 0:
                    canvas.create_oval(x * sx - 1, y * sy - 1, x * sx + 1, y * sy + 1, fill="#24425f", outline="")

        if not peers:
            canvas.create_text(w / 2, h - 12, text="No observed V2X peers", fill=MUTED, font=self.f_tiny)
            return

        # Peers do not expose geographic coordinates; plot relative distance/heading
        # around the canvas center and label that fact so the visualization stays truthful.
        cx, cy = w / 2, h / 2
        max_r = min(w * 0.32, h * 0.37)
        for idx, peer in enumerate(peers[:10]):
            if not isinstance(peer, dict):
                continue
            distance = self._as_float(self._first_value(peer, ("relative_distance", "distance", "distance_m"), None))
            heading = self._as_float(self._first_value(peer, ("relative_heading", "heading", "bearing"), None))
            if distance is None or heading is None:
                continue
            radius = min(max(distance, 0.0), 100.0) / 100.0 * max_r
            angle = math.radians(heading - 90.0)
            px = cx + math.cos(angle) * radius
            py = cy + math.sin(angle) * radius
            canvas.create_line(cx, cy, px, py, fill="#17634f", width=1)
            canvas.create_oval(px - 5, py - 5, px + 5, py + 5, fill=GREEN, outline="#a7ffe0")
            canvas.create_oval(px - 10, py - 10, px + 10, py + 10, outline="#1c7c60")
            canvas.create_text(px + 8, py - 8, text=str(peer.get("peer_id", peer.get("id", idx + 1))), fill="#bfe8d8", font=self.f_tiny, anchor="w")
        canvas.create_text(w - 8, h - 8, text="relative topology • not geographic", fill="#526883", font=self.f_tiny, anchor="se")

    def _draw_transaction_chart(self, canvas: tk.Canvas, chain: Sequence[Any]) -> None:
        canvas.delete("all")
        w = max(canvas.winfo_width(), 430)
        h = max(canvas.winfo_height(), 175)
        pad_l, pad_r, pad_t, pad_b = 34, 16, 20, 28

        for row in range(4):
            y = pad_t + row * ((h - pad_t - pad_b) / 3)
            canvas.create_line(pad_l, y, w - pad_r, y, fill=GRID)

        if not chain:
            canvas.create_text(w / 2, h / 2, text="No ledger history", fill=MUTED, font=self.f_small)
            return

        if len(chain) == 1:
            x = (pad_l + w - pad_r) / 2
            y = h / 2 - 8
            canvas.create_line(pad_l, y, w - pad_r, y, fill="#2c205f", width=2)
            canvas.create_oval(x - 5, y - 5, x + 5, y + 5, fill=PURPLE, outline="#c3b9ff")
            canvas.create_text(w / 2, h - 12, text="Insufficient history for trend", fill=MUTED, font=self.f_tiny)
            return

        values: List[float] = []
        for idx, block in enumerate(list(chain)[-18:]):
            fields = self._block_fields(block)
            try:
                values.append(float(fields["index"]))
            except (TypeError, ValueError):
                values.append(float(idx))

        lo, hi = min(values), max(values)
        span = max(hi - lo, 1.0)
        step = (w - pad_l - pad_r) / max(len(values) - 1, 1)
        points: List[float] = []
        for idx, value in enumerate(values):
            x = pad_l + idx * step
            y = h - pad_b - ((value - lo) / span) * (h - pad_t - pad_b)
            points.extend((x, y))

        # Under-line vertical fill strokes create a subtle reference-like glow.
        for idx in range(0, len(points), 2):
            canvas.create_line(points[idx], points[idx + 1], points[idx], h - pad_b, fill="#15113c")
        canvas.create_line(*points, fill=PURPLE, width=3, smooth=True)
        for idx in range(0, len(points), 2):
            x, y = points[idx], points[idx + 1]
            canvas.create_oval(x - 3, y - 3, x + 3, y + 3, fill="#a172ff", outline="")


SmartCarDashboard = PixelMatchedSmartCarDashboard
