"""Stable-render live dashboard layer.

This shell keeps the authenticated Go live-socket backend from ``dashboard_live_ui``
but avoids destructive redraws for high-frequency dashboard widgets. Feed rows are
allocated once and updated in place, the transaction overview renders a cached,
source-backed ledger-growth graph from real block timestamps, and the navigation
sidebar is larger and user-resizable without affecting backend behavior.
"""

from __future__ import annotations

import tkinter as tk
from datetime import datetime, timezone
from tkinter import font
from typing import Any, Dict, List, Sequence, Tuple

import dashboard_reference_ui as reference
from dashboard import NO_DATA
from dashboard_live_ui import LiveSocketSmartCarDashboard


class StableLiveSmartCarDashboard(LiveSocketSmartCarDashboard):
    """Live socket dashboard with stable feeds, graphing, and resizable navigation."""

    TRANSACTION_GRAPH_WINDOW = 36
    SIDEBAR_DEFAULT_WIDTH = 292
    SIDEBAR_MIN_WIDTH = 220
    SIDEBAR_MAX_WIDTH = 390

    def __init__(self) -> None:
        # These must exist before the inherited constructor performs its first render.
        self._stable_feed_slots: Dict[str, List[Dict[str, Any]]] = {}
        self._transaction_chart_signatures: Dict[str, Tuple[Any, ...]] = {}
        self._sidebar_drag_start_x = 0
        self._sidebar_drag_start_width = self.SIDEBAR_DEFAULT_WIDTH
        self._sidebar_current_width = self.SIDEBAR_DEFAULT_WIDTH
        super().__init__()

    # ---------------------------------------------------------- sidebar UX

    def _setup_reference_fonts(self) -> None:
        """Keep content typography unchanged while making navigation easier to read."""
        super()._setup_reference_fonts()
        self.f_sidebar_menu = font.Font(family="Segoe UI", size=11)
        self.f_sidebar_group = font.Font(family="Segoe UI", size=9, weight="bold")
        self.f_sidebar_status = font.Font(family="Segoe UI", size=9)

    def _build_reference_sidebar(self) -> None:
        """Build the inherited sidebar, then make it wider and drag-resizable."""
        super()._build_reference_sidebar()
        self._set_sidebar_width(self.SIDEBAR_DEFAULT_WIDTH)

        for button in self._reference_buttons.values():
            button.configure(font=self.f_sidebar_menu, padx=12, pady=11)

        self._apply_sidebar_label_fonts(self.sidebar)

        self._sidebar_resize_handle = tk.Frame(
            self.sidebar,
            bg="#1b3557",
            width=7,
            cursor="sb_h_double_arrow",
        )
        self._sidebar_resize_handle.place(relx=1.0, x=-7, y=0, relheight=1.0)
        self._sidebar_resize_handle.bind("<Button-1>", self._on_sidebar_resize_start)
        self._sidebar_resize_handle.bind("<B1-Motion>", self._on_sidebar_resize_drag)
        self._sidebar_resize_handle.bind("<Double-Button-1>", self._on_sidebar_resize_reset)
        self._sidebar_resize_handle.bind("<Enter>", lambda _e: self._sidebar_resize_handle.configure(bg="#456ea7"))
        self._sidebar_resize_handle.bind("<Leave>", lambda _e: self._sidebar_resize_handle.configure(bg="#1b3557"))
        self.after_idle(self._sidebar_resize_handle.lift)

    def _apply_sidebar_label_fonts(self, widget: tk.Widget) -> None:
        """Increase only navigation/group/status text, not dashboard content fonts."""
        for child in widget.winfo_children():
            try:
                text = str(child.cget("text"))
            except Exception:
                text = ""
            if isinstance(child, tk.Label):
                if text in {"CORE", "SECURITY", "SYSTEM"}:
                    child.configure(font=self.f_sidebar_group)
                elif text in {"Checking runtime...", "Runtime partial", "Runtime connected", "Runtime not connected"}:
                    child.configure(font=self.f_sidebar_status)
            self._apply_sidebar_label_fonts(child)

    def _set_sidebar_width(self, width: int) -> int:
        bounded = max(self.SIDEBAR_MIN_WIDTH, min(int(width), self.SIDEBAR_MAX_WIDTH))
        self._sidebar_current_width = bounded
        if hasattr(self, "sidebar"):
            self.sidebar.configure(width=bounded)
            self.sidebar.pack_propagate(False)
        return bounded

    def _on_sidebar_resize_start(self, event: tk.Event) -> None:
        self._sidebar_drag_start_x = int(event.x_root)
        current = int(self.sidebar.winfo_width() or self._sidebar_current_width)
        self._sidebar_drag_start_width = current

    def _on_sidebar_resize_drag(self, event: tk.Event) -> None:
        delta = int(event.x_root) - self._sidebar_drag_start_x
        self._set_sidebar_width(self._sidebar_drag_start_width + delta)

    def _on_sidebar_resize_reset(self, _event: tk.Event | None = None) -> None:
        self._set_sidebar_width(self.SIDEBAR_DEFAULT_WIDTH)

    # ---------------------------------------------------------- stable feeds

    def _feed_slot(self, parent: tk.Widget, index: int) -> Dict[str, Any]:
        """Return a persistent feed row; never destroy/recreate rows during live updates."""
        key = str(parent)
        slots = self._stable_feed_slots.setdefault(key, [])
        while len(slots) <= index:
            row = tk.Frame(parent, bg=reference.CARD_2, padx=10, pady=8)
            row.pack(fill="x", pady=3)

            icon = tk.Canvas(row, width=30, height=30, bg=reference.CARD_2, highlightthickness=0)
            icon.pack(side="left", padx=(0, 9))
            icon.create_oval(3, 3, 27, 27, fill="#122740", outline="", tags=("bubble",))
            icon.create_text(15, 15, text="◇", fill=reference.CYAN, font=("Segoe UI Symbol", 10), tags=("glyph",))

            copy = tk.Frame(row, bg=reference.CARD_2)
            copy.pack(side="left", fill="both", expand=True)
            title = tk.Label(copy, text="", bg=reference.CARD_2, fg=reference.TEXT, font=self.f_small, anchor="w")
            title.pack(anchor="w")
            subtitle = tk.Label(copy, text="", bg=reference.CARD_2, fg=reference.MUTED, font=self.f_tiny, anchor="w")
            subtitle.pack(anchor="w", pady=(2, 0))
            right = tk.Label(row, text="", bg=reference.CARD_2, fg="#b9c5da", font=self.f_tiny)
            right.pack(side="right")

            slots.append(
                {
                    "row": row,
                    "icon": icon,
                    "title": title,
                    "subtitle": subtitle,
                    "right": right,
                    "signature": None,
                    "visible": True,
                }
            )
        return slots[index]

    def _apply_feed_items(self, parent: tk.Widget, items: Sequence[Tuple[str, str, str, str]], capacity: int) -> None:
        """Update only changed labels/icons and keep Tk widgets alive between socket frames."""
        active = min(len(items), capacity)
        severity_colors = {
            "high": reference.RED,
            "medium": reference.ORANGE,
            "ok": reference.GREEN,
            "boundary": reference.PURPLE,
        }

        for index in range(capacity):
            slot = self._feed_slot(parent, index)
            row = slot["row"]
            if index >= active:
                if slot["visible"]:
                    row.pack_forget()
                    slot["visible"] = False
                continue

            title, subtitle, right, severity = items[index]
            signature = (title, subtitle, right, severity)
            if not slot["visible"]:
                row.pack(fill="x", pady=3)
                slot["visible"] = True
            if slot["signature"] == signature:
                continue

            slot["title"].configure(text=title)
            slot["subtitle"].configure(text=subtitle)
            slot["right"].configure(text=right)
            slot["icon"].itemconfigure("glyph", fill=severity_colors.get(severity, reference.CYAN))
            slot["signature"] = signature

    def _render_activity_feed(self, parent: tk.Widget, chain: Sequence[Any], limit: int) -> None:
        rows = list(chain)[-limit:]
        if not rows:
            items = [(NO_DATA, "Waiting for committed blockchain activity.", "", "")]
        else:
            items = []
            for block in reversed(rows):
                fields = self._block_fields(block)
                items.append(
                    (
                        str(fields["event"]),
                        f"Block #{fields['index']} • {fields['vehicle']}",
                        str(fields["timestamp"]),
                        "",
                    )
                )
        self._apply_feed_items(parent, items, max(1, limit))

    def _render_alert_feed(self, parent: tk.Widget, alerts: Sequence[Tuple[str, str, str]], limit: int) -> None:
        if not alerts:
            items = [
                (
                    "No explicit alerts",
                    "No source-backed runtime/security warning is currently exposed.",
                    "OK",
                    "ok",
                )
            ]
        else:
            items = [
                (title, detail, severity.title() if severity else "", severity)
                for title, detail, severity in list(alerts)[:limit]
            ]
        self._apply_feed_items(parent, items, max(1, limit))

    # ----------------------------------------------------- transaction graph

    @staticmethod
    def _parse_block_time(value: Any) -> datetime | None:
        raw = str(value or "").strip()
        if not raw:
            return None
        if raw.endswith("Z"):
            raw = raw[:-1] + "+00:00"
        try:
            parsed = datetime.fromisoformat(raw)
        except ValueError:
            return None
        # Backend timestamps are UTC RFC3339. Normalize older naive chain entries
        # to UTC so mixed old/new histories cannot raise aware-vs-naive errors.
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=timezone.utc)
        return parsed.astimezone(timezone.utc)

    def _transaction_series(self, chain: Sequence[Any]) -> List[Tuple[datetime, int, str]]:
        """Return real timestamp + cumulative committed-record count + event label."""
        window = list(chain)[-self.TRANSACTION_GRAPH_WINDOW :]
        series: List[Tuple[datetime, int, str]] = []
        total_before_window = max(0, len(chain) - len(window))
        for offset, block in enumerate(window, start=1):
            fields = self._block_fields(block)
            timestamp = self._parse_block_time(fields.get("timestamp"))
            if timestamp is None:
                continue
            series.append((timestamp, total_before_window + offset, str(fields.get("event", ""))))
        return series

    def _draw_transaction_chart(self, canvas: tk.Canvas, chain: Sequence[Any]) -> None:
        """Render a professional, cached ledger-growth trend from actual block history."""
        width = max(int(canvas.winfo_width() or 0), 360)
        height = max(int(canvas.winfo_height() or 0), 170)
        raw_tail = list(chain)[-self.TRANSACTION_GRAPH_WINDOW :]
        signature_rows = []
        for block in raw_tail:
            fields = self._block_fields(block)
            signature_rows.append((fields.get("index"), fields.get("timestamp"), fields.get("event")))
        source_signature = tuple(signature_rows)
        signature = (width, height, source_signature)
        key = str(canvas)
        if self._transaction_chart_signatures.get(key) == signature:
            return
        self._transaction_chart_signatures[key] = signature

        canvas.delete("all")
        pad_left, pad_right, pad_top, pad_bottom = 48, 18, 24, 38
        plot_w = max(1, width - pad_left - pad_right)
        plot_h = max(1, height - pad_top - pad_bottom)
        x0, y0 = pad_left, pad_top
        x1, y1 = pad_left + plot_w, pad_top + plot_h

        # Dark plotting field and restrained grid.
        canvas.create_rectangle(x0, y0, x1, y1, fill="#081426", outline=reference.BORDER)
        for row in range(5):
            y = y0 + (plot_h * row / 4.0)
            canvas.create_line(x0, y, x1, y, fill=reference.GRID)
        for col in range(5):
            x = x0 + (plot_w * col / 4.0)
            canvas.create_line(x, y0, x, y1, fill="#122c49")

        series = self._transaction_series(chain)
        if not series:
            canvas.create_text(
                width / 2,
                height / 2,
                text="No committed transaction history",
                fill=reference.MUTED,
                font=self.f_small,
            )
            canvas.create_text(x0, height - 12, text="Source: backend.chain", fill=reference.DIM, font=self.f_tiny, anchor="w")
            return

        first_count = series[0][1]
        last_count = series[-1][1]
        min_count = max(0, first_count - 1)
        max_count = max(last_count, min_count + 1)
        count_span = max(1, max_count - min_count)

        first_time = series[0][0]
        last_time = series[-1][0]
        time_span = max((last_time - first_time).total_seconds(), 0.0)

        points: List[float] = []
        for index, (timestamp, count, _event) in enumerate(series):
            if time_span > 0:
                x_ratio = (timestamp - first_time).total_seconds() / time_span
            else:
                x_ratio = index / max(1, len(series) - 1)
            y_ratio = (count - min_count) / count_span
            x = x0 + max(0.0, min(1.0, x_ratio)) * plot_w
            y = y1 - max(0.0, min(1.0, y_ratio)) * plot_h
            points.extend((x, y))

        # Y-axis labels are real committed-record counts.
        for row in range(5):
            ratio = 1.0 - row / 4.0
            value = int(round(min_count + ratio * count_span))
            y = y0 + (plot_h * row / 4.0)
            canvas.create_text(x0 - 8, y, text=str(value), fill=reference.MUTED, font=self.f_tiny, anchor="e")

        start_label = first_time.strftime("%H:%M:%S")
        end_label = last_time.strftime("%H:%M:%S")
        canvas.create_text(x0, y1 + 18, text=start_label, fill=reference.MUTED, font=self.f_tiny, anchor="w")
        canvas.create_text(x1, y1 + 18, text=end_label, fill=reference.MUTED, font=self.f_tiny, anchor="e")
        canvas.create_text(x0, 10, text="Committed blockchain records", fill="#d9e4f7", font=self.f_tiny, anchor="w")

        if len(points) == 2:
            x, y = points
            canvas.create_oval(x - 4, y - 4, x + 4, y + 4, fill=reference.PURPLE, outline="#b8a7ff")
            canvas.create_text(width / 2, y0 + plot_h / 2, text="Insufficient history for trend", fill=reference.MUTED, font=self.f_tiny)
        else:
            area = [x0, y1] + points + [x1, y1]
            canvas.create_polygon(*area, fill="#1b2457", outline="", stipple="gray25")
            canvas.create_line(*points, fill=reference.PURPLE, width=3, smooth=True, splinesteps=20)
            # Keep markers restrained: endpoints + every fourth interior point.
            pair_count = len(points) // 2
            marker_indexes = {0, pair_count - 1}
            marker_indexes.update(range(4, max(4, pair_count - 1), 4))
            for idx in sorted(marker_indexes):
                if idx < 0 or idx >= pair_count:
                    continue
                x, y = points[idx * 2], points[idx * 2 + 1]
                canvas.create_oval(x - 3, y - 3, x + 3, y + 3, fill="#9b78ff", outline="#d9ccff")

        elapsed = max(0.0, (last_time - first_time).total_seconds())
        span_text = f"{elapsed:.1f}s span" if elapsed < 60 else f"{elapsed / 60.0:.1f}m span"
        canvas.create_text(
            x1,
            10,
            text=f"{len(series)} visible • {span_text}",
            fill=reference.DIM,
            font=self.f_tiny,
            anchor="e",
        )


SmartCarDashboard = StableLiveSmartCarDashboard
