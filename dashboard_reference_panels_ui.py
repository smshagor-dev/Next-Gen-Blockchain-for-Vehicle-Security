"""Exact-reference presentation layer for the two remaining overview panels.

Only the Vehicle Status Overview visual and Network Status visual are changed.
All live socket, security, navigation, transaction, feed, and backend behavior stays
inherited from dashboard_live_stable_ui.
"""

from __future__ import annotations

import math
import tkinter as tk
from typing import Any, Dict, Sequence

import dashboard_reference_ui as reference
from dashboard import NO_DATA, UNAVAILABLE
from dashboard_live_stable_ui import StableLiveSmartCarDashboard


class ExactReferencePanelsDashboard(StableLiveSmartCarDashboard):
    """Match the supplied Vehicle Status + Network Status reference panels."""

    def __init__(self) -> None:
        self._reference_vehicle_photo = None
        self._reference_vehicle_photo_key = None
        self._network_metric_labels: Dict[str, tk.Label] = {}
        super().__init__()
        self._install_reference_network_metrics()

    # ---------------------------------------------------------------- vehicle

    def _draw_vehicle_art(self, canvas: tk.Canvas) -> None:
        """Render the supplied-reference style blue three-quarter sports car."""
        width = max(360, int(canvas.winfo_width() or 360))
        height = max(250, int(canvas.winfo_height() or 250))
        key = (width // 6, height // 6)
        if self._reference_vehicle_photo is not None and key == self._reference_vehicle_photo_key:
            return

        try:
            from PIL import Image, ImageDraw, ImageFilter, ImageTk

            scale = 4
            w, h = width * scale, height * scale
            bg = Image.new("RGBA", (w, h), (4, 12, 27, 255))
            draw = ImageDraw.Draw(bg)

            # Smooth vertical deep-navy background matching the reference panel.
            top = (8, 24, 48)
            bottom = (3, 10, 22)
            for y in range(h):
                t = y / max(h - 1, 1)
                rgb = tuple(int(top[i] * (1 - t) + bottom[i] * t) for i in range(3))
                draw.line((0, y, w, y), fill=(*rgb, 255))

            cx = int(w * 0.50)
            car_y = int(h * 0.58)

            # Large faint shield behind the car.
            shield = Image.new("RGBA", (w, h), (0, 0, 0, 0))
            sd = ImageDraw.Draw(shield)
            sw, sh = int(w * 0.22), int(h * 0.36)
            sy = int(h * 0.10)
            pts = [
                (cx, sy), (cx + sw, sy + int(sh * 0.20)),
                (cx + int(sw * 0.83), sy + int(sh * 0.70)),
                (cx, sy + sh),
                (cx - int(sw * 0.83), sy + int(sh * 0.70)),
                (cx - sw, sy + int(sh * 0.20)),
            ]
            sd.line(pts + [pts[0]], fill=(20, 80, 145, 110), width=2 * scale, joint="curve")
            inner = [(int(cx + (x - cx) * 0.76), int(sy + (y - sy) * 0.76 + 10 * scale)) for x, y in pts]
            sd.line(inner + [inner[0]], fill=(13, 60, 116, 90), width=scale, joint="curve")
            bg = Image.alpha_composite(bg, shield)

            # Holographic blue base/glow.
            glow = Image.new("RGBA", (w, h), (0, 0, 0, 0))
            gd = ImageDraw.Draw(glow)
            py = int(h * 0.81)
            gd.ellipse((cx - int(w * 0.39), py - int(h * 0.09), cx + int(w * 0.39), py + int(h * 0.09)), fill=(0, 105, 255, 45))
            bg = Image.alpha_composite(bg, glow.filter(ImageFilter.GaussianBlur(22 * scale)))
            rings = Image.new("RGBA", (w, h), (0, 0, 0, 0))
            rd = ImageDraw.Draw(rings)
            for i, alpha in enumerate((210, 135, 75)):
                rx = int(w * (0.34 + i * 0.045))
                ry = int(h * (0.045 + i * 0.014))
                rd.ellipse((cx - rx, py - ry, cx + rx, py + ry), outline=(10, 130, 255, alpha), width=max(scale, 1))
            bg = Image.alpha_composite(bg, rings)

            # Car shadow.
            shadow = Image.new("RGBA", (w, h), (0, 0, 0, 0))
            shd = ImageDraw.Draw(shadow)
            shd.ellipse((cx - int(w * 0.34), car_y + int(h * 0.16), cx + int(w * 0.35), car_y + int(h * 0.29)), fill=(0, 0, 0, 210))
            bg = Image.alpha_composite(bg, shadow.filter(ImageFilter.GaussianBlur(12 * scale)))

            # Three-quarter front sports-car body, matching the reference stance.
            car = Image.new("RGBA", (w, h), (0, 0, 0, 0))
            cd = ImageDraw.Draw(car)
            body = [
                (cx - int(w * 0.37), car_y + int(h * 0.06)),
                (cx - int(w * 0.35), car_y - int(h * 0.03)),
                (cx - int(w * 0.28), car_y - int(h * 0.10)),
                (cx - int(w * 0.15), car_y - int(h * 0.13)),
                (cx - int(w * 0.04), car_y - int(h * 0.16)),
                (cx + int(w * 0.12), car_y - int(h * 0.15)),
                (cx + int(w * 0.24), car_y - int(h * 0.10)),
                (cx + int(w * 0.34), car_y - int(h * 0.02)),
                (cx + int(w * 0.37), car_y + int(h * 0.07)),
                (cx + int(w * 0.30), car_y + int(h * 0.13)),
                (cx + int(w * 0.12), car_y + int(h * 0.15)),
                (cx - int(w * 0.30), car_y + int(h * 0.15)),
            ]
            mask = Image.new("L", (w, h), 0)
            ImageDraw.Draw(mask).polygon(body, fill=255)
            metallic = Image.new("RGBA", (w, h), (0, 0, 0, 0))
            md = ImageDraw.Draw(metallic)
            y0 = car_y - int(h * 0.18)
            y1 = car_y + int(h * 0.16)
            colors = ((30, 160, 255), (7, 88, 194), (3, 38, 99))
            for y in range(max(0, y0), min(h, y1)):
                t = (y - y0) / max(y1 - y0, 1)
                if t < 0.45:
                    q = t / 0.45
                    rgb = tuple(int(colors[0][i] * (1-q) + colors[1][i] * q) for i in range(3))
                else:
                    q = (t - 0.45) / 0.55
                    rgb = tuple(int(colors[1][i] * (1-q) + colors[2][i] * q) for i in range(3))
                md.line((0, y, w, y), fill=(*rgb, 255))
            car = Image.alpha_composite(car, Image.composite(metallic, Image.new("RGBA", (w, h), (0, 0, 0, 0)), mask))
            cd = ImageDraw.Draw(car)
            cd.line(body + [body[0]], fill=(52, 201, 255, 255), width=2 * scale, joint="curve")

            # Cabin / windshield.
            cabin = [
                (cx - int(w * 0.15), car_y - int(h * 0.13)),
                (cx - int(w * 0.08), car_y - int(h * 0.23)),
                (cx + int(w * 0.09), car_y - int(h * 0.23)),
                (cx + int(w * 0.20), car_y - int(h * 0.12)),
            ]
            cd.polygon(cabin, fill=(3, 25, 53, 255), outline=(46, 185, 255, 255))
            cd.line((cx - int(w * 0.01), car_y - int(h * 0.225), cx + int(w * 0.01), car_y - int(h * 0.125)), fill=(18, 86, 147, 255), width=scale)

            # Hood/body light streaks and panel lines.
            cd.line((cx - int(w * 0.34), car_y - int(h * 0.01), cx - int(w * 0.18), car_y - int(h * 0.09), cx + int(w * 0.05), car_y - int(h * 0.09)), fill=(145, 238, 255, 245), width=2 * scale)
            cd.line((cx + int(w * 0.06), car_y - int(h * 0.09), cx + int(w * 0.27), car_y - int(h * 0.03)), fill=(52, 178, 255, 225), width=2 * scale)
            cd.line((cx - int(w * 0.27), car_y + int(h * 0.07), cx + int(w * 0.27), car_y + int(h * 0.08)), fill=(13, 106, 207, 255), width=scale)
            cd.line((cx - int(w * 0.08), car_y - int(h * 0.08), cx - int(w * 0.05), car_y + int(h * 0.12)), fill=(15, 112, 198, 230), width=scale)
            cd.line((cx + int(w * 0.11), car_y - int(h * 0.10), cx + int(w * 0.13), car_y + int(h * 0.12)), fill=(15, 90, 166, 230), width=scale)

            # Front grille / headlights.
            cd.polygon([
                (cx - int(w * 0.36), car_y + int(h * 0.02)),
                (cx - int(w * 0.24), car_y - int(h * 0.01)),
                (cx - int(w * 0.27), car_y + int(h * 0.07)),
                (cx - int(w * 0.36), car_y + int(h * 0.09)),
            ], fill=(2, 18, 40, 255), outline=(14, 118, 222, 255))
            cd.line((cx - int(w * 0.32), car_y - int(h * 0.025), cx - int(w * 0.23), car_y - int(h * 0.055)), fill=(215, 251, 255, 255), width=3 * scale)
            cd.line((cx + int(w * 0.24), car_y - int(h * 0.045), cx + int(w * 0.31), car_y - int(h * 0.015)), fill=(111, 224, 255, 245), width=2 * scale)

            # Wheels: large, dark, with red brake accents like reference.
            wheel_y = car_y + int(h * 0.12)
            wheel_r = int(h * 0.085)
            for wx in (cx - int(w * 0.22), cx + int(w * 0.23)):
                cd.ellipse((wx-wheel_r-3*scale, wheel_y-wheel_r-3*scale, wx+wheel_r+3*scale, wheel_y+wheel_r+3*scale), fill=(1, 5, 12, 255), outline=(14, 80, 139, 255), width=2*scale)
                cd.ellipse((wx-int(wheel_r*0.72), wheel_y-int(wheel_r*0.72), wx+int(wheel_r*0.72), wheel_y+int(wheel_r*0.72)), fill=(8, 17, 28, 255), outline=(71, 100, 128, 255), width=2*scale)
                for angle in range(0, 360, 30):
                    a = math.radians(angle)
                    rr = int(wheel_r * 0.60)
                    cd.line((wx, wheel_y, wx + int(math.cos(a)*rr), wheel_y + int(math.sin(a)*rr)), fill=(72, 94, 115, 255), width=scale)
                cd.ellipse((wx-int(wheel_r*0.24), wheel_y-int(wheel_r*0.24), wx+int(wheel_r*0.24), wheel_y+int(wheel_r*0.24)), fill=(176, 29, 50, 255), outline=(255, 72, 96, 255), width=scale)

            # Blue outline glow without repainting the whole panel every live frame.
            glow_car = car.filter(ImageFilter.GaussianBlur(4 * scale))
            bg = Image.alpha_composite(bg, glow_car)
            bg = Image.alpha_composite(bg, car)

            image = bg.resize((width, height), Image.Resampling.LANCZOS)
            self._reference_vehicle_photo = ImageTk.PhotoImage(image=image)
            self._reference_vehicle_photo_key = key
            canvas.delete("all")
            canvas.create_image(width / 2, height / 2, image=self._reference_vehicle_photo, anchor="center")
        except Exception:
            super()._draw_vehicle_art(canvas)

    # ---------------------------------------------------------------- network

    def _install_reference_network_metrics(self) -> None:
        """Replace the old sentence footer with the reference's four metric columns."""
        footer = getattr(self, "dashboard_network_footer", None)
        if footer is None:
            return
        parent = footer.master
        footer.pack_forget()

        metric_bar = tk.Frame(parent, bg=reference.CARD)
        metric_bar.pack(fill="x", pady=(8, 0))
        specs = (
            ("nodes", "Active Nodes"),
            ("latency", "Avg. Latency"),
            ("uptime", "Uptime"),
            ("height", "Block Height"),
        )
        for idx, (key, label) in enumerate(specs):
            metric_bar.grid_columnconfigure(idx, weight=1, uniform="network_metric")
            cell = tk.Frame(metric_bar, bg=reference.CARD)
            cell.grid(row=0, column=idx, sticky="nsew")
            value = tk.Label(cell, text=UNAVAILABLE, bg=reference.CARD, fg=reference.GREEN, font=("Segoe UI", 13, "bold"))
            value.pack()
            tk.Label(cell, text=label, bg=reference.CARD, fg="#9aabc4", font=("Segoe UI", 8)).pack(pady=(2, 0))
            self._network_metric_labels[key] = value

    def _draw_peer_map(self, canvas: tk.Canvas, peers: Sequence[Any]) -> None:
        """Reference-style dotted world map with source-backed peer overlays only."""
        canvas.delete("all")
        w = max(int(canvas.winfo_width() or 0), 360)
        h = max(int(canvas.winfo_height() or 0), 170)
        canvas.configure(bg="#071426")

        # Dotted world silhouette. These dots are decorative map context only.
        # Actual V2X peers are rendered separately from real relative telemetry.
        sx, sy = w / 430.0, h / 180.0
        masks = (
            [(22,45),(42,37),(64,36),(82,43),(96,55),(92,69),(79,74),(67,82),(56,98),(42,91),(31,75),(22,60)],
            [(82,91),(97,96),(108,111),(112,130),(104,151),(94,142),(87,119)],
            [(145,49),(165,40),(192,38),(212,44),(232,49),(252,45),(275,48),(298,45),(322,50),(346,60),(365,75),(348,84),(326,83),(307,91),(288,89),(270,80),(250,82),(232,73),(211,76),(190,67),(169,67)],
            [(203,82),(219,87),(231,101),(235,119),(226,142),(211,154),(198,137),(190,111)],
            [(340,116),(359,111),(382,119),(394,132),(383,143),(359,143),(344,135)],
        )

        def inside(poly, x, y):
            hit = False
            j = len(poly) - 1
            for i in range(len(poly)):
                xi, yi = poly[i]; xj, yj = poly[j]
                if ((yi > y) != (yj > y)) and x < (xj-xi) * (y-yi) / max((yj-yi), 1e-9) + xi:
                    hit = not hit
                j = i
            return hit

        for yy in range(30, 158, 5):
            for xx in range(18, 406, 5):
                if any(inside(poly, xx, yy) for poly in masks):
                    tone = "#24445f" if (xx + yy) % 15 else "#2d526d"
                    x, y = xx*sx, yy*sy
                    canvas.create_oval(x-0.8, y-0.8, x+0.8, y+0.8, fill=tone, outline="")

        # Decorative route arcs are static styling only; endpoints are not presented as real nodes.
        routes = [((66,82),(178,72)), ((178,72),(280,86)), ((280,86),(360,132))]
        for (x1,y1),(x2,y2) in routes:
            canvas.create_line(x1*sx,y1*sy,x2*sx,y2*sy,fill="#164a52",width=1,smooth=True)

        if not peers:
            return

        cx, cy = w/2, h/2
        max_r = min(w*0.34, h*0.38)
        for idx, peer in enumerate(peers[:12]):
            if not isinstance(peer, dict):
                continue
            distance = self._as_float(self._first_value(peer, ("relative_distance", "distance", "distance_m"), None))
            heading = self._as_float(self._first_value(peer, ("relative_heading", "heading", "bearing"), None))
            if distance is None or heading is None:
                continue
            radius = min(max(distance, 0.0), 100.0) / 100.0 * max_r
            angle = math.radians(heading - 90.0)
            px, py = cx + math.cos(angle)*radius, cy + math.sin(angle)*radius
            canvas.create_line(cx, cy, px, py, fill="#1c715c", width=1)
            canvas.create_oval(px-8, py-8, px+8, py+8, fill="#0b5b49", outline="")
            canvas.create_oval(px-4, py-4, px+4, py+4, fill=reference.GREEN, outline="#9effd8")

    def _render_snapshot(self, data: Dict[str, Any]) -> None:
        super()._render_snapshot(data)
        if not self._network_metric_labels:
            return

        peers_value, peers_ready = self._point_result(data.get("v2x_peers", {}))
        peers = peers_value if peers_ready and isinstance(peers_value, list) else []
        chain, chain_ready = self._chain_rows(getattr(self.blockchain, "chain", None))

        self._network_metric_labels["nodes"].configure(text=str(len(peers)) if peers_ready else UNAVAILABLE)
        self._network_metric_labels["height"].configure(text=str(max(len(chain)-1, 0)) if chain_ready else UNAVAILABLE)

        latency = self._extract_network_metric(data, ("avg_latency_ms", "latency_ms", "network_latency_ms"))
        uptime = self._extract_network_metric(data, ("uptime_percent", "uptime_pct", "network_uptime"))
        self._network_metric_labels["latency"].configure(text=f"{latency:g} ms" if latency is not None else "—")
        self._network_metric_labels["uptime"].configure(text=f"{uptime:g}%" if uptime is not None else "—")

    def _extract_network_metric(self, data: Dict[str, Any], keys: Sequence[str]) -> float | None:
        for key in keys:
            raw = data.get(key)
            if isinstance(raw, dict):
                raw = raw.get("value") if raw.get("available", True) else None
            try:
                if raw is not None:
                    return float(raw)
            except (TypeError, ValueError):
                pass
        return None


SmartCarDashboard = ExactReferencePanelsDashboard
