"""Always-visible reference artwork for the two Overview visuals.

The Vehicle Status and Network Status canvases use the user-supplied reference
artwork bundled locally as PNG base64 parts. The artwork is presentation-only:
all metrics, controls, blockchain state, socket transport, and security semantics
remain inherited from the authenticated live dashboard.

This layer deliberately prevents empty/black presentation areas. Each reference
image is rendered as a sharp contained foreground over a blurred cover of the
same artwork, so every canvas is visually filled without distorting the supplied
reference composition. Network artwork stays visible even when zero V2X peers
are observed; the real metrics below the map remain source-backed.
"""

from __future__ import annotations

import base64
import io
from functools import lru_cache
from pathlib import Path
from typing import Any, Iterable, Sequence

import tkinter as tk

from dashboard_reference_panels_ui import ExactReferencePanelsDashboard
from release_metadata import RELEASE_VERSION
from runtime_security_strength import (
    STRENGTH_DEGRADED,
    STRENGTH_GUARDED,
    STRENGTH_RISK,
    STRENGTH_STRONG,
    evaluate_security_strength,
)


_ASSET_ROOT = Path(__file__).resolve().parent / "assets" / "dashboard" / "reference"
_VEHICLE_ASSET = "vehicle-status-ref"
_NETWORK_ASSET = "network-status-ref"

_RISK_COLORS = {
    "protected": "#24d18b",
    "warning": "#f6c343",
    "risk": "#ff5c6c",
}
_RISK_LABELS = {
    "protected": "PROTECTED",
    "warning": "WARNING",
    "risk": "RISK",
}
_STRENGTH_COLORS = {
    STRENGTH_STRONG: "#24d18b",
    STRENGTH_GUARDED: "#f6c343",
    STRENGTH_DEGRADED: "#f5a524",
    STRENGTH_RISK: "#ff5c6c",
}


@lru_cache(maxsize=4)
def _load_reference_png(stem: str):
    """Decode one bundled PNG from deterministic base64 text parts."""
    from PIL import Image

    parts = sorted(_ASSET_ROOT.glob(f"{stem}.png.b64.*"))
    if not parts:
        raise FileNotFoundError(f"reference asset parts missing: {stem}")
    encoded = "".join(part.read_text(encoding="ascii").strip() for part in parts)
    raw = base64.b64decode(encoded, validate=True)
    if not raw.startswith(b"\x89PNG\r\n\x1a\n"):
        raise ValueError(f"reference asset is not PNG: {stem}")
    image = Image.open(io.BytesIO(raw))
    image.load()
    return image.convert("RGBA")


def _compose_reference(
    image,
    width: int,
    height: int,
    *,
    foreground_brightness: float = 1.0,
    foreground_contrast: float = 1.0,
    foreground_sharpness: float = 1.0,
    foreground_scale: float = 0.96,
):
    """Fill the complete canvas while preserving the exact reference artwork.

    A blurred cover of the same source image fills any aspect-ratio gap. A sharp
    contained copy is then composited in the center. This avoids black sidebars,
    empty map canvases, or stretched artwork.
    """
    from PIL import Image, ImageEnhance, ImageFilter, ImageOps

    width = max(1, int(width))
    height = max(1, int(height))

    cover = ImageOps.fit(image, (width, height), method=Image.Resampling.LANCZOS)
    blur_radius = max(4, int(min(width, height) * 0.028))
    cover = cover.filter(ImageFilter.GaussianBlur(blur_radius))
    cover = ImageEnhance.Brightness(cover).enhance(0.42)
    cover = ImageEnhance.Contrast(cover).enhance(1.08)

    max_w = max(1, int(width * foreground_scale))
    max_h = max(1, int(height * foreground_scale))
    foreground = ImageOps.contain(image, (max_w, max_h), method=Image.Resampling.LANCZOS)
    foreground = ImageEnhance.Brightness(foreground).enhance(foreground_brightness)
    foreground = ImageEnhance.Contrast(foreground).enhance(foreground_contrast)
    foreground = ImageEnhance.Sharpness(foreground).enhance(foreground_sharpness)

    out = cover.convert("RGBA")
    x = (width - foreground.width) // 2
    y = (height - foreground.height) // 2
    out.alpha_composite(foreground, (x, y))
    return out


def _explicit_alert_levels(value: Any) -> Iterable[str]:
    """Extract only explicit alert/risk severity fields from runtime data."""
    if isinstance(value, dict):
        for key in ("severity", "level", "risk"):
            raw = value.get(key)
            if isinstance(raw, str) and raw.strip():
                yield raw.strip().lower()
        for key in ("alerts", "items", "events"):
            if key in value:
                yield from _explicit_alert_levels(value[key])
    elif isinstance(value, (list, tuple)):
        for item in value:
            yield from _explicit_alert_levels(item)


class RasterReferenceDashboard(ExactReferencePanelsDashboard):
    """Keep the two requested visuals filled, clear, and source-truthful."""

    def __init__(self) -> None:
        self._raster_vehicle_photo = None
        self._raster_vehicle_key = None
        self._raster_network_photo = None
        self._raster_network_key = None
        self._vehicle_risk_state = "warning"
        super().__init__()
        self._apply_v4_security_labels(self)

    def _apply_v4_security_labels(self, widget: tk.Widget) -> None:
        """Replace legacy score/status copy without changing the inherited layout."""
        for child in widget.winfo_children():
            if isinstance(child, tk.Label):
                try:
                    text = str(child.cget("text"))
                except Exception:
                    text = ""
                if text == "Security Score":
                    child.configure(text="Security Strength")
                elif text == "System Status":
                    child.configure(text="Security Strength")
                elif text == "v3.0.3":
                    child.configure(text=f"v{RELEASE_VERSION}")
            self._apply_v4_security_labels(child)

    # ---------------------------------------------------------------- vehicle

    def _draw_vehicle_art(self, canvas: tk.Canvas) -> None:
        """Render clear reference car art without black/empty aspect-ratio bars."""
        width = max(1, int(canvas.winfo_width() or 1))
        height = max(1, int(canvas.winfo_height() or 1))
        key = (width, height, self._vehicle_risk_state)
        if self._raster_vehicle_photo is not None and key == self._raster_vehicle_key:
            return

        try:
            from PIL import ImageTk

            image = _compose_reference(
                _load_reference_png(_VEHICLE_ASSET),
                width,
                height,
                foreground_brightness=1.12,
                foreground_contrast=1.08,
                foreground_sharpness=1.35,
                foreground_scale=0.97,
            )
            self._raster_vehicle_photo = ImageTk.PhotoImage(image=image)
            self._raster_vehicle_key = key

            canvas.delete("all")
            canvas.configure(bg="#030b18", highlightthickness=0, bd=0)
            canvas.create_image(
                width / 2,
                height / 2,
                image=self._raster_vehicle_photo,
                anchor="center",
            )
            self._draw_risk_badge(canvas, width)
        except Exception:
            super()._draw_vehicle_art(canvas)

    def _draw_risk_badge(self, canvas: tk.Canvas, width: int) -> None:
        state = self._vehicle_risk_state
        color = _RISK_COLORS.get(state, _RISK_COLORS["warning"])
        label = _RISK_LABELS.get(state, _RISK_LABELS["warning"])

        right = max(86, width - 14)
        left = right - 112
        top = 12
        bottom = 44
        canvas.create_rectangle(
            left,
            top,
            right,
            bottom,
            fill="#071426",
            outline="#163250",
            width=1,
            tags=("risk_badge",),
        )
        canvas.create_oval(
            left + 10,
            top + 9,
            left + 24,
            top + 23,
            fill=color,
            outline=color,
            tags=("risk_badge",),
        )
        canvas.create_text(
            left + 32,
            (top + bottom) / 2,
            text=label,
            fill=color,
            font=("Segoe UI", 9, "bold"),
            anchor="w",
            tags=("risk_badge",),
        )

    # ---------------------------------------------------------------- network

    def _draw_peer_map(self, canvas: tk.Canvas, peers: Sequence[Any]) -> None:
        """Always render the supplied world-map background, even with zero peers."""
        width = max(1, int(canvas.winfo_width() or 1))
        height = max(1, int(canvas.winfo_height() or 1))
        peer_count = len(peers) if peers else 0
        key = (width, height, peer_count)
        if self._raster_network_photo is not None and key == self._raster_network_key:
            return

        try:
            from PIL import ImageTk

            image = _compose_reference(
                _load_reference_png(_NETWORK_ASSET),
                width,
                height,
                foreground_brightness=1.72,
                foreground_contrast=1.28,
                foreground_sharpness=1.40,
                foreground_scale=0.95,
            )
            self._raster_network_photo = ImageTk.PhotoImage(image=image)
            self._raster_network_key = key

            canvas.delete("all")
            canvas.configure(bg="#030b18", highlightthickness=0, bd=0)
            canvas.create_image(
                width / 2,
                height / 2,
                image=self._raster_network_photo,
                anchor="center",
            )

            status = (
                f"{peer_count} observed V2X peer{'s' if peer_count != 1 else ''}"
                if peer_count
                else "No observed V2X peers"
            )
            canvas.create_rectangle(
                12,
                height - 32,
                166,
                height - 10,
                fill="#071426",
                outline="#163250",
                width=1,
            )
            canvas.create_text(
                20,
                height - 21,
                text=status,
                fill="#8fa6c6",
                font=("Segoe UI", 8),
                anchor="w",
            )
        except Exception:
            super()._draw_peer_map(canvas, peers)

    # --------------------------------------------------------------- live risk

    def _derive_vehicle_risk_state(self, data: dict[str, Any]) -> str:
        strength = evaluate_security_strength(data)
        return {
            STRENGTH_STRONG: "protected",
            STRENGTH_GUARDED: "warning",
            STRENGTH_DEGRADED: "warning",
            STRENGTH_RISK: "risk",
        }.get(strength["level"], "warning")

    def _render_snapshot(self, data: dict[str, Any]) -> None:
        strength = evaluate_security_strength(data)
        new_risk = self._derive_vehicle_risk_state(data)
        if new_risk != self._vehicle_risk_state:
            self._vehicle_risk_state = new_risk
            self._raster_vehicle_key = None

        super()._render_snapshot(data)

        level = str(strength["level"])
        color = _STRENGTH_COLORS.get(level, _STRENGTH_COLORS[STRENGTH_DEGRADED])
        if hasattr(self, "dashboard_metrics") and "security" in self.dashboard_metrics:
            self.dashboard_metrics["security"]["value"].configure(text=level, fg=color)
            self.dashboard_metrics["security"]["note"].configure(text="source-backed runtime posture")
        if hasattr(self, "system_status_icon"):
            self.system_status_icon.configure(fg=color)
        if hasattr(self, "system_status_label"):
            self.system_status_label.configure(text=level, fg=color)


SmartCarDashboard = RasterReferenceDashboard
