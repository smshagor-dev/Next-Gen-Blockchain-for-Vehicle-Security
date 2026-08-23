"""Reference-raster presentation layer for the two Overview visuals.

Only Vehicle Status artwork and the Network Status map artwork are replaced.
The images are exact crops from the user-supplied dashboard reference, bundled
locally as PNG base64 parts under assets/dashboard/reference/. There is no
runtime image generation, network download, or remote hotlink. Live values,
controls, navigation, blockchain state, security semantics, socket transport,
and the four source-backed Network Status metrics remain inherited unchanged.
"""

from __future__ import annotations

import base64
import io
from functools import lru_cache
from pathlib import Path
from typing import Any, Sequence

import tkinter as tk

from dashboard_reference_panels_ui import ExactReferencePanelsDashboard


_ASSET_ROOT = Path(__file__).resolve().parent / "assets" / "dashboard" / "reference"
_VEHICLE_ASSET = "vehicle-status-ref"
_NETWORK_ASSET = "network-status-ref"


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


def _fit_reference(image, width: int, height: int):
    """Scale the exact crop without changing its aspect ratio or artwork."""
    from PIL import Image, ImageOps

    width = max(1, int(width))
    height = max(1, int(height))
    contained = ImageOps.contain(image, (width, height), method=Image.Resampling.LANCZOS)
    out = Image.new("RGBA", (width, height), (3, 11, 24, 255))
    x = (width - contained.width) // 2
    y = (height - contained.height) // 2
    out.alpha_composite(contained, (x, y))
    return out


class RasterReferenceDashboard(ExactReferencePanelsDashboard):
    """Use bundled user-reference PNG crops for the two requested visuals."""

    def __init__(self) -> None:
        self._raster_vehicle_photo = None
        self._raster_vehicle_key = None
        self._raster_network_photo = None
        self._raster_network_key = None
        super().__init__()

    def _draw_vehicle_art(self, canvas: tk.Canvas) -> None:
        """Render the exact supplied Vehicle Status artwork crop."""
        width = max(1, int(canvas.winfo_width() or 1))
        height = max(1, int(canvas.winfo_height() or 1))
        key = (width, height)
        if self._raster_vehicle_photo is not None and key == self._raster_vehicle_key:
            return
        try:
            from PIL import ImageTk

            image = _fit_reference(_load_reference_png(_VEHICLE_ASSET), width, height)
            self._raster_vehicle_photo = ImageTk.PhotoImage(image=image)
            self._raster_vehicle_key = key
            canvas.delete("all")
            canvas.configure(bg="#030b18")
            canvas.create_image(width / 2, height / 2, image=self._raster_vehicle_photo, anchor="center")
        except Exception:
            # Fail visibly through the already-tested local fallback rather than
            # downloading/generating an unreviewed image at runtime.
            super()._draw_vehicle_art(canvas)

    def _draw_peer_map(self, canvas: tk.Canvas, peers: Sequence[Any]) -> None:
        """Render the exact supplied Network Status world-map artwork crop.

        The image is presentation-only. Active Nodes, Avg. Latency, Uptime, and
        Block Height below the map remain source-backed by the inherited live
        renderer. Reference/demo numbers are never copied into those metrics.
        """
        width = max(1, int(canvas.winfo_width() or 1))
        height = max(1, int(canvas.winfo_height() or 1))
        key = (width, height)
        if self._raster_network_photo is not None and key == self._raster_network_key:
            return
        try:
            from PIL import ImageTk

            image = _fit_reference(_load_reference_png(_NETWORK_ASSET), width, height)
            self._raster_network_photo = ImageTk.PhotoImage(image=image)
            self._raster_network_key = key
            canvas.delete("all")
            canvas.configure(bg="#030b18")
            canvas.create_image(width / 2, height / 2, image=self._raster_network_photo, anchor="center")
        except Exception:
            super()._draw_peer_map(canvas, peers)


SmartCarDashboard = RasterReferenceDashboard
