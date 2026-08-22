"""Socket-driven production dashboard shell.

This layer keeps the existing authenticated backend and all security semantics, but
moves the desktop UI to a continuous live-update model. A background collector
refreshes the authenticated Go backend cache and sends source-backed dashboard
snapshots over a local ``socket.socketpair`` to the Tk main thread. The UI therefore
updates continuously without a visible manual-refresh workflow.
"""

from __future__ import annotations

import json
import socket
import threading
import time
from typing import Any, Dict

import dashboard_pixel_ui as pixel
import dashboard_reference_ui as reference
from dashboard import DashboardDataProvider
from dashboard_vehicle_art import render_vehicle_hero


_LIVE_PALETTE = {
    "BG": "#030914",
    "TOPBAR": "#030914",
    "SIDEBAR": "#071326",
    "CARD": "#0a172a",
    "CARD_2": "#0d1d33",
    "CARD_3": "#122744",
    "BORDER": "#17304e",
    "GRID": "#173553",
    "MUTED": "#8297b6",
    "DIM": "#7185a5",
}
for _module in (pixel, reference):
    for _name, _value in _LIVE_PALETTE.items():
        if hasattr(_module, _name):
            setattr(_module, _name, _value)


_CACHE_ATTRS = {
    "security_capabilities": "_security_capabilities",
    "identity_security": "_identity_security",
    "consensus_security": "_consensus_security",
    "fl_validation": "_fl_validation",
    "adversarial_validation": "_adversarial_validation",
    "contribution_boundary": "_contribution_boundary",
    "complexity_boundary": "_complexity_boundary",
    "pedersen_privacy": "_pedersen_privacy",
    "reviewer_audit": "_reviewer_audit",
}


class LiveDashboardDataProvider(DashboardDataProvider):
    """Provider that uses the Go backend's authenticated snapshot cache when present."""

    def _metadata(self, method_name: str) -> Dict[str, Any]:
        cache_attr = _CACHE_ATTRS.get(method_name)
        if cache_attr and hasattr(self.backend, cache_attr):
            value = getattr(self.backend, cache_attr, None)
            if isinstance(value, dict):
                return self.datapoint(dict(value), "ok", f"backend.live_cache.{method_name}")
        return super()._metadata(method_name)


class LiveSocketSmartCarDashboard(pixel.PixelMatchedSmartCarDashboard):
    """Premium dashboard with socket-fed snapshots and cached anti-aliased vehicle art."""

    LIVE_UI_INTERVAL_MS = 90
    LIVE_COLLECT_INTERVAL_SEC = 0.28
    FALLBACK_COLLECT_INTERVAL_SEC = 1.0

    def __init__(self) -> None:
        self._live_stop = threading.Event()
        self._live_action_lock = threading.RLock()
        self._live_socket_rx = None
        self._live_socket_tx = None
        self._live_thread = None
        self._live_buffer = b""
        self._live_socket_connected = False
        self._live_last_snapshot_at = 0.0
        self._live_last_error = ""
        self._vehicle_photo = None
        self._vehicle_photo_key = None
        super().__init__()

        self._strip_manual_refresh_controls()
        self.provider = LiveDashboardDataProvider(self.blockchain, self.VEHICLE_ID)
        try:
            self.provider.set_camera_status(bool(self.cap and self.cap.isOpened()))
        except Exception:
            self.provider.set_camera_status(False, "camera unavailable")
        self._start_live_socket_bridge()

    def _strip_manual_refresh_controls(self) -> None:
        """Remove inherited manual-refresh affordances from the active live shell."""
        page = getattr(self, "_reference_pages", {}).get("settings")
        if page is None:
            return

        def walk(widget):
            for child in list(widget.winfo_children()):
                try:
                    text = str(child.cget("text"))
                except Exception:
                    text = ""
                if text == "Refresh Now":
                    child.destroy()
                    continue
                if text == "Refresh Interval":
                    try:
                        child.configure(text="Live Update")
                    except Exception:
                        pass
                walk(child)

        walk(page)

    # ----------------------------------------------------------- live transport

    def _start_live_socket_bridge(self) -> None:
        """Start a local socket-fed snapshot bridge without touching Tk from a worker."""
        try:
            rx, tx = socket.socketpair()
        except (AttributeError, OSError):
            self._live_socket_connected = False
            return

        rx.setblocking(False)
        tx.settimeout(0.20)
        self._live_socket_rx = rx
        self._live_socket_tx = tx
        self._live_thread = threading.Thread(
            target=self._live_collector_loop,
            name="SmartCarDashboardLiveSocket",
            daemon=True,
        )
        self._live_thread.start()

    def _live_collector_loop(self) -> None:
        """Collect authenticated backend state and deliver JSON snapshots via socket."""
        while not self._live_stop.is_set():
            started = time.monotonic()
            try:
                with self._live_action_lock:
                    refresh = getattr(self.blockchain, "_refresh", None)
                    if callable(refresh):
                        refresh()
                    snapshot = self.provider.collect()

                payload = json.dumps(
                    snapshot,
                    ensure_ascii=False,
                    separators=(",", ":"),
                    default=str,
                ).encode("utf-8") + b"\n"
                tx = self._live_socket_tx
                if tx is None:
                    return
                try:
                    tx.sendall(payload)
                    self._live_socket_connected = True
                    self._live_last_error = ""
                except (socket.timeout, BlockingIOError):
                    pass
            except Exception as exc:
                self._live_socket_connected = False
                self._live_last_error = str(exc)

            elapsed = time.monotonic() - started
            self._live_stop.wait(max(0.03, self.LIVE_COLLECT_INTERVAL_SEC - elapsed))

    def _drain_live_socket(self) -> Dict[str, Any] | None:
        rx = self._live_socket_rx
        if rx is None:
            return None
        newest = None
        while True:
            try:
                chunk = rx.recv(65536)
            except BlockingIOError:
                break
            except OSError:
                self._live_socket_connected = False
                break
            if not chunk:
                self._live_socket_connected = False
                break
            self._live_buffer += chunk

        while b"\n" in self._live_buffer:
            line, self._live_buffer = self._live_buffer.split(b"\n", 1)
            if not line:
                continue
            try:
                decoded = json.loads(line.decode("utf-8"))
            except (UnicodeDecodeError, json.JSONDecodeError):
                continue
            if isinstance(decoded, dict):
                newest = decoded
        return newest

    def _update_ui(self) -> None:
        """Render continuously from socket snapshots; 1 Hz direct collect is fallback only."""
        try:
            self._process_camera()
            snapshot = self._drain_live_socket()
            now = time.monotonic()
            if snapshot is not None:
                self._snapshot = snapshot
                self._render_snapshot(snapshot)
                self._live_last_snapshot_at = now
            elif now - self._live_last_snapshot_at >= self.FALLBACK_COLLECT_INTERVAL_SEC:
                with self._live_action_lock:
                    self._snapshot = self.provider.collect()
                self._render_snapshot(self._snapshot)
                self._live_last_snapshot_at = now
        except Exception as exc:
            now = time.time()
            if now - self._last_ui_error_log_ts > 2.0:
                import logging
                logging.getLogger("SmartCarDashboard").exception("Live dashboard update failed: %s", exc)
                self._last_ui_error_log_ts = now
        self.after(self.LIVE_UI_INTERVAL_MS, self._update_ui)

    def manual_refresh(self) -> None:
        """Compatibility-only immediate frame request; no active UI button calls this."""
        try:
            with self._live_action_lock:
                refresh = getattr(self.blockchain, "_refresh", None)
                if callable(refresh):
                    refresh()
                self._snapshot = self.provider.collect()
            self._render_snapshot(self._snapshot)
            self._live_last_snapshot_at = time.monotonic()
        except Exception:
            pass

    # --------------------------------------------------------------- visuals

    def _draw_vehicle_art(self, canvas) -> None:
        """Render a cached high-resolution metallic sports-car hero instead of wire art."""
        width = max(430, int(canvas.winfo_width() or 430))
        height = max(245, int(canvas.winfo_height() or 245))
        key = (width // 12, height // 12)
        if self._vehicle_photo is not None and self._vehicle_photo_key == key:
            return
        try:
            from PIL import ImageTk

            image = render_vehicle_hero(width, height)
            self._vehicle_photo = ImageTk.PhotoImage(image=image)
            self._vehicle_photo_key = key
            canvas.delete("all")
            canvas.create_image(width / 2, height / 2, image=self._vehicle_photo, anchor="center")
        except Exception:
            self._vehicle_photo = None
            self._vehicle_photo_key = None
            super()._draw_vehicle_art(canvas)

    def _render_snapshot(self, data: Dict[str, Any]) -> None:
        super()._render_snapshot(data)
        if hasattr(self, "backend_value_label"):
            if self._live_socket_connected:
                self.backend_value_label.configure(text="LIVE • SOCKET", fg=pixel.GREEN)
            elif self._live_last_error:
                self.backend_value_label.configure(text="Live fallback", fg=pixel.YELLOW)
        settings = getattr(self, "settings_rows", {})
        if "refresh" in settings:
            settings["refresh"].configure(
                text=(
                    f"Socket • {int(self.LIVE_COLLECT_INTERVAL_SEC * 1000)} ms"
                    if self._live_socket_connected
                    else "Automatic fallback"
                )
            )

    # ------------------------------------------------------------- action lock

    def _do_auth(self):
        with self._live_action_lock:
            return super()._do_auth()

    def _do_start(self):
        with self._live_action_lock:
            return super()._do_start()

    def _do_stop(self):
        with self._live_action_lock:
            return super()._do_stop()

    def _do_lock(self):
        with self._live_action_lock:
            return super()._do_lock()

    def _do_recover(self):
        with self._live_action_lock:
            return super()._do_recover()

    def on_closing(self) -> None:
        self._live_stop.set()
        for sock in (self._live_socket_rx, self._live_socket_tx):
            try:
                if sock is not None:
                    sock.close()
            except OSError:
                pass
        thread = self._live_thread
        if thread is not None and thread.is_alive():
            thread.join(timeout=0.8)
        super().on_closing()


SmartCarDashboard = LiveSocketSmartCarDashboard
