"""Socket-driven production dashboard shell.

The active dashboard consumes source-backed state from the authenticated Go live
socket on loopback. The normal UI path is push-based; authenticated HTTP refresh is
kept only as a fail-safe if the live stream is unavailable.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import queue
import socket
import threading
import time
from typing import Any, Dict, Tuple

# Enable the Go live-stream bridge before the inherited dashboard constructs the
# backend process. The Go side still restricts the listener to literal loopback.
os.environ.setdefault("SMARTCAR_GO_ENABLE_LIVE_STREAM", "1")
os.environ.setdefault("SMARTCAR_GO_LIVE_ADDR", "127.0.0.1:8788")

import dashboard_pixel_ui as pixel
import dashboard_reference_ui as reference
from dashboard import DashboardDataProvider
from dashboard_vehicle_art import render_vehicle_hero
from smartcar_backend import BackendBlock


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
    """Use the authenticated Go snapshot cache rather than re-querying metadata."""

    def _metadata(self, method_name: str) -> Dict[str, Any]:
        cache_attr = _CACHE_ATTRS.get(method_name)
        if cache_attr and hasattr(self.backend, cache_attr):
            value = getattr(self.backend, cache_attr, None)
            if isinstance(value, dict):
                return self.datapoint(dict(value), "ok", f"backend.live_cache.{method_name}")
        return super()._metadata(method_name)


class LiveSocketSmartCarDashboard(pixel.PixelMatchedSmartCarDashboard):
    """Premium dashboard with authenticated Go socket snapshots and smooth rendering."""

    LIVE_UI_INTERVAL_MS = 90
    LIVE_RECONNECT_DELAY_SEC = 0.40
    FALLBACK_COLLECT_INTERVAL_SEC = 1.0
    LIVE_PROTOCOL = "smartcar-live-v1"

    def __init__(self) -> None:
        self._live_stop = threading.Event()
        self._live_action_lock = threading.RLock()
        self._live_queue: queue.Queue[Dict[str, Any]] = queue.Queue(maxsize=2)
        self._live_thread = None
        self._live_conn = None
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
        self._start_live_socket_client()

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

    @staticmethod
    def _live_address() -> Tuple[str, int]:
        raw = os.getenv("SMARTCAR_GO_LIVE_ADDR", "127.0.0.1:8788").strip()
        host, sep, port_text = raw.rpartition(":")
        host = host.strip("[]")
        if not sep or host not in {"127.0.0.1", "::1"}:
            raise RuntimeError("SMARTCAR_GO_LIVE_ADDR must be a literal loopback host:port")
        port = int(port_text)
        if port < 1024 or port > 65535:
            raise RuntimeError("SMARTCAR_GO_LIVE_ADDR must use a valid non-privileged port")
        return host, port

    def _start_live_socket_client(self) -> None:
        self._live_thread = threading.Thread(
            target=self._live_socket_loop,
            name="SmartCarDashboardGoLiveSocket",
            daemon=True,
        )
        self._live_thread.start()

    @staticmethod
    def _recv_json_line(conn: socket.socket, buffer: bytes) -> Tuple[Dict[str, Any], bytes]:
        while b"\n" not in buffer:
            chunk = conn.recv(65536)
            if not chunk:
                raise ConnectionError("Go live socket closed")
            buffer += chunk
            if len(buffer) > 16 * 1024 * 1024:
                raise RuntimeError("Go live socket frame exceeded safety limit")
        line, rest = buffer.split(b"\n", 1)
        payload = json.loads(line.decode("utf-8"))
        if not isinstance(payload, dict):
            raise RuntimeError("Go live socket returned a non-object frame")
        return payload, rest

    def _connect_live_socket(self) -> Tuple[socket.socket, bytes]:
        api_secret = getattr(self.blockchain, "api_secret", "")
        if not isinstance(api_secret, str) or len(api_secret) < 32:
            raise RuntimeError("Go live stream requires the configured API secret")
        host, port = self._live_address()
        conn = socket.create_connection((host, port), timeout=2.0)
        conn.settimeout(3.0)
        buffer = b""
        challenge, buffer = self._recv_json_line(conn, buffer)
        if challenge.get("type") != "challenge" or challenge.get("protocol") != self.LIVE_PROTOCOL:
            conn.close()
            raise RuntimeError("Go live stream challenge contract mismatch")
        nonce = str(challenge.get("challenge", ""))
        if len(nonce) < 32:
            conn.close()
            raise RuntimeError("Go live stream challenge is invalid")
        proof = hmac.new(
            api_secret.encode("utf-8"),
            f"{self.LIVE_PROTOCOL}:{nonce}".encode("utf-8"),
            hashlib.sha256,
        ).hexdigest()
        conn.sendall(json.dumps({"type": "auth", "proof": proof}, separators=(",", ":")).encode("utf-8") + b"\n")
        ready, buffer = self._recv_json_line(conn, buffer)
        if ready.get("type") != "ready" or ready.get("protocol") != self.LIVE_PROTOCOL:
            conn.close()
            raise RuntimeError("Go live stream authentication failed")
        conn.settimeout(2.0)
        return conn, buffer

    def _live_socket_loop(self) -> None:
        """Receive authenticated backend status frames; no normal-path HTTP polling."""
        while not self._live_stop.is_set():
            conn = None
            try:
                conn, buffer = self._connect_live_socket()
                self._live_conn = conn
                self._live_socket_connected = True
                self._live_last_error = ""
                while not self._live_stop.is_set():
                    try:
                        message, buffer = self._recv_json_line(conn, buffer)
                    except socket.timeout:
                        continue
                    if message.get("type") != "status":
                        continue
                    status = message.get("data")
                    if not isinstance(status, dict):
                        continue
                    with self._live_action_lock:
                        self._apply_live_status(status)
                        snapshot = self.provider.collect()
                    self._queue_latest_snapshot(snapshot)
            except Exception as exc:
                self._live_socket_connected = False
                self._live_last_error = str(exc)
            finally:
                if conn is not None:
                    try:
                        conn.close()
                    except OSError:
                        pass
                self._live_conn = None
            self._live_stop.wait(self.LIVE_RECONNECT_DELAY_SEC)

    def _queue_latest_snapshot(self, snapshot: Dict[str, Any]) -> None:
        while True:
            try:
                self._live_queue.put_nowait(snapshot)
                return
            except queue.Full:
                try:
                    self._live_queue.get_nowait()
                except queue.Empty:
                    return

    def _drain_live_queue(self) -> Dict[str, Any] | None:
        newest = None
        while True:
            try:
                newest = self._live_queue.get_nowait()
            except queue.Empty:
                return newest

    def _apply_live_status(self, status: Dict[str, Any]) -> None:
        """Apply a socket-delivered /status snapshot using the existing ledger verifier."""
        backend = self.blockchain
        raw_chain = status.get("chain", [])
        if not isinstance(raw_chain, list):
            raise RuntimeError("Go live stream returned a non-list ledger")
        verifier = getattr(backend, "_ledger_verifier", None)
        instance = getattr(backend, "_service_instance", "")
        if verifier is not None:
            verifier.verify_and_track(raw_chain, instance)

        backend.car_unlocked = bool(status.get("car_unlocked", False))
        backend.engine_started = bool(status.get("engine_started", False))
        backend.emergency_brake_active = bool(status.get("emergency_brake_active", False))
        backend.safe_mode_active = bool(status.get("safe_mode_active", False))
        for json_key, cache_attr in (
            ("security_capabilities", "_security_capabilities"),
            ("identity_security", "_identity_security"),
            ("consensus_security", "_consensus_security"),
            ("fl_validation", "_fl_validation"),
            ("adversarial_validation", "_adversarial_validation"),
            ("contribution_boundary", "_contribution_boundary"),
            ("complexity_boundary", "_complexity_boundary"),
            ("pedersen_privacy", "_pedersen_privacy"),
            ("reviewer_audit", "_reviewer_audit"),
        ):
            value = status.get(json_key)
            if isinstance(value, dict):
                setattr(backend, cache_attr, dict(value))

        vehicle_id = str(status.get("vehicle_id", getattr(backend, "vehicle_id", self.VEHICLE_ID)))
        backend.chain = [
            BackendBlock(
                index=int(block.get("index", 0)),
                timestamp=str(block.get("timestamp", "")),
                vehicle_id=str(block.get("vehicle_id", vehicle_id)),
                telemetry=dict(block.get("telemetry") or {}),
                event_data=str(block.get("event_data", "")),
                block_hash=str(block.get("block_hash", "")),
                previous_hash=str(block.get("previous_hash", "")),
                smart_contract_receipts=block.get("smart_contract_receipts") or [],
            )
            for block in raw_chain
            if isinstance(block, dict)
        ]

    def _update_ui(self) -> None:
        """Render socket snapshots continuously; HTTP is used only during stream failure."""
        try:
            self._process_camera()
            snapshot = self._drain_live_queue()
            now = time.monotonic()
            if snapshot is not None:
                self._snapshot = snapshot
                self._render_snapshot(snapshot)
                self._live_last_snapshot_at = now
            elif not self._live_socket_connected and now - self._live_last_snapshot_at >= self.FALLBACK_COLLECT_INTERVAL_SEC:
                with self._live_action_lock:
                    refresh = getattr(self.blockchain, "_refresh", None)
                    if callable(refresh):
                        refresh()
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
        """Compatibility-only fail-safe; the active UI has no refresh button."""
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
            settings["refresh"].configure(text="Socket push • 8788" if self._live_socket_connected else "Automatic fallback")

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
        conn = self._live_conn
        if conn is not None:
            try:
                conn.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            try:
                conn.close()
            except OSError:
                pass
        thread = self._live_thread
        if thread is not None and thread.is_alive():
            thread.join(timeout=0.8)
        super().on_closing()


SmartCarDashboard = LiveSocketSmartCarDashboard
