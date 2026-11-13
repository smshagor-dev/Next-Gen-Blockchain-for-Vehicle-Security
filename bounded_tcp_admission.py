"""Bounded TCP admission for bench-only ingress.

A slow peer must not consume the accept loop or create an unbounded worker queue.
The caller supplies an authenticated, fail-closed per-connection handler.
No vehicle actuation is performed by this module.
"""
import socket
import threading


class BoundedTCPAdmission:
    def __init__(self, handler, *, max_clients=4):
        if not callable(handler):
            raise TypeError("handler must be callable")
        if type(max_clients) is not int or not 1 <= max_clients <= 64:
            raise ValueError("max_clients must be an integer between 1 and 64")
        self.handler = handler
        self._slots = threading.BoundedSemaphore(max_clients)
        self._lock = threading.Lock()
        self.active = 0
        self.rejected = 0

    def dispatch(self, conn):
        """Takes ownership of conn. Rejects immediately when saturated."""
        if not self._slots.acquire(blocking=False):
            try:
                conn.close()
            finally:
                with self._lock:
                    self.rejected += 1
            return False

        def run():
            try:
                with conn:
                    self.handler(conn)
            finally:
                with self._lock:
                    self.active -= 1
                self._slots.release()

        with self._lock:
            self.active += 1
        try:
            threading.Thread(target=run, daemon=True).start()
        except BaseException:
            with self._lock:
                self.active -= 1
            self._slots.release()
            conn.close()
            raise
        return True


def serve_bounded(listener, handler, *, max_clients=4):
    """Accept forever; handler must implement MAC, replay and deadline checks.

    No unbounded executor queue. Caller owns listener lifecycle.
    """
    admission = BoundedTCPAdmission(handler, max_clients=max_clients)
    while True:
        conn, _ = listener.accept()
        admission.dispatch(conn)
