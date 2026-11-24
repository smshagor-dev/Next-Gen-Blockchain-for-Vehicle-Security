"""Non-actuating real-loopback ingress saturation experiment.

Measures admission behavior, NOT V2X attack detection or hardware safety.
Only binds 127.0.0.1 on an ephemeral port; no vehicle commands.
"""
import argparse
import json
import socket
import statistics
import threading
import time

from bounded_tcp_admission import BoundedTCPAdmission


def campaign(*, peers=16, slots=2, hold_seconds=0.12):
    if not 1 <= slots <= 64 or not 1 <= peers <= 1024:
        raise ValueError("invalid peer/slot count")
    if not 0.01 <= hold_seconds <= 5:
        raise ValueError("invalid hold duration")
    entered = threading.Event()
    release = threading.Event()
    lock = threading.Lock()
    started = 0

    def handler(conn):
        nonlocal started
        with lock:
            started += 1
            if started >= slots:
                entered.set()
        release.wait(timeout=5)

    admission = BoundedTCPAdmission(handler, max_clients=slots)
    listener = socket.socket()
    listener.settimeout(3)
    listener.bind(("127.0.0.1", 0))
    listener.listen(peers + slots + 2)
    clients = []
    accepted = 0
    try:
        for _ in range(slots):
            c = socket.create_connection(listener.getsockname(), timeout=2)
            clients.append(c)
            server, _ = listener.accept()
            accepted += int(admission.dispatch(server))
        if not entered.wait(2):
            raise RuntimeError("workers did not occupy all slots")
        latencies_ms = []
        for _ in range(peers):
            c = socket.create_connection(listener.getsockname(), timeout=2)
            clients.append(c)
            server, _ = listener.accept()
            start = time.perf_counter_ns()
            admitted = admission.dispatch(server)
            latencies_ms.append((time.perf_counter_ns() - start) / 1e6)
            if admitted:
                raise AssertionError("saturated admission unexpectedly accepted peer")
        time.sleep(hold_seconds)
        release.set()
        deadline = time.monotonic() + 3
        while admission.active and time.monotonic() < deadline:
            time.sleep(0.002)
        if admission.active:
            raise RuntimeError("workers did not release")
        probe = socket.create_connection(listener.getsockname(), timeout=2)
        clients.append(probe)
        server, _ = listener.accept()
        recovered = admission.dispatch(server)
        if not recovered:
            raise AssertionError("capacity did not recover")
        deadline = time.monotonic() + 3
        while admission.active and time.monotonic() < deadline:
            time.sleep(0.002)
        return {"experiment": "loopback_admission_saturation", "network": "127.0.0.1",
                "slots": slots, "held_connections": accepted, "rejected": admission.rejected,
                "attempted_excess_peers": peers, "recovered": recovered,
                "median_dispatch_ms": statistics.median(latencies_ms),
                "max_dispatch_ms": max(latencies_ms),
                "evidence_scope": "local loopback admission only; no authentication or hardware validation"}
    finally:
        release.set()
        for c in clients:
            c.close()
        listener.close()


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--peers", type=int, default=16)
    parser.add_argument("--slots", type=int, default=2)
    parser.add_argument("--hold-seconds", type=float, default=0.12)
    args = parser.parse_args()
    print(json.dumps(campaign(peers=args.peers, slots=args.slots,
                              hold_seconds=args.hold_seconds), sort_keys=True))
