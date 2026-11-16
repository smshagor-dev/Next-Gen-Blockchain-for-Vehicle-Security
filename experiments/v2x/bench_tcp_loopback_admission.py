"""Actual localhost TCP admission saturation experiment, simulation-only.

No blockchain, MAC verification, vehicle network, or physical ECU is involved.
Measures real loopback accept/dispatch, not authenticated end-to-end throughput.
"""
import argparse
import hashlib
import json
import platform
import socket
import statistics
import threading
import time
import tracemalloc
from bounded_tcp_admission import BoundedTCPAdmission


def trial(*, clients=4, overload=100, hold_seconds=0.05, timeout=5.0):
    if type(clients) is not int or not 1 <= clients <= 32:
        raise ValueError("clients must be 1..32")
    if type(overload) is not int or not 1 <= overload <= 10000:
        raise ValueError("overload must be 1..10000")
    if not 0 < hold_seconds <= 2 or not 0 < timeout <= 30:
        raise ValueError("invalid timing bounds")
    release = threading.Event()
    entered = threading.Condition()
    active_handlers = [0]
    peak = [0]
    completed = [0]

    def handler(conn):
        with entered:
            active_handlers[0] += 1
            peak[0] = max(peak[0], active_handlers[0])
            entered.notify_all()
        try:
            release.wait(timeout)
        finally:
            with entered:
                active_handlers[0] -= 1
                completed[0] += 1
                entered.notify_all()

    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind(("127.0.0.1", 0))
    server.listen(clients + 16)
    server.settimeout(timeout)
    admission = BoundedTCPAdmission(handler, max_clients=clients)
    samples = []
    held = []
    tracemalloc.start()
    cpu_start = time.process_time()
    wall_start = time.perf_counter()
    try:
        for _ in range(clients):
            peer = socket.create_connection(server.getsockname(), timeout=timeout)
            held.append(peer)
            conn, _ = server.accept()
            if not admission.dispatch(conn):
                raise AssertionError("failed to fill admission slots")
        with entered:
            if not entered.wait_for(lambda: active_handlers[0] == clients, timeout=timeout):
                raise TimeoutError("workers did not enter before overload")
        for _ in range(overload):
            t0 = time.perf_counter_ns()
            peer = socket.create_connection(server.getsockname(), timeout=timeout)
            try:
                conn, _ = server.accept()
                admitted = admission.dispatch(conn)
                if admitted:
                    raise AssertionError("saturated admission unexpectedly accepted")
            finally:
                peer.close()
            samples.append((time.perf_counter_ns() - t0) / 1e6)
        time.sleep(hold_seconds)
        if peak[0] != clients or admission.active != clients or admission.rejected != overload:
            raise AssertionError("admission capacity invariant violated")
        release.set()
        with entered:
            if not entered.wait_for(lambda: completed[0] == clients, timeout=timeout):
                raise TimeoutError("workers failed to exit")
        # Worker completion counter precedes admission.active decrement;
        # allow bounded time for the semaphore release to finish.
        deadline = time.monotonic() + timeout
        while admission.active and time.monotonic() < deadline:
            time.sleep(0.001)
        if admission.active:
            raise TimeoutError("worker slots not released")
        recovered = socket.create_connection(server.getsockname(), timeout=timeout)
        try:
            conn, _ = server.accept()
            if not admission.dispatch(conn):
                raise AssertionError("admission did not recover after saturation")
        finally:
            recovered.close()
        with entered:
            if not entered.wait_for(lambda: completed[0] == clients + 1, timeout=timeout):
                raise TimeoutError("recovery worker did not complete")
        elapsed = time.perf_counter() - wall_start
        cpu = time.process_time() - cpu_start
        _, peak_bytes = tracemalloc.get_traced_memory()
        return {
            "environment": {"python": platform.python_version(), "platform": platform.platform(),
                            "transport": "IPv4 127.0.0.1 TCP loopback"},
            "max_clients": clients, "overload_attempts": overload,
            "rejected": admission.rejected, "peak_active_handlers": peak[0],
            "recovered_after_release": True,
            "wall_seconds": elapsed, "process_cpu_seconds": cpu,
            "tracemalloc_peak_python_bytes": peak_bytes,
            "overload_attempts_per_second": overload / elapsed,
            "rejection_roundtrip_median_ms": statistics.median(samples),
            "rejection_roundtrip_p95_ms": sorted(samples)[min(len(samples)-1, int(0.95*len(samples)))],
            "limitations": [
                "Localhost TCP accept/dispatch only, not authenticated telemetry or ledger throughput.",
                "Python tracemalloc peak excludes native allocations and total process RSS.",
                "One process, one host, no network impairment or independent physical hardware.",
                "Overload rate includes connection creation and accept; no inference of external DoS resistance."
            ]
        }
    finally:
        release.set()
        for peer in held:
            peer.close()
        server.close()
        tracemalloc.stop()


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--clients", type=int, default=4)
    p.add_argument("--overload", type=int, default=100)
    p.add_argument("--repetitions", type=int, default=5)
    p.add_argument("--output", required=True)
    args = p.parse_args()
    if not 1 <= args.repetitions <= 20:
        p.error("repetitions must be 1..20")
    results = [trial(clients=args.clients, overload=args.overload) for _ in range(args.repetitions)]
    payload = {"schema_version": 1, "publication_ready": False,
               "experimental_class": "local_tcp_admission_microbenchmark",
               "repetitions": results}
    encoded = (json.dumps(payload, sort_keys=True, indent=2, allow_nan=False) + "\n").encode()
    from pathlib import Path
    output = Path(args.output)
    with output.open("xb") as f:
        f.write(encoded)
    print(json.dumps({"output": str(output), "sha256": hashlib.sha256(encoded).hexdigest(),
                      "repetitions": len(results), "publication_ready": False}))


if __name__ == "__main__":
    main()
