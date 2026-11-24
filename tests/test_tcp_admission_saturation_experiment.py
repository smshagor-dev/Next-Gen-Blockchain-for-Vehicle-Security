"""Loopback-only concurrency and saturation experiment for bounded TCP admission.

This measures the real thread/connection boundary, not V2X detection accuracy.
No network device, ECU, CAN bus or external host is accessed.
"""
import argparse
import json
import socket
import threading
import time
import unittest

from bounded_tcp_admission import BoundedTCPAdmission


def run_trial(capacity=2, excess=4, hold_seconds=0.05):
    if not 1 <= capacity <= 64 or not 1 <= excess <= 256:
        raise ValueError("invalid trial size")
    if not 0.01 <= hold_seconds <= 2:
        raise ValueError("invalid hold time")
    entered = threading.Event()
    release = threading.Event()
    lock = threading.Lock()
    observed = {"entered": 0, "peak": 0, "running": 0}
    def handler(conn):
        with lock:
            observed["entered"] += 1
            observed["running"] += 1
            observed["peak"] = max(observed["peak"], observed["running"])
            if observed["entered"] == capacity:
                entered.set()
        try:
            release.wait(timeout=3)
        finally:
            with lock:
                observed["running"] -= 1

    admission = BoundedTCPAdmission(handler, max_clients=capacity)
    peers = []
    try:
        start = time.perf_counter_ns()
        for _ in range(capacity):
            local, remote = socket.socketpair()
            peers.append(remote)
            assert admission.dispatch(local)
        if not entered.wait(timeout=3):
            raise RuntimeError("workers did not reach capacity")
        rejected = 0
        for _ in range(excess):
            local, remote = socket.socketpair()
            peers.append(remote)
            if not admission.dispatch(local):
                rejected += 1
        elapsed_ns = time.perf_counter_ns() - start
        if admission.active != capacity or rejected != excess:
            raise AssertionError("saturation invariant failed")
        time.sleep(hold_seconds)
        release.set()
        deadline = time.monotonic() + 3
        while admission.active and time.monotonic() < deadline:
            time.sleep(0.001)
        if admission.active:
            raise RuntimeError("workers failed to drain")
        local, remote = socket.socketpair()
        peers.append(remote)
        if not admission.dispatch(local):
            raise AssertionError("slot not restored after drain")
        deadline = time.monotonic() + 3
        while admission.active and time.monotonic() < deadline:
            time.sleep(0.001)
        if admission.active:
            raise RuntimeError("recovery worker failed to drain")
        return {"capacity": capacity, "excess_attempts": excess,
                "rejected_at_saturation": rejected, "peak_handlers": observed["peak"],
                "active_after_drain": admission.active, "rejected_total": admission.rejected,
                "dispatch_elapsed_ns": elapsed_ns, "clock": "perf_counter_ns",
                "scope": "loopback admission only; no authentication, ledger, or physical safety claim"}
    finally:
        release.set()
        for peer in peers:
            peer.close()


class AdmissionSaturationTests(unittest.TestCase):
    def test_saturation_and_recovery(self):
        for capacity in (1, 2, 4):
            with self.subTest(capacity=capacity):
                result = run_trial(capacity=capacity, excess=capacity + 2)
                self.assertEqual(result["peak_handlers"], capacity)
                self.assertEqual(result["rejected_at_saturation"], capacity + 2)
                self.assertEqual(result["active_after_drain"], 0)

    def test_reject_invalid_parameters(self):
        for capacity, excess in ((0, 1), (65, 1), (1, 0), (1, 257)):
            with self.assertRaises(ValueError):
                run_trial(capacity=capacity, excess=excess)

    def test_no_slot_leak_after_handler_exception(self):
        finished = threading.Event()
        def failing_handler(conn):
            try:
                raise RuntimeError("injected failure")
            finally:
                finished.set()
        # Thread exception is intentionally contained by a wrapper to avoid
        # misleading test-runner warnings while exercising cleanup.
        def wrapped(conn):
            try:
                failing_handler(conn)
            except RuntimeError:
                pass
        admission = BoundedTCPAdmission(wrapped, max_clients=1)
        a, b = socket.socketpair()
        try:
            self.assertTrue(admission.dispatch(a))
            self.assertTrue(finished.wait(3))
            deadline = time.monotonic() + 3
            while admission.active and time.monotonic() < deadline:
                time.sleep(0.001)
            self.assertEqual(admission.active, 0)
            c, d = socket.socketpair()
            try:
                self.assertTrue(admission.dispatch(c))
            finally:
                d.close()
        finally:
            b.close()


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--capacity", type=int, default=4)
    parser.add_argument("--excess", type=int, default=16)
    parser.add_argument("--hold-seconds", type=float, default=0.05)
    args = parser.parse_args()
    print(json.dumps(run_trial(args.capacity, args.excess, args.hold_seconds),
                     sort_keys=True))
