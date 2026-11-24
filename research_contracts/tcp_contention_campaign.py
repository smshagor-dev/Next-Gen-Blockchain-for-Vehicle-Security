"""Non-actuating socketpair admission contention experiment; not V2X effectiveness evidence."""
import argparse
import json
import socket
import statistics
import threading
import time
from bounded_tcp_admission import BoundedTCPAdmission


def run_trial(*, max_clients=2, attempts=16, hold_ms=100, timeout=3):
    if not (1 <= max_clients <= 64 and attempts >= max_clients and 1 <= hold_ms <= 10000):
        raise ValueError("invalid campaign parameters")
    release = threading.Event()
    entered = threading.Condition()
    active = 0

    def handler(conn):
        nonlocal active
        with entered:
            active += 1
            entered.notify_all()
        release.wait(timeout)

    gate = BoundedTCPAdmission(handler, max_clients=max_clients)
    peers, accepted = [], []
    try:
        for _ in range(max_clients):
            server, client = socket.socketpair()
            peers.append(client)
            accepted.append(gate.dispatch(server))
        with entered:
            if not entered.wait_for(lambda: active == max_clients, timeout=timeout):
                raise RuntimeError("workers did not enter before deadline")
        start = time.perf_counter_ns()
        for _ in range(attempts - max_clients):
            server, client = socket.socketpair()
            peers.append(client)
            accepted.append(gate.dispatch(server))
        rejection_ms = (time.perf_counter_ns() - start) / 1e6
        rejected_at_saturation = gate.rejected
        time.sleep(hold_ms / 1000)
    finally:
        release.set()
        for client in peers:
            client.close()
    deadline = time.monotonic() + timeout
    while gate.active and time.monotonic() < deadline:
        time.sleep(.001)
    if gate.active:
        raise RuntimeError("worker slots not recovered")
    server, client = socket.socketpair()
    try:
        recovered = gate.dispatch(server)
    finally:
        client.close()
        release.set()
    while gate.active and time.monotonic() < deadline:
        time.sleep(.001)
    return {"max_clients": max_clients, "attempts": attempts,
            "initial_accepted": sum(accepted),
            "rejected_at_saturation": rejected_at_saturation,
            "rejection_batch_ms": rejection_ms, "recovered": recovered,
            "slots_released": gate.active == 0}


def campaign(trials=5, **kwargs):
    if not 1 <= trials <= 100:
        raise ValueError("trials must be 1..100")
    observations = [run_trial(**kwargs) for _ in range(trials)]
    durations = [r["rejection_batch_ms"] for r in observations]
    return {"experiment": "local_socket_admission_contention",
            "scope": "non_actuating_controlled_socketpair",
            "trials": observations,
            "median_rejection_batch_ms": statistics.median(durations),
            "min_rejection_batch_ms": min(durations),
            "max_rejection_batch_ms": max(durations),
            "publication_effectiveness_evidence": False}


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--trials", type=int, default=5)
    parser.add_argument("--max-clients", type=int, default=2)
    parser.add_argument("--attempts", type=int, default=16)
    parser.add_argument("--hold-ms", type=int, default=100)
    args = parser.parse_args()
    print(json.dumps(campaign(trials=args.trials, max_clients=args.max_clients,
                              attempts=args.attempts, hold_ms=args.hold_ms), indent=2))
