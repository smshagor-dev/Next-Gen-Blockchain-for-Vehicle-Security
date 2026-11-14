"""Exercise the actual Pi connection handler with real loopback socket I/O.

No physical hardware or ledger consensus is involved. These are engineering
regressions, not publishable independent V2X incident experiments.
"""
import ast
import pathlib
import socket
import threading
import time
import unittest
from datetime import datetime, timezone
from types import SimpleNamespace

import hardware_bridge as bridge
from hardware_transport_security import (
    HardwareEnvelopeVerifier, HardwareTransportError,
    build_authenticated_envelope, encode_authenticated_envelope,
)

ROOT = pathlib.Path(__file__).resolve().parents[1]
SECRET = "integration-test-secret-material-0123456789abcdef"
DEVICE = "test-pi"


def production_handler(verifier, chain, *, auth_timeout=1, byte_limit=4096):
    """Compile the *production* nested handler with controlled dependencies."""
    tree = ast.parse((ROOT / "hardware_bridge.py").read_text(encoding="utf-8-sig"))
    fn = next(n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == "run_pi_mode")
    handler = next(n for n in fn.body if isinstance(n, ast.FunctionDef) and n.name == "handle_client")
    handler = ast.fix_missing_locations(handler)
    code = compile(ast.Module(body=[handler], type_ignores=[]), str(ROOT / "hardware_bridge.py"), "exec")
    class NoActuation:
        def maybe_send_pi(self, *args, **kwargs):
            return None
    scope = dict(
        socket=socket, time=time, HardwareTransportError=HardwareTransportError,
        AuthenticatedPiTelemetrySession=bridge.AuthenticatedPiTelemetrySession,
        deadline_check=bridge.deadline_check, DeadlineExpired=bridge.DeadlineExpired,
        to_telemetry=bridge.to_telemetry,
        verifier=verifier, bc=chain, actuator=NoActuation(),
        verifier_lock=threading.Lock(), ledger_lock=threading.Lock(),
        actuator_lock=threading.Lock(),
        idle_timeout=1, auth_timeout=auth_timeout, max_session_sec=5,
        max_session_bytes=byte_limit, max_frames=64,
        global_budget=bridge.GlobalTelemetryBudget(1000, 1000),
    )
    exec(code, scope)
    return scope["handle_client"]


def signed(nonce):
    from hardware_transport_security import _NUMERIC_RANGES
    payload = {k: (lo + hi) / 2 for k, (lo, hi) in _NUMERIC_RANGES.items()}
    payload.update(event="BENCH_OBSERVATION", timestamp=datetime.now(timezone.utc).isoformat(),
                   emergency_brake_active=False, driver_unwell=False)
    return encode_authenticated_envelope(
        build_authenticated_envelope(DEVICE, SECRET, "TELEMETRY", payload, nonce=nonce)
    )


class RecordingChain:
    def __init__(self):
        self.events = []
        self.lock = threading.Lock()
    def push_telemetry(self, telemetry, event):
        with self.lock:
            self.events.append((telemetry, event))
            return SimpleNamespace(index=len(self.events))


class ProductionPiHandlerLoopbackTests(unittest.TestCase):
    def setUp(self):
        self.chain = RecordingChain()
        self.verifier = HardwareEnvelopeVerifier({DEVICE: SECRET}, replay_cache_entries=128)
        self.handler = production_handler(self.verifier, self.chain)

    def session(self, data, *, fragments=None):
        client, server = socket.socketpair()
        worker = threading.Thread(target=self.handler, args=(server,), daemon=True)
        worker.start()
        try:
            if fragments:
                for fragment in fragments:
                    client.sendall(fragment)
            else:
                client.sendall(data)
            client.shutdown(socket.SHUT_WR)
            worker.join(timeout=3)
            self.assertFalse(worker.is_alive(), "production handler failed to terminate")
        finally:
            client.close()
            server.close()

    def test_fragmented_valid_envelope_mutates_ledger_once(self):
        wire = signed("ab" * 16)
        self.session(wire, fragments=[wire[:7], wire[7:19], wire[19:]])
        self.assertEqual(len(self.chain.events), 1)

    def test_replay_across_parallel_connections_mutates_once(self):
        wire = signed("cd" * 16)
        threads = [threading.Thread(target=self.session, args=(wire,)) for _ in range(12)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(timeout=5)
            self.assertFalse(thread.is_alive())
        self.assertEqual(len(self.chain.events), 1)

    def test_partial_frame_byte_exhaustion_never_mutates(self):
        # No newline, no valid MAC; exceed the per-session byte ceiling.
        self.session(b"x" * 5000)
        self.assertEqual(len(self.chain.events), 0)

    def test_invalid_then_valid_independent_connection_recovers(self):
        self.session(b"invalid-json\\n")
        self.session(signed("ef" * 16))
        self.assertEqual(len(self.chain.events), 1)


if __name__ == "__main__":
    unittest.main()
