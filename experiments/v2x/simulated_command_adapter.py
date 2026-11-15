"""Simulation-only V2X command boundary. No CAN, serial or vehicle interfaces."""
from dataclasses import dataclass, field, replace
from model_command_authority import State, decide, transition

@dataclass
class MemoryAlertSink:
    alerts: list[str] = field(default_factory=list)
    def emit(self, message: str) -> None:
        self.alerts.append(message)

class SimulationCommandAdapter:
    def __init__(self, sink: MemoryAlertSink):
        if type(sink) is not MemoryAlertSink:
            raise TypeError("only in-memory simulation sinks are supported")
        self._sink = sink
        self._state = State()

    @property
    def state(self) -> State:
        return self._state

    def set_evidence_context(self, *, authenticated: bool, fresh: bool,
                             admitted: bool, network_available: bool) -> None:
        if any(type(v) is not bool for v in (authenticated, fresh, admitted, network_available)):
            raise TypeError("strict boolean context required")
        self._state = replace(self._state, transport_authenticated=authenticated,
                              fresh_nonce=fresh, evidence_admitted=admitted,
                              network_available=network_available)

    def local_emergency(self) -> None:
        self._state = transition(self._state, "local_emergency")

    def local_reset(self, *, locally_authorized: bool) -> None:
        if type(locally_authorized) is not bool:
            raise TypeError("strict local authorization required")
        if locally_authorized:
            self._state = transition(self._state, "authorize_local_reset")
            self._state = transition(self._state, "local_reset")

    def request(self, action: str, message: str):
        if type(message) is not str or len(message.encode("utf-8")) > 4096:
            raise ValueError("bounded text alert required")
        result = decide(self._state, action)
        if result.network_relay:
            self._sink.emit(message)
        return result
