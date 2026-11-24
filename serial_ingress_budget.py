"""Bounded serial ingress accounting for authenticated bench sessions.

No actuator permissions are granted. Local emergency stop stays independent.
"""

class SerialIngressBudgetExceeded(ValueError):
    pass


class SerialIngressBudget:
    def __init__(self, *, max_bytes: int, max_frames: int):
        if type(max_bytes) is not int or not 1024 <= max_bytes <= 8 * 1024 * 1024:
            raise ValueError("max_bytes outside supported bounds")
        if type(max_frames) is not int or not 1 <= max_frames <= 10000:
            raise ValueError("max_frames outside supported bounds")
        self.max_bytes = max_bytes
        self.max_frames = max_frames
        self.bytes_seen = 0
        self.frames_seen = 0

    def charge_bytes(self, count: int) -> None:
        if type(count) is not int or count < 0:
            raise ValueError("invalid byte count")
        if count > self.max_bytes - self.bytes_seen:
            raise SerialIngressBudgetExceeded("HW_SERIAL_BYTE_BUDGET_EXCEEDED")
        self.bytes_seen += count

    def charge_frame(self) -> None:
        if self.frames_seen >= self.max_frames:
            raise SerialIngressBudgetExceeded("HW_SERIAL_FRAME_BUDGET_EXCEEDED")
        self.frames_seen += 1
