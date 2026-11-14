"""Pure deadline guard shared by TCP receive admission and deterministic tests.

These checks complement socket timeouts; they do not replace OS-level
connection limits or independent emergency-stop hardware.
"""


class DeadlineExpired(RuntimeError):
    pass


def deadline_check(now: float, *, session_deadline: float,
                   auth_deadline: float, authenticated: bool) -> None:
    if now >= session_deadline:
        raise DeadlineExpired("HW_SESSION_DEADLINE_EXCEEDED")
    if not authenticated and now >= auth_deadline:
        raise DeadlineExpired("HW_AUTH_DEADLINE_EXCEEDED")
