"""Fail-closed monotonic deadline guard for authenticated hardware ingress.

This is a software ingress check, not a physical actuator interlock.
"""
import math


class DeadlineExpired(RuntimeError):
    pass


def _finite_clock(value, label):
    if type(value) not in (int, float):
        raise DeadlineExpired(f"HW_INVALID_{label}")
    try:
        finite = math.isfinite(value)
    except (OverflowError, ValueError, TypeError):
        finite = False
    if not finite:
        raise DeadlineExpired(f"HW_INVALID_{label}")


def deadline_check(now: float, *, session_deadline: float,
                   auth_deadline: float, authenticated: bool) -> None:
    """Reject malformed clock samples and expired sessions before admission.

    The caller must use one monotonic clock domain for all three timestamps.
    Invalid clock input fails closed rather than bypassing a comparison (NaN).
    """
    _finite_clock(now, "NOW")
    _finite_clock(session_deadline, "SESSION_DEADLINE")
    _finite_clock(auth_deadline, "AUTH_DEADLINE")
    if type(authenticated) is not bool:
        raise DeadlineExpired("HW_INVALID_AUTH_STATE")
    if auth_deadline > session_deadline:
        raise DeadlineExpired("HW_INVALID_DEADLINE_ORDER")
    if now >= session_deadline:
        raise DeadlineExpired("HW_SESSION_DEADLINE_EXCEEDED")
    if not authenticated and now >= auth_deadline:
        raise DeadlineExpired("HW_AUTH_DEADLINE_EXCEEDED")
