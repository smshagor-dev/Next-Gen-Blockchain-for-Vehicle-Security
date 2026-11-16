"""Reject stale/future device observations before blockchain mutation.

The device MAC authenticates a timestamp claim, not the physical sensor clock.
Host UTC is an independent *software* reception clock, not trusted time hardware.
No CAN, serial, socket or actuation imports.
"""
from datetime import datetime, timezone
import re

_PATTERN = re.compile(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,6})?(?:Z|\+00:00)\Z")


def verify_observation_age(timestamp: str, *, received_utc: datetime,
                           max_age_seconds: int = 15,
                           max_future_skew_seconds: int = 2) -> float:
    """Return observed age in seconds, or fail closed.

    Caller must obtain received_utc at the host ingress boundary, not from
    sender payload. Both thresholds are bounded policy values, not evidence
    that a sender's wall clock is synchronized or physically attested.
    """
    if (type(max_age_seconds) is not int or not 1 <= max_age_seconds <= 3600 or
            type(max_future_skew_seconds) is not int or
            not 0 <= max_future_skew_seconds <= 60):
        raise ValueError("invalid bounded observation age policy")
    if (type(timestamp) is not str or len(timestamp) > 40 or
            not _PATTERN.fullmatch(timestamp)):
        raise ValueError("noncanonical signed observation timestamp")
    if (not isinstance(received_utc, datetime) or
            received_utc.tzinfo is None or
            received_utc.utcoffset() is None or
            received_utc.utcoffset().total_seconds() != 0):
        raise ValueError("host reception clock must be timezone-aware UTC")
    try:
        observed = datetime.fromisoformat(timestamp.replace("Z", "+00:00"))
        age = (received_utc.astimezone(timezone.utc) - observed).total_seconds()
    except (ValueError, OverflowError) as exc:
        raise ValueError("invalid observation timestamp") from exc
    if age > max_age_seconds:
        raise ValueError("stale signed observation")
    if age < -max_future_skew_seconds:
        raise ValueError("future-dated signed observation")
    return age
