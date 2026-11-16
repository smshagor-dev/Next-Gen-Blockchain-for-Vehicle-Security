"""Bind signed observation freshness to first completed host receive and elapsed time.

No physical sensor clock attestation. The UTC clock is sampled after recv/read;
monotonic elapsed time prevents queued frames from being refreshed by processing
delay or by backward adjustments of host wall time. Simulation/bench software.
"""
from datetime import datetime, timedelta, timezone
import math
from hardware_observation_freshness import verify_observation_age


def verify_ingress_observation(timestamp, *, received_utc, received_monotonic,
                               commit_monotonic, max_age_seconds=15,
                               max_future_skew_seconds=2):
    """Fail closed if stale at reception OR before mutation.

    The caller MUST sample both host clocks immediately after recv/read, before
    verification or processing. A fragmented frame is timestamped on the read
    that completes it. This is not a trusted hardware receive timestamp.
    """
    if not isinstance(received_utc, datetime) or received_utc.tzinfo is None:
        raise ValueError("invalid host ingress UTC")
    if (type(received_monotonic) not in (int, float) or
            type(commit_monotonic) not in (int, float) or
            not math.isfinite(received_monotonic) or
            not math.isfinite(commit_monotonic) or
            commit_monotonic < received_monotonic):
        raise ValueError("invalid monotonic ingress/commit ordering")
    age_at_ingress = verify_observation_age(
        timestamp, received_utc=received_utc,
        max_age_seconds=max_age_seconds,
        max_future_skew_seconds=max_future_skew_seconds)
    elapsed = commit_monotonic - received_monotonic
    # Bound arithmetic to avoid pathological floats or timedelta overflow.
    if elapsed > 86400:
        raise ValueError("ingress-to-commit delay exceeds maximum")
    derived_commit_utc = received_utc + timedelta(seconds=elapsed)
    age_at_commit = verify_observation_age(
        timestamp, received_utc=derived_commit_utc,
        max_age_seconds=max_age_seconds,
        max_future_skew_seconds=max_future_skew_seconds)
    return {"age_at_ingress_seconds": age_at_ingress,
            "age_at_commit_seconds": age_at_commit,
            "ingress_to_commit_seconds": elapsed}
