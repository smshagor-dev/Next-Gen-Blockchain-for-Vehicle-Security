"""Dependency-free runtime error classification for the local control backend.

Only stable reason codes leave this module. Response bodies, exception text,
credentials, request payloads, and other arbitrary data are never returned.
"""

from __future__ import annotations


BACKEND_RUNTIME_POLICY = "OMNIGUARD_BACKEND_RUNTIME_ERRORS_V1"


def classify_backend_runtime_error(exc: Exception) -> str:
    """Map backend exceptions to a small value-free security reason vocabulary."""
    text = str(exc).upper()
    if "HTTP 401" in text:
        return "CONTROL_API_HTTP_401"
    if "HTTP 403" in text:
        return "CONTROL_API_HTTP_403"
    if "HTTP 409" in text:
        return "CONTROL_API_HTTP_409"
    if "SERVICE PROOF" in text or "SERVICE_PROOF" in text:
        return "SERVICE_PROOF_INVALID"
    if (
        "CONNECTION UNAVAILABLE" in text
        or "URLERROR" in text
        or "TIMEOUT" in text
        or "TIMED OUT" in text
    ):
        return "BACKEND_CONNECTION_UNAVAILABLE"
    return "CONTROL_API_REQUEST_FAILURE"


def backend_runtime_error_metadata() -> dict[str, object]:
    return {
        "policy": BACKEND_RUNTIME_POLICY,
        "stable_reason_codes": [
            "CONTROL_API_HTTP_401",
            "CONTROL_API_HTTP_403",
            "CONTROL_API_HTTP_409",
            "SERVICE_PROOF_INVALID",
            "BACKEND_CONNECTION_UNAVAILABLE",
            "CONTROL_API_REQUEST_FAILURE",
        ],
        "exception_text_exposed": False,
        "response_body_exposed": False,
        "secret_values_exposed": False,
    }
