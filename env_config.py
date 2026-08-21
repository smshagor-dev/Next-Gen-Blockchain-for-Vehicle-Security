# OmniGuard V2X: A Privacy-Preserving Blockchain Framework for Smart Vehicle Security
# Developer : Md Shahanur Islam Shagor
# Role      : Project Architect & Lead Developer
"""
Minimal .env loader and typed getters for OmniGuard V2X.

Security properties:
- preserves literal '#' characters inside unquoted secrets;
- only treats '#' as an inline comment when it is preceded by whitespace;
- validates environment variable names before loading them;
- rejects silent defaults for security-sensitive credentials;
- validates secret quality, cross-domain separation, registries, and rotation slots;
- routes sensitive secret access through the configured key-provider boundary;
- provides fail-closed helpers for required secrets.
"""

import logging
import os
import re
import sys
from pathlib import Path
from typing import Optional, Tuple

from credential_policy import (
    credential_policy_metadata,
    insecure_secret_defaults_allowed,
    is_secret_registry,
    is_sensitive_secret,
    validate_rotation_pair,
    validate_secret_registry_json,
    validate_secret_separation,
    validate_secret_value,
)
from key_provider import get_key_provider

_LOADED = False
_PROCESS_LOGGING_READY = False
_PROCESS_KEY_PROVIDER = None
_ENV_KEY_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")


class _TeeStream:
    """Write stream output to both original stream and log file."""

    def __init__(self, original, logfile):
        self._original = original
        self._logfile = logfile

    def write(self, data):
        self._original.write(data)
        self._logfile.write(data)
        return len(data)

    def flush(self):
        self._original.flush()
        self._logfile.flush()

    def isatty(self):
        return self._original.isatty()

    @property
    def encoding(self):
        return getattr(self._original, "encoding", "utf-8")


def _parse_env_value(raw_value: str) -> str:
    """Parse a .env value without truncating literal '#' characters."""
    value = raw_value.strip()
    if not value:
        return ""

    if value[0] in {"'", '"'}:
        quote = value[0]
        escaped = False
        for idx in range(1, len(value)):
            ch = value[idx]
            if quote == '"' and ch == "\\" and not escaped:
                escaped = True
                continue
            if ch == quote and not escaped:
                trailing = value[idx + 1 :].strip()
                if trailing and not trailing.startswith("#"):
                    raise ValueError("unexpected characters after quoted .env value")
                return value[1:idx]
            escaped = False
        raise ValueError("unterminated quoted .env value")

    for idx, ch in enumerate(value):
        if ch == "#" and idx > 0 and value[idx - 1].isspace():
            return value[:idx].rstrip()
    return value


def _parse_env_line(line: str) -> Tuple[Optional[str], Optional[str]]:
    """Parse one .env line into a validated key/value pair."""
    line = line.strip()
    if not line or line.startswith("#") or "=" not in line:
        return None, None

    key, raw_value = line.split("=", 1)
    key = key.strip()
    if not _ENV_KEY_RE.fullmatch(key):
        return None, None

    try:
        value = _parse_env_value(raw_value)
    except ValueError:
        return None, None
    return key, value


def find_project_root(start: Optional[Path] = None) -> Path:
    """Detect project root for flattened SmartCar layout."""
    curr = (start or Path.cwd()).resolve()
    for p in [curr, *curr.parents]:
        if (p / "main.py").exists() and (p / "dashboard.py").exists() and (p / "blockchain.py").exists():
            return p
    return curr


def _safe_process_log_name() -> str:
    """Build safe log file name from current process entrypoint."""
    script = Path(sys.argv[0]).stem if sys.argv and sys.argv[0] else "interactive"
    if not script or script == "-":
        script = "interactive"
    return re.sub(r"[^A-Za-z0-9_.-]", "_", script)


def setup_process_logging():
    """Create per-process log file and route print/log output to it."""
    global _PROCESS_LOGGING_READY
    if _PROCESS_LOGGING_READY:
        return

    root = find_project_root()
    logs_dir = root / "logs" / "processes"
    logs_dir.mkdir(parents=True, exist_ok=True)

    process_name = _safe_process_log_name()
    log_path = logs_dir / f"{process_name}.log"
    fh = open(log_path, mode="a", encoding="utf-8", buffering=1)

    sys.stdout = _TeeStream(sys.stdout, fh)
    sys.stderr = _TeeStream(sys.stderr, fh)
    os.environ.setdefault("SMARTCAR_PROCESS_LOG_FILE", str(log_path))

    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s [%(name)s] %(message)s",
        handlers=[logging.StreamHandler(sys.stdout)],
        force=True,
    )
    logging.getLogger("SmartCar").info("Process log ready: %s", log_path)
    _PROCESS_LOGGING_READY = True


def load_env_file(path: Optional[str] = None, override: bool = False):
    """Load a .env file into the process environment."""
    env_path = Path(path).resolve() if path else (find_project_root() / ".env")
    if not env_path.exists():
        return

    for raw in env_path.read_text(encoding="utf-8").splitlines():
        key, value = _parse_env_line(raw)
        if not key or value is None:
            continue
        if override:
            os.environ[key] = value
        else:
            os.environ.setdefault(key, value)


def load_project_env_once():
    """Load project .env only once per process."""
    global _LOADED
    if _LOADED:
        return
    load_env_file()
    setup_process_logging()
    _LOADED = True


def _process_key_provider():
    """Return the process key-provider singleton without exposing key material."""
    global _PROCESS_KEY_PROVIDER
    if _PROCESS_KEY_PROVIDER is None:
        _PROCESS_KEY_PROVIDER = get_key_provider()
    return _PROCESS_KEY_PROVIDER


def _provider_secret(name: str, purpose: str, min_length: Optional[int] = None) -> str:
    """Resolve one exportable secret through the provider and zeroize its owned buffer."""
    provider = _process_key_provider()
    with provider.export_secret(name, purpose=purpose) as secret:
        value = secret.text_copy()
    if min_length is not None:
        validate_secret_value(name, value, min_length=min_length)
    return value


def get_env(name: str, default: str = "") -> str:
    """Return an env value while refusing unsafe secret fallbacks by default."""
    raw = os.getenv(name)
    if raw is None or (is_sensitive_secret(name) and not raw.strip()):
        if is_sensitive_secret(name) and default:
            if insecure_secret_defaults_allowed():
                return default
            raise RuntimeError(
                f"Sensitive credential {name} must be explicitly configured; "
                "caller-provided fallback was rejected"
            )
        return default

    if is_sensitive_secret(name):
        return _provider_secret(name, purpose="env_config.get_env")
    if is_secret_registry(name):
        validate_secret_registry_json(name, raw)
    return raw


def get_required_env(name: str) -> str:
    """Return a required non-empty environment value or fail closed."""
    value = os.getenv(name)
    if value is None or not value.strip():
        raise RuntimeError(f"Required environment variable {name} is not configured")
    return value.strip()


def get_required_secret(name: str, min_length: int = 32) -> str:
    """Return a required secret through the configured key-provider boundary."""
    return _provider_secret(name, purpose="env_config.get_required_secret", min_length=min_length)


def get_secret_ring(name: str, min_length: Optional[int] = None) -> Tuple[str, ...]:
    """Return current + optional previous secret for rotation-aware verifiers.

    This helper does not automatically make a protocol rotation-aware. Callers
    must deliberately verify against the returned ring and always sign new data
    with ring[0].
    """
    current = get_required_secret(name, min_length=min_length or 32)
    previous_name = name + "_PREVIOUS"
    previous_raw = os.getenv(previous_name)
    previous = None
    if previous_raw is not None and previous_raw.strip():
        previous = _provider_secret(
            previous_name,
            purpose="env_config.get_secret_ring.previous",
            min_length=min_length or 32,
        )
    ring = validate_rotation_pair(name, current, previous)
    if min_length is not None:
        for slot, value in enumerate(ring):
            validate_secret_value(
                name if slot == 0 else previous_name,
                value,
                min_length=min_length,
            )
    return ring


def get_credential_policy_metadata():
    """Return non-secret credential and provider diagnostics."""
    result = credential_policy_metadata()
    try:
        result["key_provider"] = _process_key_provider().metadata()
    except Exception as exc:
        result["key_provider"] = {
            "available": False,
            "error_type": type(exc).__name__,
            "secret_values_exposed": False,
        }
    return result


def get_bool(name: str, default: bool = False) -> bool:
    """Return boolean env value with fallback."""
    raw = os.getenv(name)
    if raw is None:
        return default
    return raw.strip().lower() in {"1", "true", "yes", "on"}


def get_int(name: str, default: int = 0) -> int:
    """Return integer env value with fallback."""
    raw = os.getenv(name)
    if raw is None:
        return default
    try:
        return int(raw)
    except (TypeError, ValueError):
        return default


def get_float(name: str, default: float = 0.0) -> float:
    """Return float env value with fallback."""
    raw = os.getenv(name)
    if raw is None:
        return default
    try:
        return float(raw)
    except (TypeError, ValueError):
        return default
