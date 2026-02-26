# OmniGuard V2X: A Privacy-Preserving Blockchain Framework for Smart Vehicle Security
# Developer : Md Shahanur Islam Shagor
# Role      : Project Architect & Lead Developer
"""
Minimal .env loader and typed getters for SmartCar project.
No external dependency required.
"""

import os
import re
import sys
import logging
from pathlib import Path
from typing import Optional

_LOADED = False
_PROCESS_LOGGING_READY = False


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


def _strip_quotes(value: str) -> str:
    """Remove symmetric single/double quotes around env value."""
    if len(value) >= 2 and ((value[0] == '"' and value[-1] == '"') or (value[0] == "'" and value[-1] == "'")):
        return value[1:-1]
    return value


def _parse_env_line(line: str):
    """Parse one .env line into key/value."""
    line = line.strip()
    if not line or line.startswith("#"):
        return None, None
    if "=" not in line:
        return None, None
    key, value = line.split("=", 1)
    key = key.strip()
    value = value.strip()
    if "#" in value and not (value.startswith('"') or value.startswith("'")):
        value = value.split("#", 1)[0].strip()
    return key, _strip_quotes(value)


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
    """Load .env into process environment."""
    env_path = Path(path).resolve() if path else (find_project_root() / ".env")
    if not env_path.exists():
        return
    for raw in env_path.read_text(encoding="utf-8").splitlines():
        key, value = _parse_env_line(raw)
        if not key:
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


def get_env(name: str, default: str = "") -> str:
    """Return string env value with fallback."""
    return os.getenv(name, default)


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
    except Exception:
        return default


def get_float(name: str, default: float = 0.0) -> float:
    """Return float env value with fallback."""
    raw = os.getenv(name)
    if raw is None:
        return default
    try:
        return float(raw)
    except Exception:
        return default

