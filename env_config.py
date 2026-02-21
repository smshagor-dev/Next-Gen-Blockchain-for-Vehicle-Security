# OmniGuard V2X: A Privacy-Preserving Blockchain Framework for Smart Vehicle Security
# Developer : Md Shahanur Islam Shagor
# Role      : Project Architect & Lead Developer
"""
Minimal .env loader and typed getters for SmartCar project.
No external dependency required.
"""

import os
from pathlib import Path
from typing import Optional

_LOADED = False


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

