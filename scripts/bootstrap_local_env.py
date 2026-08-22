#!/usr/bin/env python3
"""Create or repair a local .env with independent high-entropy credentials.

This helper is intentionally local-development focused:
- it never writes secrets to stdout;
- it preserves every existing non-empty value by default;
- it fills only missing/blank sensitive credentials;
- generated credentials are independent token_urlsafe values;
- .env remains gitignored and is chmod 0600 where supported.

Use --rotate-all only when you explicitly want to replace every managed local
credential (for example after deleting local runtime state that depends on them).
"""

from __future__ import annotations

import argparse
import os
import re
import secrets
from pathlib import Path
from typing import Dict, Iterable, List, Tuple


ROOT = Path(__file__).resolve().parents[1]
TEMPLATE_PATH = ROOT / ".env.example"
DEFAULT_ENV_PATH = ROOT / ".env"
ENV_KEY_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")

# Keep this list aligned with credential_policy.py. These are security domains,
# so each generated value MUST be independent rather than copied/reused.
MANAGED_SECRET_NAMES: Tuple[str, ...] = (
    "SMARTCAR_PASSWORD",
    "SMARTCAR_AUTH_TOKEN",
    "SMARTCAR_VALIDATOR_KEY",
    "SMARTCAR_SYNC_SHARED_KEY",
    "SMARTCAR_V2X_SHARED_SECRET",
    "SMARTCAR_V2X_NODE_SECRET",
    "SMARTCAR_HW_DEVICE_SECRET",
    "SMARTCAR_GO_API_SECRET",
    "SMARTCAR_RECOVERY_KEY",
    "SMARTCAR_OWNER_RECOVERY_KEY",
    "SMARTCAR_STORAGE_PASSPHRASE",
    "SMARTCAR_CPP_DATA_KEY",
    "SMARTCAR_CPP_PQC_KEYSTORE_KEY",
    "SMARTCAR_CPP_PQC_ROLLBACK_KEY",
    "SMARTCAR_FORENSIC_ACCESS_KEY",
    "SMARTCAR_INSURANCE_ACCESS_KEY",
    "SMARTCAR_INCIDENT_EVIDENCE_KEY",
    "SMARTCAR_INCIDENT_OPERATOR_KEY",
)


def _split_assignment(line: str) -> Tuple[str | None, str | None]:
    stripped = line.strip()
    if not stripped or stripped.startswith("#") or "=" not in line:
        return None, None
    key, value = line.split("=", 1)
    key = key.strip()
    if not ENV_KEY_RE.fullmatch(key):
        return None, None
    return key, value.strip()


def _load_base_lines(env_path: Path) -> List[str]:
    if env_path.exists():
        return env_path.read_text(encoding="utf-8").splitlines()
    if not TEMPLATE_PATH.exists():
        raise RuntimeError(f"Missing configuration template: {TEMPLATE_PATH}")
    return TEMPLATE_PATH.read_text(encoding="utf-8").splitlines()


def _current_values(lines: Iterable[str]) -> Dict[str, str]:
    values: Dict[str, str] = {}
    for line in lines:
        key, value = _split_assignment(line)
        if key is not None and value is not None:
            values[key] = value
    return values


def _new_secret() -> str:
    # 48 random bytes => ~64 URL-safe characters, comfortably above the
    # credential policy's 32-character minimum without '#' parsing hazards.
    return secrets.token_urlsafe(48)


def _replace_or_append(
    lines: List[str],
    replacements: Dict[str, str],
) -> List[str]:
    output: List[str] = []
    seen = set()
    for line in lines:
        key, _ = _split_assignment(line)
        if key in replacements:
            output.append(f"{key}={replacements[key]}")
            seen.add(key)
        else:
            output.append(line)

    missing = [name for name in replacements if name not in seen]
    if missing:
        if output and output[-1].strip():
            output.append("")
        output.append("# Generated local-development credentials")
        output.extend(f"{name}={replacements[name]}" for name in missing)
    return output


def bootstrap_local_env(env_path: Path, rotate_all: bool = False) -> Tuple[int, int]:
    lines = _load_base_lines(env_path)
    values = _current_values(lines)
    replacements: Dict[str, str] = {}

    for name in MANAGED_SECRET_NAMES:
        current = values.get(name, "").strip()
        if rotate_all or not current:
            replacements[name] = _new_secret()

    vehicle_id = values.get("SMARTCAR_VEHICLE_ID", "").strip()
    if not vehicle_id:
        replacements["SMARTCAR_VEHICLE_ID"] = "SMARTCAR_LOCAL_DEV_001"

    # Enforce the secure local policy even if an older .env enabled the legacy
    # compatibility bypass. This helper exists specifically to avoid weak defaults.
    replacements["SMARTCAR_ALLOW_INSECURE_SECRET_DEFAULTS"] = "0"

    generated_secret_values = [
        value for key, value in replacements.items() if key in MANAGED_SECRET_NAMES
    ]
    if len(generated_secret_values) != len(set(generated_secret_values)):
        raise RuntimeError("Generated credentials unexpectedly collided; refusing to write .env")

    output = _replace_or_append(lines, replacements)
    env_path.write_text("\n".join(output).rstrip() + "\n", encoding="utf-8")

    try:
        os.chmod(env_path, 0o600)
    except OSError:
        # Windows ACLs do not map cleanly to POSIX mode bits; .gitignore is the
        # primary repository-level protection there.
        pass

    generated_count = sum(1 for name in MANAGED_SECRET_NAMES if name in replacements)
    preserved_count = len(MANAGED_SECRET_NAMES) - generated_count
    return generated_count, preserved_count


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Create/repair a gitignored local .env using independent secure credentials."
    )
    parser.add_argument(
        "--env-file",
        type=Path,
        default=DEFAULT_ENV_PATH,
        help="Target .env path (default: project-root .env)",
    )
    parser.add_argument(
        "--rotate-all",
        action="store_true",
        help="Replace all managed local credentials instead of filling only missing values.",
    )
    args = parser.parse_args()

    env_path = args.env_file.expanduser().resolve()
    generated, preserved = bootstrap_local_env(env_path, rotate_all=args.rotate_all)
    print(f"Local environment ready: {env_path}")
    print(f"Generated/rotated credentials: {generated}; preserved credentials: {preserved}")
    print("Secret values were not printed.")

    if args.rotate_all:
        print("IMPORTANT: --rotate-all changed the Go API credential.")
        print(
            "If a previous SmartCar Go backend is still listening on 127.0.0.1:8787, "
            "stop only the verified project-owned stale backend before starting the dashboard."
        )
        print(
            "If main.py reports an authenticated-health/port-8787 conflict, follow "
            "INITIAL_SETUP.md -> Troubleshooting -> configured Go backend endpoint already in use."
        )

    print("You can now run: python main.py")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
