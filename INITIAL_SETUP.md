# OmniGuard V2X: A Privacy-Preserving Blockchain Framework for Smart Vehicle Security
# Developer : Md Shahanur Islam Shagor
# Role      : Project Architect & Lead Developer

## Initial Setup

## Prerequisites
- Python 3.10+
- pip
- (Optional) Go toolchain or prebuilt Go backend when `SMARTCAR_BACKEND=go`
- (Optional) OpenCV runtime for camera features

## Secure Local First Run

The project uses a fail-closed credential policy. Sensitive credentials no longer accept caller-provided hardcoded fallbacks, so a fresh checkout must have explicit local secrets before `python main.py` starts.

From the project root run:

```bash
python scripts/bootstrap_local_env.py
python main.py
```

`bootstrap_local_env.py` creates or repairs the gitignored `.env` file, generates independent high-entropy credentials for missing security domains, preserves existing non-empty credentials, and never prints secret values.

On PowerShell inside the virtual environment:

```powershell
(.venv) PS> python scripts/bootstrap_local_env.py
(.venv) PS> python main.py
```

Do not commit `.env`. The repository tracks only `.env.example`.

## Existing `.env`

If `.env` already exists but contains blank values such as:

```text
SMARTCAR_AUTH_TOKEN=
SMARTCAR_PASSWORD=
SMARTCAR_VALIDATOR_KEY=
```

run the same bootstrap command. Only missing/blank managed secrets are generated; existing non-empty credentials are preserved.

To intentionally rotate every managed local credential:

```bash
python scripts/bootstrap_local_env.py --rotate-all
```

Use `--rotate-all` only when local persisted state that depends on the old credentials can also be regenerated or migrated.

## Important Security Settings

Normal local development keeps:

```text
SMARTCAR_KEY_PROVIDER=environment
SMARTCAR_REQUIRE_HARDWARE_KEY_PROVIDER=0
SMARTCAR_ALLOW_INSECURE_SECRET_DEFAULTS=0
```

Do not enable `SMARTCAR_ALLOW_INSECURE_SECRET_DEFAULTS=1` as a normal workaround. That flag exists only for explicitly isolated compatibility/lab scenarios and weakens the fail-closed policy.

## First Run Check
- GUI opens successfully after configuration validation.
- Camera panel initializes, or reports its fallback state if no camera is available.
- Speed meter and telemetry update.
- Access controls respond (`AUTH`, `START`, `STOP`, `LOCK`, `RECOVER`).
- Process logs are written under `logs/processes/`.

## Troubleshooting

### `Sensitive credential ... must be explicitly configured`
Run:

```bash
python scripts/bootstrap_local_env.py
```

Then restart `python main.py` so the process reloads `.env`.

### Go backend does not start
The default backend is Go. Ensure Go is installed or a compatible prebuilt backend exists. For an explicitly local Python-only run, configure the supported Python backend mode in `.env` if appropriate for the validation you are performing.

### Camera warnings
Verify the configured webcam index in `.env` (`SMARTCAR_CAMERA_INDEX`).

### Chain save failure
Check write permission for `logs/` and confirm the configured storage credential has not changed unexpectedly.
