# OmniGuard V2X: A Privacy-Preserving Blockchain Framework for Smart Vehicle Security
# Developer : Md Shahanur Islam Shagor
# Role      : Project Architect & Lead Developer

## Initial Setup

## Prerequisites
- Python 3.10+
- pip
- Go toolchain or a compatible prebuilt Go backend when `SMARTCAR_BACKEND=go`
- (Optional) OpenCV runtime for camera features

## Secure Local First Run

The project uses a fail-closed credential policy. Sensitive credentials do not accept caller-provided hardcoded fallbacks, so a fresh checkout must have explicit local secrets before `python main.py` starts.

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

### Important: after `--rotate-all`

`--rotate-all` changes `SMARTCAR_GO_API_SECRET`. If a Go backend from an older run is still listening on `127.0.0.1:8787`, that process still knows the old secret. The new dashboard will correctly reject it with an authenticated-health mismatch.

Before starting `python main.py` after a full credential rotation, make sure an old project-owned Go backend is not still using port `8787`.

On Windows PowerShell:

```powershell
$listener = Get-NetTCPConnection `
    -LocalAddress 127.0.0.1 `
    -LocalPort 8787 `
    -State Listen `
    -ErrorAction SilentlyContinue

if ($listener) {
    Get-CimInstance Win32_Process `
        -Filter "ProcessId=$($listener.OwningProcess)" |
        Select-Object ProcessId, Name, ExecutablePath, CommandLine
}
```

Inspect the output first. Only if the process is clearly this project's `smartcar_go_backend.exe`, `go.exe`/`go-build` backend, or is running from this project path, stop it:

```powershell
Stop-Process -Id $listener.OwningProcess -Force
```

Confirm the port is free:

```powershell
Get-NetTCPConnection `
    -LocalPort 8787 `
    -State Listen `
    -ErrorAction SilentlyContinue
```

No output means there is no listener on the port. Then run:

```powershell
python main.py
```

Never blindly terminate an unknown process just because it owns port `8787`.

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
- The authenticated Go backend becomes healthy on loopback.
- Camera panel initializes, or reports its fallback state if no camera is available.
- Speed meter and telemetry update.
- Access controls respond (`AUTH`, `START`, `STOP`, `LOCK`, `RECOVER`).
- Process logs are written under `logs/processes/`.
- Go backend diagnostics are available in `logs/processes/go-backend.log` when startup fails.

## Troubleshooting

### `Sensitive credential ... must be explicitly configured`

Run:

```bash
python scripts/bootstrap_local_env.py
```

Then restart `python main.py` so the process reloads `.env`.

### `Configured Go backend loopback endpoint is already in use but failed authenticated health`

This usually means port `127.0.0.1:8787` is held by an older local Go backend that was started before the current `SMARTCAR_GO_API_SECRET` was generated or rotated.

On Windows PowerShell, identify the listener:

```powershell
$listener = Get-NetTCPConnection `
    -LocalAddress 127.0.0.1 `
    -LocalPort 8787 `
    -State Listen `
    -ErrorAction SilentlyContinue

if ($listener) {
    Get-CimInstance Win32_Process `
        -Filter "ProcessId=$($listener.OwningProcess)" |
        Select-Object ProcessId, Name, ExecutablePath, CommandLine
}
```

If, and only if, the process is verified as this project's stale Go backend, stop it:

```powershell
Stop-Process -Id $listener.OwningProcess -Force
python main.py
```

If the process is not clearly project-owned, do not kill it. Resolve the port conflict explicitly before retrying.

### `Authenticated Go backend did not become ready`

Check the local backend diagnostic log:

```powershell
Get-Content .\logs\processes\go-backend.log -Tail 100
```

The default startup window is 45 seconds to accommodate cold Windows `go run .` builds. If needed, it can be adjusted within the supported 5-120 second range with `SMARTCAR_GO_STARTUP_TIMEOUT_SEC`.

### Go backend does not start

The default backend is Go. Ensure Go is installed or a compatible prebuilt backend exists. Check:

```powershell
go version
Get-Content .\logs\processes\go-backend.log -Tail 100
```

For an explicitly local Python-only run, configure the supported Python backend mode in `.env` only when appropriate for the validation being performed.

### Camera warnings
Verify the configured webcam index in `.env` (`SMARTCAR_CAMERA_INDEX`).

### Chain save failure
Check write permission for `logs/` and confirm the configured storage credential has not changed unexpectedly.
