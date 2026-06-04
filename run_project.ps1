$ErrorActionPreference = "Stop"

$projectRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
$python = Join-Path $projectRoot ".venv\Scripts\python.exe"

if (-not (Test-Path $python)) {
    Write-Host "Virtual environment missing. Creating .venv..."
    python -m venv (Join-Path $projectRoot ".venv")
}

& $python -m pip install -r (Join-Path $projectRoot "requirements.txt")
& $python (Join-Path $projectRoot "main.py")
