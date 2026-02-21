# OmniGuard V2X: A Privacy-Preserving Blockchain Framework for Smart Vehicle Security
# Developer : Md Shahanur Islam Shagor
# Role      : Project Architect & Lead Developer

## Developer Guide

## Scope
This guide targets engineers working on core modules: blockchain, GUI, V2X network, privacy proofs, and hardware bridge.

## Project Conventions
- Keep files at project root (except `logs/`, `image source/`, `pyc files/`).
- Use environment-driven configuration from `.env`.
- Add short docstrings to public functions/methods.
- Avoid silent exception swallowing; log failures with context.

## Core Modules
- `blockchain.py`: chain, PoA, ZKP integration, anomaly, storage encryption, owner recovery.
- `dashboard.py`: live UI, telemetry loop, camera detection, operator controls.
- `sync_protocol.py`: majority vote and secure sync channel.
- `v2x_protocol.py`: V2V/V2I node and hub transport.

## Security Rules
- Never hardcode production secrets in source.
- Keep `SMARTCAR_OWNER_RECOVERY_KEY` separate from auth token.
- Prefer AES-256-GCM storage mode (install `cryptography`).
- Validate chain integrity before privileged state changes.

## Testing Checklist
- `python -m py_compile *.py` (or per-file loop on Windows)
- `python main.py` GUI start check
- `python multi_car_majority_demo.py`
- `python attacker_fake_zkp.py`
- `python network_overhead_analysis.py`

## Release Checklist
- Update `readme.md` with any behavior/config changes.
- Verify `.env` defaults are safe for demo mode.
- Confirm no debug secrets are committed.
