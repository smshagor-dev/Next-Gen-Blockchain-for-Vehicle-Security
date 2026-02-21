# OmniGuard V2X: A Privacy-Preserving Blockchain Framework for Smart Vehicle Security
# Developer : Md Shahanur Islam Shagor
# Role      : Project Architect & Lead Developer

## Initial Setup

## Prerequisites
- Python 3.10+
- pip
- (Optional) OpenCV runtime for camera features

## Steps
1. Clone/open project.
2. Verify `.env` exists and update key values:
- `SMARTCAR_AUTH_TOKEN`
- `SMARTCAR_OWNER_RECOVERY_KEY`
- `SMARTCAR_STORAGE_ENCRYPTION`
- `SMARTCAR_V2X_HOST`, `SMARTCAR_V2X_PORT`
3. Run:

```bash
python main.py
```

## First Run Check
- GUI opens fullscreen.
- Camera panel initializes (or fallback if camera unavailable).
- Speed meter and telemetry update.
- Access controls respond (`AUTH`, `START`, `STOP`, `LOCK`, `RECOVER`).

## Troubleshooting
- If camera warnings appear, verify webcam index in `.env` (`SMARTCAR_CAMERA_INDEX`).
- If auth fails repeatedly, use owner recovery key flow.
- If chain save fails, check write permission for `logs/`.
