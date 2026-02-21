# OmniGuard V2X: A Privacy-Preserving Blockchain Framework for Smart Vehicle Security
# Developer : Md Shahanur Islam Shagor
# Role      : Project Architect & Lead Developer

## Development Guide

## 1. Setup
1. Install Python 3.10+.
2. (Optional) Install OpenCV dependencies for camera runtime.
3. Configure `.env` values.
4. Start app with:

```bash
python main.py
```

## 2. Daily Workflow
1. Pull latest changes.
2. Update/implement feature.
3. Run compile and smoke tests.
4. Update docs for behavior/config changes.

## 3. Coding Standards
- Use clear names and compact functions.
- Add concise docstrings.
- Preserve backward compatibility for `.env` keys when possible.
- Log exceptions with actionable messages.

## 4. Branching Suggestion
- `feature/<topic>`
- `fix/<topic>`
- `docs/<topic>`

## 5. Validation Commands
```bash
python -m py_compile blockchain.py dashboard.py sync_protocol.py v2x_protocol.py main.py
python main.py
```

## 6. Key Integration Paths
- UI control -> `dashboard.py` -> `blockchain.py` state changes
- Chain event -> logs/ledger widgets -> operator visibility
- V2X data -> verification -> event commit
- Recovery flow -> owner key -> unlock/reset policy
