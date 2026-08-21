# v2.2 — Authenticated Local Control API Hardening

This increment hardens the Python dashboard <-> Go control backend trust boundary. It removes unauthenticated state-changing HTTP access and makes the local control service fail closed when its identity or request authenticity cannot be verified.

## Security properties

- Go control service binds to loopback only.
- `SMARTCAR_GO_API_SECRET` is required and must be a high-entropy secret of at least 32 characters.
- Python verifies an HMAC challenge-response from `/health` before sending initialization credentials to an already-running service.
- Every non-health API request carries an HMAC-SHA256 signature over method, path, timestamp, nonce, and exact request-body SHA-256.
- Requests outside the replay window are rejected.
- Reused nonces are rejected.
- Request bodies are capped at 1 MiB.
- POST endpoints require JSON content type.
- Unknown JSON fields are rejected for sensitive handlers.
- State-changing endpoints are POST-only.
- `/init` is authenticated and can initialize a process only once. Runtime identity/credential reconfiguration is rejected.
- Chain output is confined to the configured Go data directory; caller-provided parent paths cannot escape it.
- `/save` uses restricted file permissions and a temporary-file replacement flow.
- Malformed emergency-brake requests fail before any state mutation.
- Remote chain reset through `/recovery/unlock` is disabled.
- Recovery uses a dedicated recovery key rather than the vehicle password.
- Server read/write/header/idle timeouts and header-size limits are enforced.
- Python fallback is disabled by default. It must be explicitly enabled with `SMARTCAR_BACKEND_ALLOW_PYTHON_FALLBACK=1` for controlled lab use.

## Service-spoofing defense

Previously, any process that bound `127.0.0.1:8787` and returned HTTP 200 from `/health` could be mistaken for the Go backend and receive initialization credentials.

The Python client now sends a random challenge to `/health`. The service must return:

```text
HMAC-SHA256(SMARTCAR_GO_API_SECRET, "health:" + challenge)
```

If the proof is absent or invalid, Python does not send `/init` credentials.

## Signed request format

Every authenticated request includes:

- `X-SmartCar-Timestamp`
- `X-SmartCar-Nonce`
- `X-SmartCar-Content-SHA256`
- `X-SmartCar-Signature`

The signature covers:

```text
METHOD\nPATH\nTIMESTAMP\nNONCE\nBODY_SHA256
```

using HMAC-SHA256 with `SMARTCAR_GO_API_SECRET`.

## OS/process trust boundary

This layer is designed to stop unauthenticated local HTTP callers and a rogue process that only pre-binds the backend TCP port. It is not a substitute for operating-system privilege separation.

A process running with sufficient privileges under the same account may still be able to inspect process memory, inherited environment variables, or other local resources. Production-oriented follow-up should move long-lived keys into TPM 2.0 / secure-element / OS credential storage and prefer an authenticated local IPC transport with operating-system peer identity where available.

## Go SHA3 portability fix

The previous Go backend imported `crypto/sha3`, which is not available in the declared Go 1.22 toolchain. The backend now contains a compact FIPS 202 SHA3-256 implementation and validates it against the standard `SHA3-256("abc")` test vector in CI. No unpinned Go crypto dependency is introduced.

## Validation

Local validation completed before publication:

- Go control API security tests: **10/10 PASS**
- Python signing/proof helper tests: **4/4 PASS**
- Real-process smoke: authenticated health proof -> signed init -> signed status -> replay rejection: **PASS**

Hosted CI additionally runs the existing security baseline suites, Go formatting, all Go tests, and a Go build.

## Required migration

Generate and configure a new independent API secret:

```bash
python -c "import secrets; print(secrets.token_urlsafe(48))"
```

Set the generated value as `SMARTCAR_GO_API_SECRET` in the local secret store / `.env`. Do not reuse the sync, V2X, validator, authentication, or recovery secret.

## Remaining hardening

This increment does not claim production or vehicle-safety certification. Next priorities are ledger integrity coverage, removal of remaining hard-coded core credential fallbacks, hardware-backed key storage, branch protection/required checks, secret-history purge, fuzzing, and HIL adversarial validation.
