"""Bounded local simulation process runner tied to a pre-pinned policy artifact.

The operator controls executable and config; do not run untrusted binaries.
No shell, no remote commands, no CAN/ECU actuation. This receipt is a LOCAL
process observation, not independent execution, sensor or safety attestation.
"""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import json
import os
import signal
from pathlib import Path
import subprocess
import tempfile
import time

if os.name == 'posix':
    import resource

from capture_export_producer import canonical, create_once
from pin_policy_artifacts import sha, verify_pin
from verify_capture_receipt_pair import load_strict_json


def execute_local_simulation(pin: bytes, pinned_sha256: str, manifest: bytes,
                             baseline_executable: bytes, candidate_executable: bytes,
                             baseline_config: bytes, candidate_config: bytes,
                             arm: str, executable_path: Path, config_path: Path,
                             *, timeout_seconds: float = 10.0,
                             max_output_bytes: int = 1048576) -> dict:
    if arm not in ("baseline", "candidate"):
        raise ValueError("unknown trial arm")
    if not (0.1 <= timeout_seconds <= 300):
        raise ValueError("timeout outside permitted simulation bounds")
    if not (1 <= max_output_bytes <= 10485760):
        raise ValueError("output bound outside permitted simulation limits")
    verify_pin(pin, pinned_sha256, manifest, baseline_executable,
               candidate_executable, baseline_config, candidate_config)
    expected_executable = baseline_executable if arm == "baseline" else candidate_executable
    expected_config = baseline_config if arm == "baseline" else candidate_config
    if not executable_path.is_file() or executable_path.is_symlink():
        raise ValueError("simulation executable must be a regular, non-symlink file")
    if not config_path.is_file() or config_path.is_symlink():
        raise ValueError("simulation config must be a regular, non-symlink file")
    if executable_path.read_bytes() != expected_executable or config_path.read_bytes() != expected_config:
        raise ValueError("on-disk policy artifacts differ from externally pinned bytes")
    if not os.access(executable_path, os.X_OK):
        raise ValueError("simulation executable is not executable")
    # Absolute paths, no shell, no user-controlled extra argv.
    command = [str(executable_path.resolve()), str(config_path.resolve())]
    started_utc = datetime.now(timezone.utc).isoformat()
    start = time.monotonic()
    # On POSIX, enforce kernel file-size quotas BEFORE the child executes.
    # This prevents a malicious simulator from filling disk while producing
    # stdout/stderr; post-hoc file size checks alone are not a resource bound.
    def limit_child_output():
        resource.setrlimit(resource.RLIMIT_FSIZE,
                           (max_output_bytes, max_output_bytes))

    with tempfile.TemporaryFile() as stdout, tempfile.TemporaryFile() as stderr:
        process = subprocess.Popen(
            command, stdin=subprocess.DEVNULL, stdout=stdout, stderr=stderr,
            close_fds=True, start_new_session=(os.name == 'posix'),
            preexec_fn=limit_child_output if os.name == 'posix' else None)
        try:
            try:
                process.wait(timeout=timeout_seconds)
            except subprocess.TimeoutExpired as exc:
                # Kill the entire POSIX process group, not just its leader.
                # Otherwise child processes can continue writing after timeout.
                if os.name == 'posix':
                    os.killpg(process.pid, signal.SIGKILL)
                else:
                    process.kill()  # Windows descendants require a Job Object.
                process.wait()
                raise ValueError("simulation timed out; no successful run receipt") from exc
            duration_ms = round((time.monotonic() - start) * 1000, 3)
            stdout_size = os.fstat(stdout.fileno()).st_size
            stderr_size = os.fstat(stderr.fileno()).st_size
            if stdout_size > max_output_bytes or stderr_size > max_output_bytes:
                raise ValueError("simulation exceeded output bound; no successful run receipt")
            if process.returncode != 0:
                # SIGXFSZ is the expected POSIX result when RLIMIT_FSIZE is hit.
                if os.name == 'posix' and (process.returncode == -signal.SIGXFSZ or
                                           stdout_size >= max_output_bytes or
                                           stderr_size >= max_output_bytes):
                    raise ValueError("simulation exceeded output bound; no successful run receipt")
                raise ValueError("simulation exited unsuccessfully; no successful run receipt")
            stdout.seek(0)
            stderr.seek(0)
            stdout_bytes, stderr_bytes = stdout.read(), stderr.read()
        finally:
            if process.poll() is None:
                if os.name == 'posix':
                    os.killpg(process.pid, signal.SIGKILL)
                else:
                    process.kill()
                process.wait()
    # A post-run digest detects changes before/after execution, not races
    # while a mutable executable/config is in use.
    if executable_path.read_bytes() != expected_executable or config_path.read_bytes() != expected_config:
        raise ValueError("policy artifact changed during trial; discard run receipt")
    return {
        "schema_version": 1,
        "arm": arm,
        "policy_name": load_strict_json(manifest)[arm + "_name"],
        "trial_manifest_sha256": sha(manifest),
        "artifact_pin_sha256": pinned_sha256,
        "executable_sha256": sha(expected_executable),
        "config_sha256": sha(expected_config),
        "command": command,
        "process_pid_observed": process.pid,
        "started_utc_local_clock": started_utc,
        "duration_ms_local_clock": duration_ms,
        "returncode": process.returncode,
        "stdout_sha256": sha(stdout_bytes),
        "stderr_sha256": sha(stderr_bytes),
        "stdout_bytes": len(stdout_bytes),
        "stderr_bytes": len(stderr_bytes),
        "publication_ready": False,
        "limitations": [
            "Operator-controlled local simulation process; not independently witnessed.",
            "Pre/post hashes cannot exclude mutable executable race or process substitution.",
            "POSIX child output is kernel-capped; Windows descendants and disk output remain only post-run checked.",
            "No real vehicle/CAN actuation, physical interlock, sensor uptime or policy efficacy verified.",
        ],
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="Bounded local simulation run, not hardware attestation")
    for name in ("pin", "trial-manifest", "baseline-executable",
                 "candidate-executable", "baseline-config", "candidate-config",
                 "executable-path", "config-path", "receipt-out"):
        parser.add_argument("--" + name, type=Path, required=True)
    parser.add_argument("--pinned-sha256", required=True)
    parser.add_argument("--arm", choices=("baseline", "candidate"), required=True)
    parser.add_argument("--timeout-seconds", type=float, default=10)
    parser.add_argument("--max-output-bytes", type=int, default=1048576)
    args = parser.parse_args()
    if args.receipt_out.exists():
        raise FileExistsError("refuse to replace existing execution evidence")
    result = execute_local_simulation(
        args.pin.read_bytes(), args.pinned_sha256, args.trial_manifest.read_bytes(),
        args.baseline_executable.read_bytes(), args.candidate_executable.read_bytes(),
        args.baseline_config.read_bytes(), args.candidate_config.read_bytes(),
        args.arm, args.executable_path, args.config_path,
        timeout_seconds=args.timeout_seconds, max_output_bytes=args.max_output_bytes)
    data = canonical(result)
    create_once(args.receipt_out, data)
    print(json.dumps({"receipt_sha256": sha(data), "publication_ready": False}))


if __name__ == "__main__":
    main()
