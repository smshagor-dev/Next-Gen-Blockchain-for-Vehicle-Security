"""Deterministic incident-response validation for OmniGuard V2X.

The harness uses temporary local files only.  It does not open sockets, CAN,
serial devices, GPIO, or external services and does not perform vehicle
actuation.  It validates acknowledgement, recovery, journal, and safety-gate
invariants introduced in v2.9.
"""

from __future__ import annotations

import argparse
import json
import tempfile
import time
from dataclasses import asdict, dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Callable, Dict, List
from unittest.mock import patch

from incident_response import (
    INCIDENT_RESPONSE_VERSION,
    IncidentEvidenceJournal,
    IncidentResponseError,
    IncidentResponseManager,
    build_operator_authorization,
)
from key_provider import EnvironmentKeyProvider
from runtime_security_monitor import RuntimeSecurityMonitor


VALIDATION_VERSION = "OMNIGUARD_INCIDENT_RESPONSE_VALIDATION_V1"
_VALIDATION_ENV = {
    "SMARTCAR_INCIDENT_EVIDENCE_KEY": "validation-evidence-only-" + "E" * 48,
    "SMARTCAR_INCIDENT_OPERATOR_KEY": "validation-operator-only-" + "O" * 48,
}


@dataclass
class IncidentScenarioResult:
    name: str
    passed: bool
    final_state: str
    journal_valid: bool
    journal_entries: int
    expected_reason: str
    external_hardware_touched: bool = False
    external_network_touched: bool = False


@dataclass
class IncidentValidationReport:
    version: str
    incident_response_version: str
    generated_at_epoch: int
    duration_ms: float
    scenarios: List[IncidentScenarioResult]

    @property
    def passed(self) -> bool:
        return all(item.passed for item in self.scenarios)

    def to_dict(self) -> Dict[str, object]:
        return {
            "version": self.version,
            "incident_response_version": self.incident_response_version,
            "generated_at_epoch": self.generated_at_epoch,
            "duration_ms": self.duration_ms,
            "passed": self.passed,
            "scenario_count": len(self.scenarios),
            "external_hardware_touched": False,
            "external_network_touched": False,
            "scenarios": [asdict(item) for item in self.scenarios],
        }


def _stack(directory: str):
    provider = EnvironmentKeyProvider(environ=dict(_VALIDATION_ENV))
    monitor = RuntimeSecurityMonitor(window_sec=5)
    journal = IncidentEvidenceJournal(directory, provider)
    manager = IncidentResponseManager(
        monitor,
        journal,
        provider,
        required_healthy_observations=3,
    )
    return provider, monitor, journal, manager


def _health_window(manager: IncidentResponseManager, count: int = 3) -> None:
    future = datetime.now(timezone.utc) + timedelta(seconds=10)
    with patch("runtime_security_monitor._utc_now", return_value=future):
        for _ in range(count):
            manager.evaluate()


def _scenario(name: str, body: Callable[[str], tuple[bool, str, bool, int, str]]) -> IncidentScenarioResult:
    with tempfile.TemporaryDirectory() as directory:
        passed = False
        state = "ERROR"
        journal_valid = False
        entries = 0
        reason = "UNEXPECTED_FAILURE"
        try:
            passed, state, journal_valid, entries, reason = body(directory)
        except Exception:
            passed = False
        return IncidentScenarioResult(
            name=name,
            passed=bool(passed),
            final_state=str(state),
            journal_valid=bool(journal_valid),
            journal_entries=int(entries),
            expected_reason=str(reason),
        )


def scenario_network_recovery(directory: str):
    provider, monitor, journal, manager = _stack(directory)
    monitor.observe("sync", "REPLAY_DETECTED")
    monitor.observe("sync", "REPLAY_DETECTED")
    opened = manager.evaluate()
    incident_id = str(opened["status"]["incident_id"])
    manager.acknowledge(build_operator_authorization(provider, "ACKNOWLEDGE", incident_id))
    _health_window(manager)
    future = datetime.now(timezone.utc) + timedelta(seconds=10)
    with patch("runtime_security_monitor._utc_now", return_value=future):
        recovered = manager.recover(build_operator_authorization(provider, "RECOVER", incident_id))
    state = str(recovered["status"]["state"])
    return state == "RECOVERED" and journal.verify(), state, journal.verify(), len(journal.entries()), "NETWORK_RECOVERY_GATED"


def scenario_safety_interlock(directory: str):
    provider, monitor, journal, manager = _stack(directory)
    monitor.observe("ledger", "LEDGER_INTEGRITY_FAILURE")
    incident_id = str(manager.evaluate()["status"]["incident_id"])
    manager.acknowledge(build_operator_authorization(provider, "ACKNOWLEDGE", incident_id))
    _health_window(manager)
    blocked = False
    future = datetime.now(timezone.utc) + timedelta(seconds=10)
    with patch("runtime_security_monitor._utc_now", return_value=future):
        try:
            manager.recover(
                build_operator_authorization(provider, "RECOVER", incident_id),
                safety_interlock_confirmed=False,
            )
        except IncidentResponseError as exc:
            blocked = exc.reason == "SAFETY_INTERLOCK_CONFIRMATION_REQUIRED"
        recovered = manager.recover(
            build_operator_authorization(provider, "RECOVER", incident_id),
            safety_interlock_confirmed=True,
        )
    state = str(recovered["status"]["state"])
    return blocked and state == "RECOVERED" and journal.verify(), state, journal.verify(), len(journal.entries()), "SAFETY_INTERLOCK_CONFIRMATION_REQUIRED"


def scenario_forged_operator_action(directory: str):
    provider, monitor, journal, manager = _stack(directory)
    monitor.observe("control_api", "SERVICE_PROOF_INVALID")
    incident_id = str(manager.evaluate()["status"]["incident_id"])
    auth = build_operator_authorization(provider, "ACKNOWLEDGE", incident_id)
    auth["signature"] = "0" * 64
    blocked = False
    try:
        manager.acknowledge(auth)
    except IncidentResponseError as exc:
        blocked = exc.reason == "OPERATOR_SIGNATURE_INVALID"
    state = manager.status.state
    return blocked and state == "OPEN" and journal.verify(), state, journal.verify(), len(journal.entries()), "OPERATOR_SIGNATURE_INVALID"


def scenario_journal_tamper(directory: str):
    provider, monitor, journal, manager = _stack(directory)
    monitor.observe("ledger", "LEDGER_INTEGRITY_FAILURE")
    manager.evaluate()
    path = Path(journal.path)
    entry = json.loads(path.read_text(encoding="utf-8").splitlines()[0])
    entry["decision_action"] = "NONE"
    path.write_text(json.dumps(entry, sort_keys=True) + "\n", encoding="utf-8")
    blocked = False
    try:
        IncidentEvidenceJournal(directory, provider)
    except IncidentResponseError as exc:
        blocked = exc.reason == "EVIDENCE_JOURNAL_INVALID"
    return blocked, "OPEN", False, 1, "EVIDENCE_JOURNAL_INVALID"


def scenario_new_evidence_reopens(directory: str):
    provider, monitor, journal, manager = _stack(directory)
    monitor.observe("ledger", "LEDGER_INTEGRITY_FAILURE")
    incident_id = str(manager.evaluate()["status"]["incident_id"])
    manager.acknowledge(build_operator_authorization(provider, "ACKNOWLEDGE", incident_id))
    monitor.observe("control_api", "SERVICE_PROOF_INVALID")
    updated = manager.evaluate()
    state = str(updated["status"]["state"])
    same_incident = str(updated["status"]["incident_id"]) == incident_id
    return state == "OPEN" and same_incident and journal.verify(), state, journal.verify(), len(journal.entries()), "NEW_EVIDENCE_REQUIRES_REACKNOWLEDGEMENT"


def run_validation() -> IncidentValidationReport:
    started = time.monotonic()
    scenarios = [
        _scenario("network_recovery_gate", scenario_network_recovery),
        _scenario("safety_interlock_gate", scenario_safety_interlock),
        _scenario("forged_operator_action", scenario_forged_operator_action),
        _scenario("persisted_journal_tamper", scenario_journal_tamper),
        _scenario("new_evidence_reopens_incident", scenario_new_evidence_reopens),
    ]
    return IncidentValidationReport(
        version=VALIDATION_VERSION,
        incident_response_version=INCIDENT_RESPONSE_VERSION,
        generated_at_epoch=int(time.time()),
        duration_ms=round((time.monotonic() - started) * 1000.0, 3),
        scenarios=scenarios,
    )


def main() -> int:
    parser = argparse.ArgumentParser(description="Run deterministic incident-response validation")
    parser.add_argument("--output", default="security-reports/incident-response-validation.json")
    args = parser.parse_args()

    report = run_validation()
    output = Path(args.output)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(report.to_dict(), indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(report.to_dict(), sort_keys=True))
    return 0 if report.passed else 1


if __name__ == "__main__":
    raise SystemExit(main())
