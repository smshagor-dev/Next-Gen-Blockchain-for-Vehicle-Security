"""Deterministic software-HIL security scenarios for OmniGuard V2X.

This harness never opens CAN, serial, or non-loopback network interfaces. It
validates runtime detection and fail-safe decision policy in a simulated safety
controller so the scenarios are reproducible in CI and on developer machines.
"""

from __future__ import annotations

import argparse
import json
import time
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Dict, List

from runtime_security_monitor import RuntimeSecurityDecision, RuntimeSecurityMonitor


HIL_VALIDATION_VERSION = "OMNIGUARD_SOFTWARE_HIL_SECURITY_V1"


@dataclass
class SimulatedSafetyController:
    network_isolated: bool = False
    safe_mode_requested: bool = False
    stop_command_count: int = 0

    def apply(self, decision: RuntimeSecurityDecision) -> None:
        if decision.recommended_action == "ISOLATE_NETWORK":
            self.network_isolated = True
        elif decision.recommended_action == "SAFE_MODE_REQUEST":
            self.network_isolated = True
            if not self.safe_mode_requested:
                self.stop_command_count += 1
            self.safe_mode_requested = True


@dataclass
class HILScenarioResult:
    name: str
    passed: bool
    final_incident_level: str
    final_action: str
    event_count: int
    network_isolated: bool
    safe_mode_requested: bool
    stop_command_count: int
    evidence_chain_valid: bool
    notes: str


@dataclass
class HILValidationReport:
    version: str
    generated_at_epoch: int
    duration_ms: float
    scenarios: List[HILScenarioResult]
    external_hardware_touched: bool = False
    external_network_touched: bool = False

    @property
    def passed(self) -> bool:
        return all(item.passed for item in self.scenarios)

    def to_dict(self) -> Dict[str, object]:
        return {
            "version": self.version,
            "generated_at_epoch": self.generated_at_epoch,
            "duration_ms": self.duration_ms,
            "passed": self.passed,
            "external_hardware_touched": self.external_hardware_touched,
            "external_network_touched": self.external_network_touched,
            "scenario_count": len(self.scenarios),
            "scenarios": [asdict(item) for item in self.scenarios],
        }


def _result(
    name: str,
    monitor: RuntimeSecurityMonitor,
    controller: SimulatedSafetyController,
    *,
    expected_action: str,
    expected_safe_mode: bool,
    notes: str,
) -> HILScenarioResult:
    metadata = monitor.metadata()
    decision = metadata["last_decision"]
    passed = (
        decision["recommended_action"] == expected_action
        and controller.safe_mode_requested is expected_safe_mode
        and monitor.verify_evidence_chain()
    )
    if expected_action in {"ISOLATE_NETWORK", "SAFE_MODE_REQUEST"}:
        passed = passed and controller.network_isolated
    if expected_action == "NONE":
        passed = passed and not controller.network_isolated
    return HILScenarioResult(
        name=name,
        passed=passed,
        final_incident_level=str(decision["incident_level"]),
        final_action=str(decision["recommended_action"]),
        event_count=int(metadata["retained_events"]),
        network_isolated=controller.network_isolated,
        safe_mode_requested=controller.safe_mode_requested,
        stop_command_count=controller.stop_command_count,
        evidence_chain_valid=monitor.verify_evidence_chain(),
        notes=notes,
    )


def scenario_clean_baseline() -> HILScenarioResult:
    monitor = RuntimeSecurityMonitor()
    controller = SimulatedSafetyController()
    return _result(
        "clean_baseline",
        monitor,
        controller,
        expected_action="NONE",
        expected_safe_mode=False,
        notes="No security event must not trigger containment or a stop command.",
    )


def scenario_replay_burst() -> HILScenarioResult:
    monitor = RuntimeSecurityMonitor()
    controller = SimulatedSafetyController()
    for _ in range(2):
        decision = monitor.observe("sync", "REPLAY_DETECTED", subject="vehicle-001")
        controller.apply(decision)
    return _result(
        "replay_burst",
        monitor,
        controller,
        expected_action="ISOLATE_NETWORK",
        expected_safe_mode=False,
        notes="Repeated replay activity isolates network trust without commanding a vehicle stop.",
    )


def scenario_cross_layer_auth_attack() -> HILScenarioResult:
    monitor = RuntimeSecurityMonitor()
    controller = SimulatedSafetyController()
    events = [
        ("sync", "INVALID_MESSAGE_MAC"),
        ("consensus", "INVALID_VOTE_SIGNATURE"),
    ]
    for source, reason in events:
        decision = monitor.observe(source, reason, subject="vehicle-002")
        controller.apply(decision)
    return _result(
        "cross_layer_auth_attack",
        monitor,
        controller,
        expected_action="ISOLATE_NETWORK",
        expected_safe_mode=False,
        notes="Correlated authentication/consensus failures cross the containment threshold.",
    )


def scenario_ledger_tamper() -> HILScenarioResult:
    monitor = RuntimeSecurityMonitor()
    controller = SimulatedSafetyController()
    controller.apply(monitor.observe("ledger", "LEDGER_INTEGRITY_FAILURE", subject="vehicle-003"))
    return _result(
        "ledger_tamper",
        monitor,
        controller,
        expected_action="SAFE_MODE_REQUEST",
        expected_safe_mode=True,
        notes="A ledger-integrity failure is safety-critical and requests safe mode exactly once.",
    )


def scenario_service_spoof() -> HILScenarioResult:
    monitor = RuntimeSecurityMonitor()
    controller = SimulatedSafetyController()
    controller.apply(monitor.observe("control_api", "SERVICE_PROOF_INVALID", subject="vehicle-004"))
    return _result(
        "authenticated_service_spoof",
        monitor,
        controller,
        expected_action="SAFE_MODE_REQUEST",
        expected_safe_mode=True,
        notes="Authenticated-service proof failure is treated as a control-plane authenticity compromise.",
    )


def scenario_sensor_integrity_attack() -> HILScenarioResult:
    monitor = RuntimeSecurityMonitor()
    controller = SimulatedSafetyController()
    controller.apply(monitor.observe("hardware", "TELEMETRY_INTEGRITY_FAILURE", subject="sensor-node-01"))
    return _result(
        "sensor_integrity_attack",
        monitor,
        controller,
        expected_action="SAFE_MODE_REQUEST",
        expected_safe_mode=True,
        notes="Telemetry-integrity compromise requests safe mode without contacting real hardware.",
    )


def run_validation() -> HILValidationReport:
    started = time.monotonic()
    scenarios = [
        scenario_clean_baseline(),
        scenario_replay_burst(),
        scenario_cross_layer_auth_attack(),
        scenario_ledger_tamper(),
        scenario_service_spoof(),
        scenario_sensor_integrity_attack(),
    ]
    return HILValidationReport(
        version=HIL_VALIDATION_VERSION,
        generated_at_epoch=int(time.time()),
        duration_ms=round((time.monotonic() - started) * 1000.0, 3),
        scenarios=scenarios,
    )


def main() -> int:
    parser = argparse.ArgumentParser(description="Run bounded software-HIL security validation")
    parser.add_argument("--output", default="security-reports/hil-security-validation.json")
    args = parser.parse_args()

    report = run_validation()
    output = Path(args.output)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(report.to_dict(), indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(report.to_dict(), sort_keys=True))
    return 0 if report.passed else 1


if __name__ == "__main__":
    raise SystemExit(main())
