"""Deterministic adversarial validation campaigns for OmniGuard V2X.

The runner is intentionally bounded and repo-local. It does not scan networks,
probe external hosts, or attempt exploitation outside the local protocol/API
contracts. Every randomized campaign is reproducible from an explicit seed.
"""

from __future__ import annotations

import argparse
import copy
import json
import random
import string
import time
from dataclasses import asdict, dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Callable, Dict, Iterable, List, Mapping, Optional

import control_api_security as api_security
import sync_protocol as sync
from ledger_integrity import seal_block_integrity, verify_block_integrity
from permissioned_consensus import ConsensusError, PermissionedConsensusEngine, sign_vote

DEFAULT_SEED = 0x0A11CE27
DEFAULT_ITERATIONS = 192
MAX_FUZZ_TEXT = 16_384
REPORT_VERSION = "OMNIGUARD_ADVERSARIAL_VALIDATION_V1"


@dataclass
class CampaignResult:
    name: str
    seed: int
    iterations: int = 0
    rejected: int = 0
    accepted: int = 0
    unexpected_failures: List[str] = field(default_factory=list)
    duration_ms: float = 0.0

    @property
    def passed(self) -> bool:
        return not self.unexpected_failures


@dataclass
class ValidationReport:
    version: str
    seed: int
    iterations_per_campaign: int
    generated_at: str
    duration_ms: float
    campaigns: List[CampaignResult]

    @property
    def passed(self) -> bool:
        return all(item.passed for item in self.campaigns)

    def to_dict(self) -> Dict[str, object]:
        payload = asdict(self)
        payload["passed"] = self.passed
        payload["summary"] = {
            "campaign_count": len(self.campaigns),
            "unexpected_failure_count": sum(len(c.unexpected_failures) for c in self.campaigns),
            "accepted_cases": sum(c.accepted for c in self.campaigns),
            "rejected_cases": sum(c.rejected for c in self.campaigns),
        }
        return payload


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _random_text(rng: random.Random, max_len: int = 256) -> str:
    alphabet = string.ascii_letters + string.digits + string.punctuation + " \t\r\n"
    length = rng.randint(0, max(0, min(int(max_len), MAX_FUZZ_TEXT)))
    return "".join(rng.choice(alphabet) for _ in range(length))


def _record_unexpected(result: CampaignResult, index: int, exc: Exception) -> None:
    result.unexpected_failures.append(f"case={index} {type(exc).__name__}: {exc}")


def _load_json_corpus(name: str) -> List[object]:
    path = Path(__file__).resolve().parent / "tests" / "security_corpus" / name
    if not path.exists():
        return []
    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, list):
        raise ValueError(f"corpus {name} must contain a JSON array")
    return data


def campaign_sync_parser(seed: int, iterations: int) -> CampaignResult:
    """Exercise malformed JSON, MAC tamper, replay, and type confusion paths."""
    result = CampaignResult("sync_parser", seed)
    rng = random.Random(seed)
    started = time.monotonic()
    session_key = "S" * 48

    corpus = [str(item) for item in _load_json_corpus("sync_malformed.json")]
    corpus.extend([
        "",
        "null",
        "[]",
        "{}",
        '{"type":"PING","payload":{}}',
        "{" + "x" * 1024,
    ])

    for index, raw in enumerate(corpus):
        result.iterations += 1
        try:
            parsed = sync.verify_message(raw, session_key, replay_cache={})
            if parsed is None:
                result.rejected += 1
            else:
                result.accepted += 1
        except Exception as exc:
            _record_unexpected(result, index, exc)

    for offset in range(max(0, int(iterations))):
        index = len(corpus) + offset
        mode = rng.randrange(6)
        try:
            if mode == 0:
                raw = _random_text(rng, 1024)
            elif mode == 1:
                raw = json.dumps({"type": rng.choice([None, 1, [], "PING"]), "payload": _random_text(rng)})
            elif mode == 2:
                raw = sync.create_message(sync.MessageType.PING, {}, session_key).decode()
                parsed = json.loads(raw)
                parsed["mac"] = rng.choice(["", "0" * 64, _random_text(rng, 80)])
                raw = json.dumps(parsed)
            elif mode == 3:
                raw = sync.create_message(sync.MessageType.PING, {}, session_key).decode()
                parsed = json.loads(raw)
                parsed["timestamp"] = (datetime.now(timezone.utc) - timedelta(minutes=10)).isoformat()
                raw = json.dumps(parsed)
            elif mode == 4:
                raw = json.dumps({
                    "type": "PING",
                    "payload": {},
                    "timestamp": _utc_now(),
                    "nonce": _random_text(rng, 15),
                    "mac": "0" * 64,
                })
            else:
                raw = json.dumps({"type": "PING", "payload": {}, "timestamp": _utc_now(), "nonce": "ab" * 16})

            parsed = sync.verify_message(raw[:MAX_FUZZ_TEXT], session_key, replay_cache={})
            if parsed is None:
                result.rejected += 1
            else:
                result.accepted += 1
            result.iterations += 1
        except Exception as exc:
            _record_unexpected(result, index, exc)
            result.iterations += 1

    # Explicit replay invariant: first authenticated message may pass; exact reuse must not.
    try:
        raw = sync.create_message(sync.MessageType.PING, {}, session_key).decode()
        cache: Dict[str, float] = {}
        first = sync.verify_message(raw, session_key, replay_cache=cache)
        second = sync.verify_message(raw, session_key, replay_cache=cache)
        result.iterations += 2
        if first is None or second is not None:
            result.unexpected_failures.append("replay invariant failed")
        else:
            result.accepted += 1
            result.rejected += 1
    except Exception as exc:
        _record_unexpected(result, result.iterations, exc)

    result.duration_ms = round((time.monotonic() - started) * 1000.0, 3)
    return result


def _consensus_keys() -> Dict[str, str]:
    return {
        "VAL1": "v1-" + "A" * 48,
        "VAL2": "v2-" + "B" * 48,
        "VAL3": "v3-" + "C" * 48,
    }


def campaign_permissioned_consensus(seed: int, iterations: int) -> CampaignResult:
    """Mutate signed-vote fields and ensure invalid authority transitions fail closed."""
    result = CampaignResult("permissioned_consensus", seed)
    rng = random.Random(seed)
    started = time.monotonic()
    keys = _consensus_keys()

    for index in range(max(1, int(iterations))):
        engine = PermissionedConsensusEngine(keys, epoch=9, proposal_ttl_sec=30)
        proposal_id = f"P{index}"
        proposal_hash = f"{(index % 15) + 1:x}" * 64
        timestamp = _utc_now()
        voter = rng.choice(sorted(keys))
        vote = bool(rng.getrandbits(1))
        signature = sign_vote(proposal_id, proposal_hash, voter, vote, 9, timestamp, keys[voter])
        payload = {
            "proposal_id": proposal_id,
            "proposal_hash": proposal_hash,
            "voter_id": voter,
            "vote": vote,
            "epoch": 9,
            "proposal_timestamp": timestamp,
            "vote_signature": signature,
        }
        mutation = rng.randrange(8)
        if mutation == 0:
            payload["proposal_hash"] = "0" * 64
        elif mutation == 1:
            payload["epoch"] = 8
        elif mutation == 2:
            payload["voter_id"] = "OUTSIDER"
        elif mutation == 3:
            payload["vote_signature"] = "0" * 64
        elif mutation == 4:
            payload["proposal_timestamp"] = (datetime.now(timezone.utc) - timedelta(minutes=5)).isoformat()
        elif mutation == 5:
            payload["proposal_id"] = "!invalid proposal!"
        elif mutation == 6:
            payload["proposal_hash"] = _random_text(rng, 63)
        else:
            payload["vote_signature"] = _random_text(rng, 63)

        try:
            engine.submit_vote(**payload)
            result.accepted += 1
            result.unexpected_failures.append(f"case={index} mutated consensus vote unexpectedly accepted")
        except ConsensusError:
            result.rejected += 1
        except Exception as exc:
            _record_unexpected(result, index, exc)
        result.iterations += 1

    # Quorum and immutability invariants on a clean proposal.
    try:
        engine = PermissionedConsensusEngine(keys, epoch=9, proposal_ttl_sec=30)
        ts = _utc_now()
        ph = "d" * 64
        first_sig = sign_vote("Q1", ph, "VAL1", True, 9, ts, keys["VAL1"])
        first = engine.submit_vote(
            proposal_id="Q1", proposal_hash=ph, voter_id="VAL1", vote=True,
            epoch=9, proposal_timestamp=ts, vote_signature=first_sig,
        )
        second_sig = sign_vote("Q1", ph, "VAL2", True, 9, ts, keys["VAL2"])
        second = engine.submit_vote(
            proposal_id="Q1", proposal_hash=ph, voter_id="VAL2", vote=True,
            epoch=9, proposal_timestamp=ts, vote_signature=second_sig,
        )
        result.iterations += 2
        if first.get("status") != "PENDING" or second.get("status") != "ACCEPTED":
            result.unexpected_failures.append("full-validator-set quorum invariant failed")
        else:
            result.accepted += 2
        try:
            engine.submit_vote(
                proposal_id="Q1", proposal_hash=ph, voter_id="VAL1", vote=False,
                epoch=9, proposal_timestamp=ts,
                vote_signature=sign_vote("Q1", ph, "VAL1", False, 9, ts, keys["VAL1"]),
            )
            result.unexpected_failures.append("finalized/duplicate vote unexpectedly accepted")
        except ConsensusError:
            result.rejected += 1
            result.iterations += 1
    except Exception as exc:
        _record_unexpected(result, result.iterations, exc)

    result.duration_ms = round((time.monotonic() - started) * 1000.0, 3)
    return result


def _base_ledger_block() -> Dict[str, object]:
    return {
        "index": 0,
        "timestamp": "2026-08-21T00:00:00+00:00",
        "vehicle_id": "VEHICLE-001",
        "previous_hash": "0" * 64,
        "block_hash": "1" * 64,
        "telemetry_hash_sha3": "2" * 64,
        "event_hash_sha3": "3" * 64,
        "event_data": "GENESIS",
        "consensus": "POA",
        "validator_id": "VAL1",
        "authority_round": 0,
        "poa_signature": "4" * 64,
        "privacy_preserving": False,
        "metadata": {"source": "adversarial-corpus", "version": 1},
    }


def campaign_ledger_integrity(seed: int, iterations: int) -> CampaignResult:
    """Apply a deterministic corrupted-ledger corpus plus randomized field mutations."""
    result = CampaignResult("ledger_integrity", seed)
    rng = random.Random(seed)
    started = time.monotonic()
    mac_key = b"ledger-adversarial-mac-key-32-bytes!"
    base = _base_ledger_block()
    seal_block_integrity(base, mac_key)

    corpus = _load_json_corpus("ledger_corruption_cases.json")
    mutations: List[Mapping[str, object]] = [item for item in corpus if isinstance(item, Mapping)]
    for offset in range(max(0, int(iterations))):
        field_name = rng.choice([
            "vehicle_id", "block_hash", "previous_hash", "event_data",
            "validator_id", "authority_round", "privacy_preserving", "metadata",
        ])
        mutations.append({"field": field_name, "value": _random_text(rng, 128)})

    for index, mutation in enumerate(mutations):
        block = copy.deepcopy(base)
        field_name = str(mutation.get("field", ""))
        value = mutation.get("value")
        if field_name == "metadata.nested":
            block.setdefault("metadata", {})["nested"] = value
        else:
            block[field_name] = value
        try:
            if verify_block_integrity(block, mac_key):
                result.accepted += 1
                result.unexpected_failures.append(f"case={index} ledger mutation {field_name!r} retained valid seal")
            else:
                result.rejected += 1
        except Exception as exc:
            _record_unexpected(result, index, exc)
        result.iterations += 1

    try:
        if not verify_block_integrity(base, mac_key):
            result.unexpected_failures.append("untampered sealed ledger block was rejected")
        else:
            result.accepted += 1
        result.iterations += 1
    except Exception as exc:
        _record_unexpected(result, result.iterations, exc)

    result.duration_ms = round((time.monotonic() - started) * 1000.0, 3)
    return result


def campaign_control_api_contract(seed: int, iterations: int) -> CampaignResult:
    """Fuzz loopback URL, nonce, canonical path, and signed-header validation helpers."""
    result = CampaignResult("control_api_contract", seed)
    rng = random.Random(seed)
    started = time.monotonic()
    secret = "control-api-adversarial-secret-" + "K" * 32

    invalid_urls = [
        "https://127.0.0.1:8787",
        "http://example.com:8787",
        "http://127.0.0.1:8787/path",
        "http://user:pass@127.0.0.1:8787",
        "http://127.0.0.1:8787/?q=1",
        "file:///tmp/socket",
        "",
    ]
    for index, candidate in enumerate(invalid_urls):
        try:
            api_security.validate_loopback_base_url(candidate)
            result.accepted += 1
            result.unexpected_failures.append(f"case={index} invalid control URL unexpectedly accepted")
        except ValueError:
            result.rejected += 1
        except Exception as exc:
            _record_unexpected(result, index, exc)
        result.iterations += 1

    for offset in range(max(0, int(iterations))):
        index = len(invalid_urls) + offset
        mode = rng.randrange(4)
        try:
            if mode == 0:
                api_security.build_signed_headers(secret, "POST", "/engine/stop", b"{}", nonce=_random_text(rng, 15))
            elif mode == 1:
                api_security.canonical_api_message("POST", _random_text(rng, 32).lstrip("/"), "1", "ab" * 16, "0" * 64)
            elif mode == 2:
                api_security.build_signed_headers("short", "POST", "/engine/stop", b"{}")
            else:
                api_security.validate_loopback_base_url("http://" + _random_text(rng, 48))
            result.accepted += 1
        except ValueError:
            result.rejected += 1
        except Exception as exc:
            _record_unexpected(result, index, exc)
        result.iterations += 1

    try:
        valid = api_security.validate_loopback_base_url("http://127.0.0.1:8787")
        headers = api_security.build_signed_headers(secret, "POST", "/engine/stop", b"{}", nonce="ab" * 16)
        if valid != "http://127.0.0.1:8787" or len(headers.get("X-SmartCar-Signature", "")) != 64:
            result.unexpected_failures.append("valid loopback signing invariant failed")
        else:
            result.accepted += 1
        result.iterations += 1
    except Exception as exc:
        _record_unexpected(result, result.iterations, exc)

    result.duration_ms = round((time.monotonic() - started) * 1000.0, 3)
    return result


def run_adversarial_validation(
    *,
    seed: int = DEFAULT_SEED,
    iterations: int = DEFAULT_ITERATIONS,
    max_duration_sec: float = 20.0,
) -> ValidationReport:
    """Run all bounded campaigns and return a machine-readable report."""
    started = time.monotonic()
    campaign_fns: Iterable[Callable[[int, int], CampaignResult]] = (
        campaign_sync_parser,
        campaign_permissioned_consensus,
        campaign_ledger_integrity,
        campaign_control_api_contract,
    )
    campaigns: List[CampaignResult] = []
    for offset, fn in enumerate(campaign_fns):
        campaigns.append(fn(int(seed) + offset * 1009, int(iterations)))
        if time.monotonic() - started > float(max_duration_sec):
            campaigns[-1].unexpected_failures.append(
                f"global adversarial validation exceeded {max_duration_sec:.3f}s budget"
            )
            break
    return ValidationReport(
        version=REPORT_VERSION,
        seed=int(seed),
        iterations_per_campaign=int(iterations),
        generated_at=_utc_now(),
        duration_ms=round((time.monotonic() - started) * 1000.0, 3),
        campaigns=campaigns,
    )


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(description="Run bounded OmniGuard adversarial validation")
    parser.add_argument("--seed", type=int, default=DEFAULT_SEED)
    parser.add_argument("--iterations", type=int, default=DEFAULT_ITERATIONS)
    parser.add_argument("--max-duration-sec", type=float, default=20.0)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args(argv)

    report = run_adversarial_validation(
        seed=args.seed,
        iterations=max(1, args.iterations),
        max_duration_sec=max(1.0, args.max_duration_sec),
    )
    payload = report.to_dict()
    text = json.dumps(payload, indent=2, sort_keys=True)
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(text + "\n", encoding="utf-8")
    print(text)
    return 0 if report.passed else 1


if __name__ == "__main__":
    raise SystemExit(main())
