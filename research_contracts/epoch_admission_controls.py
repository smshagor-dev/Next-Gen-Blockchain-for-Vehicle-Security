"""Non-actuating bounded epoch admission state machine for synthetic V2X controls.

Authentication is a caller-provided verified assertion, not performed here.
This is not an actuator or cryptographic verifier.
"""
from collections import OrderedDict
from dataclasses import dataclass


@dataclass(frozen=True)
class Evidence:
    incident: str
    sender: str
    epoch: int
    nonce: str
    event: str
    verified: bool


class EpochAdmission:
    def __init__(self, *, quorum=2, window=1, max_buckets=128, max_nonces=1024):
        if not (isinstance(quorum, int) and quorum >= 2 and
                isinstance(window, int) and window >= 0 and
                isinstance(max_buckets, int) and max_buckets >= 1 and
                isinstance(max_nonces, int) and max_nonces >= quorum):
            raise ValueError("invalid admission bounds")
        self.quorum, self.window = quorum, window
        self.max_buckets, self.max_nonces = max_buckets, max_nonces
        self.epoch = 0
        self.stopped = False
        self._buckets = OrderedDict()
        self._nonces = set()

    def advance_epoch(self, epoch):
        if not isinstance(epoch, int) or epoch < self.epoch:
            raise ValueError("epoch must be monotonic")
        self.epoch = epoch
        self._buckets.clear()
        self._nonces.clear()

    def local_emergency_stop(self):
        self.stopped = True
        self._buckets.clear()
        self._nonces.clear()

    def local_reset(self, *, operator_confirmed=False):
        if not operator_confirmed:
            return False
        self.stopped = False
        self._buckets.clear()
        self._nonces.clear()
        return True

    def admit(self, evidence):
        if self.stopped or not evidence.verified:
            return False
        if not all(isinstance(v, str) and 0 < len(v) <= 128 for v in
                   (evidence.incident, evidence.sender, evidence.nonce, evidence.event)):
            return False
        if not isinstance(evidence.epoch, int) or not (self.epoch - self.window <= evidence.epoch <= self.epoch):
            return False
        key = (evidence.sender, evidence.epoch, evidence.nonce)
        if key in self._nonces:
            return False
        bucket = (evidence.incident, evidence.epoch, evidence.event)
        if bucket not in self._buckets and len(self._buckets) >= self.max_buckets:
            return False
        if len(self._nonces) >= self.max_nonces:
            return False
        self._nonces.add(key)
        senders = self._buckets.setdefault(bucket, set())
        if evidence.sender in senders:
            return False
        senders.add(evidence.sender)
        return len(senders) >= self.quorum
