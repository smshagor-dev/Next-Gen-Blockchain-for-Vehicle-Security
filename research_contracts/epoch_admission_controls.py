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
        self._admitted = set()

    def advance_epoch(self, epoch):
        if type(epoch) is not int or epoch < self.epoch:
            raise ValueError("epoch must be monotonic")
        if epoch == self.epoch:
            return  # Idempotent epoch announcement must not erase replay history.
        self.epoch = epoch
        # Retain replay pins for epochs still admissible within the window.
        # Clearing them here would allow an old signed observation to be
        # replayed immediately after an epoch transition.
        earliest = epoch - self.window
        self._buckets = OrderedDict(
            (key, senders) for key, senders in self._buckets.items()
            if key[1] >= earliest
        )
        self._nonces = {key for key in self._nonces if key[1] >= earliest}
        self._admitted = {key for key in self._admitted if key[1] >= earliest}

    def local_emergency_stop(self):
        self.stopped = True
        # Preserve authenticated replay pins and one-shot decisions across
        # emergency stops. Resetting them would resurrect signed old evidence.

    def local_reset(self, *, operator_confirmed=False):
        if not operator_confirmed:
            return False
        self.stopped = False
        # Operator reset restores availability, never replay eligibility.
        return True

    def admit(self, evidence):
        if self.stopped or not evidence.verified:
            return False
        if not all(isinstance(v, str) and 0 < len(v) <= 128 for v in
                   (evidence.incident, evidence.sender, evidence.nonce, evidence.event)):
            return False
        if type(evidence.epoch) is not int or not (self.epoch - self.window <= evidence.epoch <= self.epoch):
            return False
        key = (evidence.sender, evidence.epoch, evidence.nonce)
        if key in self._nonces or (evidence.incident, evidence.epoch, evidence.event) in self._admitted:
            return False
        bucket = (evidence.incident, evidence.epoch, evidence.event)
        if bucket not in self._buckets and len(self._buckets) >= self.max_buckets:
            return False
        if len(self._nonces) >= self.max_nonces:
            return False
        senders = self._buckets.get(bucket)
        if senders is not None and evidence.sender in senders:
            return False  # A repeated sender cannot exhaust the global nonce budget.
        self._nonces.add(key)
        if senders is None:
            senders = set()
            self._buckets[bucket] = senders
        senders.add(evidence.sender)
        if len(senders) >= self.quorum:
            self._admitted.add(bucket)
            return True
        return False
