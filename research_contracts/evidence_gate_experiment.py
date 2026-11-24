"""Non-actuating synthetic V2X evidence-gate negative controls; not publication evidence."""
from dataclasses import dataclass
from collections import defaultdict
import argparse
import json
import random

@dataclass(frozen=True)
class Observation:
    incident: str
    sender: str
    epoch: int
    nonce: str
    event: str
    authenticated: bool
    corroborates: bool

class EvidenceGate:
    def __init__(self, quorum=2, max_observations=64):
        if quorum < 2 or max_observations < quorum:
            raise ValueError("invalid limits")
        self.quorum = quorum
        self.max_observations = max_observations
        self._seen = set()
        self._evidence = defaultdict(set)
        self._count = defaultdict(int)

    def admit(self, obs: Observation, *, local_stop=False):
        if local_stop:
            return False
        if not obs.authenticated or not obs.corroborates or obs.epoch < 0:
            return False
        key = (obs.sender, obs.epoch, obs.nonce)
        if key in self._seen:
            return False
        bucket = (obs.incident, obs.epoch, obs.event)
        if self._count[bucket] >= self.max_observations:
            return False
        self._seen.add(key)
        self._count[bucket] += 1
        self._evidence[bucket].add(obs.sender)
        return len(self._evidence[bucket]) >= self.quorum

def evaluate(seed=7, incidents=200, compromised_fraction=0.2):
    """Synthetic sensitivity only: no independent labels or physical safety claims."""
    if incidents < 1 or not 0 <= compromised_fraction <= 1:
        raise ValueError("invalid experiment parameters")
    rng = random.Random(seed)
    counts = {p: {"tp":0,"fp":0,"tn":0,"fn":0} for p in ("authenticated_only","evidence_gate")}
    for i in range(incidents):
        truth = rng.random() < 0.5
        compromised = rng.random() < compromised_fraction
        claimed = truth or compromised
        gate = EvidenceGate(quorum=2)
        observations = [Observation(str(i),"nodeA",i,"n1","hazard",True,claimed),
                        Observation(str(i),"nodeB",i,"n2","hazard",True,truth)]
        baseline = claimed
        gated = any(gate.admit(o) for o in observations)
        for name, prediction in (("authenticated_only",baseline),("evidence_gate",gated)):
            key = ("tp" if prediction else "fn") if truth else ("fp" if prediction else "tn")
            counts[name][key] += 1
    return {"kind":"synthetic_nonpublishable","seed":seed,"incidents":incidents,
            "compromised_fraction":compromised_fraction,"counts":counts}

def main():
    p=argparse.ArgumentParser()
    p.add_argument("--seed",type=int,default=7)
    p.add_argument("--incidents",type=int,default=200)
    p.add_argument("--compromised-fraction",type=float,default=0.2)
    a=p.parse_args()
    print(json.dumps(evaluate(a.seed,a.incidents,a.compromised_fraction),sort_keys=True))
if __name__=="__main__":
    main()
