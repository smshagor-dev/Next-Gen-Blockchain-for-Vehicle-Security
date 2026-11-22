"""Bounded exhaustive crash/retry model for nonce/inbox/ledger delivery.

Abstract protocol, not a proof about the production implementation.
"""
from collections import deque
from dataclasses import dataclass

@dataclass(frozen=True)
class State:
    nonce: bool = False
    inbox: bool = False
    ledger_copies: int = 0
    ack: bool = False
    crashed: bool = False

def transitions(s, *, atomic_inbox=True, idempotent_ledger=True):
    if s.crashed:
        yield 'restart', State(s.nonce, s.inbox, s.ledger_copies, s.ack, False)
        return
    if not s.nonce:
        yield 'ingest', State(True, atomic_inbox, s.ledger_copies, s.ack, False)
    if s.nonce and not s.inbox:
        yield 'write_inbox', State(True, True, s.ledger_copies, s.ack, False)
    if s.inbox and not s.ack:
        copies = s.ledger_copies if idempotent_ledger and s.ledger_copies else s.ledger_copies + 1
        yield 'deliver', State(s.nonce, s.inbox, copies, False, False)
        if s.ledger_copies:
            yield 'ack', State(s.nonce, s.inbox, s.ledger_copies, True, False)
    yield 'crash', State(s.nonce, s.inbox, s.ledger_copies, s.ack, True)

def explore(*, atomic_inbox=True, idempotent_ledger=True, max_depth=9):
    start = State()
    queue = deque([(start, ())])
    visited = {start}
    violations = {}
    while queue:
        state, path = queue.popleft()
        if state.nonce and not state.inbox:
            violations.setdefault('orphan_nonce', path)
        if state.ledger_copies > 1:
            violations.setdefault('duplicate_delivery', path)
        if len(path) >= max_depth:
            continue
        for action, nxt in transitions(state, atomic_inbox=atomic_inbox, idempotent_ledger=idempotent_ledger):
            if nxt not in visited:
                visited.add(nxt)
                queue.append((nxt, path + (action,)))
    return {'reachable_states': len(visited), 'counterexamples': violations}

if __name__ == '__main__':
    for name, atomic, idem in [('legacy', False, False), ('atomic_only', True, False), ('atomic_idempotent', True, True)]:
        print(name, explore(atomic_inbox=atomic, idempotent_ledger=idem))
