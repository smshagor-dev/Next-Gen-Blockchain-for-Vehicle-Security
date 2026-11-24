"""Non-actuating socket ingress experiment. Never dispatches vehicle commands."""
import socket
import time

MAX_FRAME = 4096

class FrameRejected(ValueError):
    pass

def read_bounded_frame(sock, *, max_frame=MAX_FRAME, deadline_seconds=0.25, clock=time.monotonic):
    """Read one newline-terminated frame with a total monotonic deadline.

    Read at most one byte beyond the budget. The caller closes the connection
    after the frame to prevent pipelined unvalidated commands.
    """
    if not (1 <= max_frame <= MAX_FRAME) or deadline_seconds <= 0:
        raise ValueError('invalid limits')
    deadline = clock() + deadline_seconds
    data = bytearray()
    while True:
        remaining = deadline - clock()
        if remaining <= 0:
            raise FrameRejected('deadline')
        sock.settimeout(remaining)
        try:
            chunk = sock.recv(min(512, max_frame + 1 - len(data)))
        except socket.timeout as exc:
            raise FrameRejected('deadline') from exc
        if not chunk:
            raise FrameRejected('truncated')
        data.extend(chunk)
        if len(data) > max_frame:
            raise FrameRejected('oversized')
        index = data.find(b'\n')
        if index >= 0:
            if index != len(data)-1:
                raise FrameRejected('pipelined data')
            return bytes(data)

def evidence_only_session(conn, gate, *, deadline_seconds=0.25):
    """One frame, one gate call, no actuation surface. Always closes socket."""
    try:
        raw = read_bounded_frame(conn, deadline_seconds=deadline_seconds)
        return gate.ingest(raw)
    finally:
        conn.close()
