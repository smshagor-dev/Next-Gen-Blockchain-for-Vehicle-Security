import socket
import threading
import time
import unittest
from research_contracts.socket_boundary_experiment import FrameRejected, read_bounded_frame, evidence_only_session

class Gate:
    def __init__(self): self.frames=[]
    def ingest(self, raw): self.frames.append(raw); return {'status':'evidence_only'}

class SocketBoundaryTests(unittest.TestCase):
    def setUp(self): self.server,self.client=socket.socketpair()
    def tearDown(self): self.server.close(); self.client.close()
    def test_fragmented(self):
        def send():
            for p in (b'abc',b'def',b'\n'):
                self.client.sendall(p); time.sleep(.005)
        t=threading.Thread(target=send); t.start()
        self.assertEqual(read_bounded_frame(self.server),b'abcdef\n'); t.join()
    def test_oversized(self):
        self.client.sendall(b'a'*4097)
        with self.assertRaisesRegex(FrameRejected,'oversized'): read_bounded_frame(self.server)
    def test_slowloris_total_deadline(self):
        def send():
            for _ in range(8):
                try: self.client.sendall(b'a')
                except OSError: break
                time.sleep(.025)
        t=threading.Thread(target=send);t.start()
        start=time.monotonic()
        with self.assertRaisesRegex(FrameRejected,'deadline'): read_bounded_frame(self.server,deadline_seconds=.065)
        self.assertLess(time.monotonic()-start,.2);t.join()
    def test_truncated(self):
        self.client.sendall(b'abc');self.client.shutdown(socket.SHUT_WR)
        with self.assertRaisesRegex(FrameRejected,'truncated'):read_bounded_frame(self.server)
    def test_pipelined(self):
        self.client.sendall(b'one\ntwo\n')
        with self.assertRaisesRegex(FrameRejected,'pipelined'):read_bounded_frame(self.server)
    def test_nonactuating_session(self):
        self.client.sendall(b'evidence\n');gate=Gate()
        self.assertEqual(evidence_only_session(self.server,gate),{'status':'evidence_only'})
        self.assertEqual(gate.frames,[b'evidence\n'])
        self.assertEqual(self.server.fileno(),-1)
    def test_invalid_limit(self):
        with self.assertRaises(ValueError):read_bounded_frame(self.server,max_frame=4097)
if __name__=='__main__':unittest.main()
