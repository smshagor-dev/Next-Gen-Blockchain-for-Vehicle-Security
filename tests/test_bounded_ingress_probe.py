import json
import os
import tempfile
import unittest
from research_contracts.bounded_ingress_probe import EvidenceOnlyGate, Reject, frame, MAX_FRAME

class IngressTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.path = os.path.join(self.tmp.name,'seen.sqlite')
        self.gate = EvidenceOnlyGate(self.path, {'a':b'secret'},clock=lambda:100)
        self.payload = {'device':'a','nonce':'n1','timestamp':100,'observation':{'speed':2}}
    def tearDown(self):
        self.gate.db.close(); self.tmp.cleanup()
    def test_accept_is_nonactuating(self):
        self.assertEqual(self.gate.ingest(frame(self.payload,b'secret'))['status'],'evidence_only')
    def test_replay_after_restart(self):
        data=frame(self.payload,b'secret');self.gate.ingest(data);self.gate.db.close()
        self.gate=EvidenceOnlyGate(self.path,{'a':b'secret'},clock=lambda:100)
        with self.assertRaises(Reject): self.gate.ingest(data)
    def test_tamper(self):
        data=json.loads(frame(self.payload,b'secret'));data['payload']['observation']['speed']=99
        with self.assertRaises(Reject): self.gate.ingest(json.dumps(data).encode()+b'\n')
    def test_oversize(self):
        with self.assertRaises(Reject): self.gate.ingest(b'x'*(MAX_FRAME+1)+b'\n')
    def test_stale(self):
        self.payload['timestamp']=0
        with self.assertRaises(Reject): self.gate.ingest(frame(self.payload,b'secret'))
    def test_bad_key(self):
        with self.assertRaises(Reject): self.gate.ingest(frame(self.payload,b'wrong'))
    def test_missing_delimiter(self):
        with self.assertRaises(Reject): self.gate.ingest(frame(self.payload,b'secret')[:-1])
    def test_duplicate_key_is_per_device(self):
        self.gate.ingest(frame(self.payload,b'secret'))
        self.assertEqual(self.gate.db.execute('SELECT COUNT(*) FROM seen').fetchone()[0],1)
if __name__=='__main__': unittest.main()
