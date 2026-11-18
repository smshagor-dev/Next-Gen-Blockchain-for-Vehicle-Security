import unittest
from research_contracts.loopback_attack_campaign import run, envelope, Receiver, MAX_FRAME
class LoopbackCampaignTests(unittest.TestCase):
    def test_local_socket_campaign(self):
        rows=run(3)
        self.assertEqual(len(rows),12)
        self.assertEqual({r['kind'] for r in rows},{'honest','replay','tamper','oversize'})
        self.assertTrue(all(r['expected']==r['observed'] for r in rows))
        self.assertTrue(all(r['latency_ns']>=0 for r in rows))
    def test_frame_cap(self):
        self.assertLess(len(envelope('node',1,1))-4,MAX_FRAME)
    def test_bad_trial_count(self):
        with self.assertRaises(ValueError): run(0)
    def test_no_actuator_surface(self):
        self.assertFalse(hasattr(Receiver(),'actuate'))
if __name__=='__main__': unittest.main()
