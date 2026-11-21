"""Regression tests for non-actuating replay fault campaign."""
import unittest
from research_contracts.replay_fault_campaign import campaign

class ReplayFaultCampaignTests(unittest.TestCase):
    def test_post_commit_sigkill_rejected(self):
        r=campaign(("post_commit",),2)
        self.assertTrue(all(x["pass"] and x["observed"]=="replay" for x in r),r)
    def test_pre_commit_sigkill_not_persisted(self):
        r=campaign(("pre_commit",),2)
        self.assertTrue(all(x["pass"] and x["observed"]=="accept" for x in r),r)
    def test_rollback_negative_control(self):
        r=campaign(("rollback",),2)
        self.assertTrue(all(x["pass"] and x["observed"]=="accept" for x in r),r)
    def test_corruption_fails_at_startup(self):
        r=campaign(("corruption",),2)
        self.assertTrue(all(x["pass"] and x["observed"]=="startup_error" for x in r),r)
    def test_invalid_trials(self):
        with self.assertRaises(ValueError): campaign(trials=0)
        with self.assertRaises(ValueError): campaign(trials=10001)
if __name__=="__main__": unittest.main()
