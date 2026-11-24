"""Safety and limitation checks for dissent-tolerant quorum."""
import sys
import unittest
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1] / "research_contracts"))
from robust_group_policy import Report,evaluate

def r(i,g,h=True):
    return Report(i,g,'incident',10.,h,True)

class TestPolicy(unittest.TestCase):
    def test_dissent_does_not_veto_two_independent_groups(self):
        v=evaluate([r('a','A'),r('b','B'),r('c','C',False)],incident='incident',now=11)
        self.assertTrue(v.admitted)
        self.assertEqual((v.support_groups,v.dissent_groups),(2,1))
        self.assertFalse(v.command_authorized)

    def test_same_group_sybil_not_quorum(self):
        self.assertFalse(evaluate([r('a','A'),r('b','A')],incident='incident',now=11).admitted)

    def test_conflicted_group_abstains(self):
        self.assertFalse(evaluate([r('a','A'),r('b','A',False),r('c','B')],incident='incident',now=11).admitted)

    def test_stale_fails_closed(self):
        self.assertFalse(evaluate([r('a','A'),r('b','B')],incident='incident',now=15).admitted)

    def test_two_compromised_groups_remain_limitation(self):
        self.assertTrue(evaluate([r('a','A'),r('b','B')],incident='incident',now=11).admitted)

if __name__=='__main__':
    unittest.main()
