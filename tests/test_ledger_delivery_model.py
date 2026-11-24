import unittest
from research_contracts.ledger_delivery_model import explore

class DeliveryModelTests(unittest.TestCase):
    def test_nonatomic_exposes_orphan(self):
        self.assertIn('orphan_nonce', explore(atomic_inbox=False)['counterexamples'])
    def test_atomic_inbox_removes_orphan(self):
        self.assertNotIn('orphan_nonce', explore()['counterexamples'])
    def test_nonidempotent_delivery_duplicates(self):
        self.assertIn('duplicate_delivery', explore(idempotent_ledger=False)['counterexamples'])
    def test_idempotent_delivery_prevents_duplicates(self):
        self.assertNotIn('duplicate_delivery', explore()['counterexamples'])

if __name__ == '__main__':
    unittest.main()
