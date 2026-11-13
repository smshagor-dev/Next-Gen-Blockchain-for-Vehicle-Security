"""Deterministic tests for simulation-only authenticated admission receipts."""
import unittest
from command_ack_protocol import issue_receipt, verify_receipt

KEY = 'a' * 48
DEVICE = 'bench-node'
NONCE = 'b' * 32
CHALLENGE = 'c' * 32


class ReceiptTests(unittest.TestCase):
    def receipt(self):
        return issue_receipt(KEY, device_id=DEVICE, command_nonce=NONCE,
                             challenge=CHALLENGE, admitted=True)

    def verify(self, receipt, **changes):
        params = dict(device_id=DEVICE, command_nonce=NONCE, challenge=CHALLENGE)
        params.update(changes)
        return verify_receipt(KEY, receipt, **params)

    def test_valid_receipt_is_not_actuation_ack(self):
        receipt = self.receipt()
        self.assertTrue(self.verify(receipt))
        self.assertFalse(receipt['physical_acknowledgment'])
        self.assertFalse(receipt['actuation_performed'])

    def test_wrong_challenge_rejected(self):
        self.assertFalse(self.verify(self.receipt(), challenge='d' * 32))

    def test_wrong_command_rejected(self):
        self.assertFalse(self.verify(self.receipt(), command_nonce='e' * 32))

    def test_tampered_receipt_rejected(self):
        receipt = self.receipt()
        receipt['admitted'] = False
        self.assertFalse(self.verify(receipt))

    def test_fake_physical_ack_rejected(self):
        receipt = self.receipt()
        receipt['physical_acknowledgment'] = True
        self.assertFalse(self.verify(receipt))

    def test_unknown_field_rejected(self):
        receipt = self.receipt()
        receipt['execution'] = 'done'
        self.assertFalse(self.verify(receipt))

    def test_key_mismatch_rejected(self):
        self.assertFalse(verify_receipt('z' * 48, self.receipt(), device_id=DEVICE,
                                        command_nonce=NONCE, challenge=CHALLENGE))

    def test_short_challenge_rejected(self):
        with self.assertRaises(ValueError):
            issue_receipt(KEY, device_id=DEVICE, command_nonce=NONCE,
                          challenge='a', admitted=True)


if __name__ == '__main__':
    unittest.main()
