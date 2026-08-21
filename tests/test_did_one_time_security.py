import unittest

from did_identity import DIDIdentity, verify_did_proof


class DIDOneTimeSecurityTests(unittest.TestCase):
    def test_first_signature_verifies(self):
        identity = DIDIdentity.generate("CAR-1")
        doc = identity.to_document()
        proof = identity.sign_challenge("nonce-1")
        self.assertTrue(verify_did_proof("nonce-1", proof, doc))

    def test_second_signature_is_rejected(self):
        identity = DIDIdentity.generate("CAR-1")
        identity.sign_challenge("nonce-1")
        with self.assertRaises(RuntimeError):
            identity.sign_challenge("nonce-2")

    def test_private_key_is_cleared_after_use(self):
        identity = DIDIdentity.generate("CAR-1")
        self.assertEqual(len(identity.private_key), 256)
        identity.sign_challenge("nonce-1")
        self.assertTrue(identity.exhausted)
        self.assertEqual(identity.private_key, [])

    def test_tampered_challenge_fails(self):
        identity = DIDIdentity.generate("CAR-1")
        doc = identity.to_document()
        proof = identity.sign_challenge("nonce-1")
        self.assertFalse(verify_did_proof("nonce-2", proof, doc))

    def test_tampered_signature_fails(self):
        identity = DIDIdentity.generate("CAR-1")
        doc = identity.to_document()
        proof = identity.sign_challenge("nonce-1")
        proof["signature"][0] = "00" * 32
        self.assertFalse(verify_did_proof("nonce-1", proof, doc))

    def test_malformed_signature_fails_closed(self):
        identity = DIDIdentity.generate("CAR-1")
        doc = identity.to_document()
        proof = identity.sign_challenge("nonce-1")
        proof["signature"][0] = "not-hex"
        self.assertFalse(verify_did_proof("nonce-1", proof, doc))

    def test_proof_must_declare_one_time_key(self):
        identity = DIDIdentity.generate("CAR-1")
        doc = identity.to_document()
        proof = identity.sign_challenge("nonce-1")
        proof["one_time_key"] = False
        self.assertFalse(verify_did_proof("nonce-1", proof, doc))

    def test_successor_has_fresh_did_and_key(self):
        identity = DIDIdentity.generate("CAR-1")
        identity.sign_challenge("nonce-1")
        successor = identity.successor()
        self.assertNotEqual(successor.did, identity.did)
        self.assertFalse(successor.exhausted)
        self.assertEqual(successor.controller, identity.controller)


if __name__ == "__main__":
    unittest.main()
