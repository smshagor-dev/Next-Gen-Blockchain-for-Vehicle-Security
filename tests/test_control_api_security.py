import hashlib
import hmac
import unittest

from control_api_security import (
    build_signed_headers,
    canonical_api_message,
    expected_service_proof,
    validate_loopback_base_url,
    verify_service_proof,
)


class ControlAPISecurityTests(unittest.TestCase):
    def test_loopback_urls_only(self):
        self.assertEqual(validate_loopback_base_url("http://127.0.0.1:8787"), "http://127.0.0.1:8787")
        self.assertEqual(validate_loopback_base_url("http://localhost:8787/"), "http://localhost:8787")
        for value in [
            "https://127.0.0.1:8787",
            "http://10.0.0.7:8787",
            "http://example.com:8787",
            "http://user:pass@127.0.0.1:8787",
            "http://127.0.0.1:8787/api",
        ]:
            with self.subTest(value=value):
                with self.assertRaises(ValueError):
                    validate_loopback_base_url(value)

    def test_signed_headers_match_contract(self):
        secret = "s" * 48
        body = b'{"distance":4}'
        ts = 1_700_000_000
        nonce = "01" * 16
        headers = build_signed_headers(secret, "POST", "/emergency/brake", body, timestamp=ts, nonce=nonce)
        body_hash = hashlib.sha256(body).hexdigest()
        canonical = canonical_api_message("POST", "/emergency/brake", str(ts), nonce, body_hash)
        expected = hmac.new(secret.encode(), canonical.encode(), hashlib.sha256).hexdigest()
        self.assertEqual(headers["X-SmartCar-Content-SHA256"], body_hash)
        self.assertEqual(headers["X-SmartCar-Signature"], expected)

    def test_nonce_requires_128_bits(self):
        with self.assertRaises(ValueError):
            build_signed_headers("s" * 48, "GET", "/status", b"", timestamp=1, nonce="01")

    def test_service_proof_is_secret_bound(self):
        challenge = "ab" * 16
        secret = "k" * 48
        proof = expected_service_proof(secret, challenge)
        self.assertTrue(verify_service_proof(secret, challenge, proof))
        self.assertFalse(verify_service_proof("x" * 48, challenge, proof))


if __name__ == "__main__":
    unittest.main()
