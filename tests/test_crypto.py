import unittest

from rsa_demo.crypto import (
    decrypt_bytes,
    decrypt_payload,
    encrypt_bytes,
    encrypt_payload,
    generate_keypair,
    sign_bytes,
    verify_signature,
)


class CryptoTests(unittest.TestCase):
    def test_rsa_encrypt_decrypt_round_trip(self):
        public_key, private_key = generate_keypair(1024)
        message = ("RSA demo " * 20).encode("utf-8")
        ciphertext = encrypt_bytes(message, public_key)
        plaintext = decrypt_bytes(ciphertext, private_key)
        self.assertEqual(plaintext, message)

    def test_signature_round_trip(self):
        public_key, private_key = generate_keypair(1024)
        message = b"message for signature"
        signature = sign_bytes(message, private_key)
        self.assertTrue(verify_signature(message, signature, public_key))
        self.assertFalse(verify_signature(message + b"!", signature, public_key))

    def test_hybrid_payload_round_trip(self):
        payload = b"example file bytes" * 64
        package = encrypt_payload(payload)
        restored = decrypt_payload(
            package["session_key"],
            package["nonce"],
            package["ciphertext"],
            package["tag"],
        )
        self.assertEqual(restored, payload)


if __name__ == "__main__":
    unittest.main()
