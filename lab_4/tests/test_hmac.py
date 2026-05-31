import unittest
from hmac_utils import compute_hmac, verify_hmac, tamper_message


class TestHMAC(unittest.TestCase):

    def test_compute_hmac_hex_length(self):
        h = compute_hmac("Hello", "key")
        self.assertEqual(len(h), 64)
        self.assertTrue(all(c in '0123456789abcdef' for c in h))

    def test_verify_correct(self):
        msg = "Test message"
        key = "secret"
        h = compute_hmac(msg, key)
        self.assertTrue(verify_hmac(msg, key, h))

    def test_verify_wrong_key(self):
        msg = "Test"
        h = compute_hmac(msg, "key1")
        self.assertFalse(verify_hmac(msg, "key2", h))

    def test_verify_tampered_message(self):
        msg = "Original"
        key = "key"
        h = compute_hmac(msg, key)
        tampered = tamper_message(msg)
        self.assertFalse(verify_hmac(tampered, key, h))

    def test_tamper_changes_message(self):
        original = "abcdef"
        tampered = tamper_message(original)
        self.assertNotEqual(original, tampered)

    def test_compute_hmac_raises_on_empty_key(self):
        with self.assertRaises(ValueError):
            compute_hmac("msg", "")

    def test_compute_hmac_raises_on_non_string(self):
        with self.assertRaises(TypeError):
            compute_hmac(123, "key")

    def test_compute_hmac_deterministic(self):
    h1 = compute_hmac("msg", "key")
    h2 = compute_hmac("msg", "key")
    self.assertEqual(h1, h2)

    def test_different_messages_different_hmac(self):
        h1 = compute_hmac("msg1", "key")
        h2 = compute_hmac("msg2", "key")
        self.assertNotEqual(h1, h2)

    def test_verify_raises_on_invalid_hmac_format(self):
        with self.assertRaises(ValueError):
            verify_hmac("msg", "key", "not_a_valid_hmac")

    def test_compute_hmac_raises_on_empty_message(self):
        with self.assertRaises(ValueError):
            compute_hmac("", "key")


if __name__ == '__main__':
    unittest.main()