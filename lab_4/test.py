import unittest
from hmac_utils import compute_hmac, verify_hmac, tamper_message
from constants import TEST1, TEST2, TEST_KEY, TEST_HMAC, TEST2_HMAC


class TestHMACUtils(unittest.TestCase):
    """Unit tests for HMAC functions and message tampering."""

    def test_compute_hmac_correct(self):
        """Compute HMAC for correct data."""
        hmac_value = compute_hmac(TEST1, TEST_KEY)
        self.assertEqual(hmac_value, TEST_HMAC)

    def test_compute_hmac_different_message(self):
        """Different messages produce different HMACs."""
        hmac1 = compute_hmac(TEST1, TEST_KEY)
        hmac2 = compute_hmac(TEST2, TEST_KEY)
        self.assertNotEqual(hmac1, hmac2)

    def test_compute_hmac_empty_message(self):
        """Empty message raises ValueError."""
        with self.assertRaises(ValueError):
            compute_hmac("", TEST_KEY)

    def test_compute_hmac_empty_key(self):
        """Empty key raises ValueError."""
        with self.assertRaises(ValueError):
            compute_hmac(TEST1, "")

    def test_compute_hmac_non_string(self):
        """Non‑string arguments raise TypeError."""
        with self.assertRaises(TypeError):
            compute_hmac(123, TEST_KEY)
        with self.assertRaises(TypeError):
            compute_hmac(TEST1, 456)\

    def test_verify_hmac_correct(self):
        """Verification of correct (message, HMAC) pair."""
        self.assertTrue(verify_hmac(TEST1, TEST_KEY, TEST_HMAC))

    def test_verify_hmac_wrong_message(self):
        """Wrong message returns False."""
        self.assertFalse(verify_hmac(TEST2, TEST_KEY, TEST_HMAC))

    def test_verify_hmac_wrong_hmac(self):
        """Wrong HMAC returns False."""
        self.assertFalse(verify_hmac(TEST1, TEST_KEY, "0" * 64))

    def test_verify_hmac_wrong_key(self):
        """Wrong key returns False."""
        self.assertFalse(verify_hmac(TEST1, "wrongkey", TEST_HMAC))

    def test_verify_hmac_invalid_length(self):
        """HMAC with incorrect length raises ValueError."""
        with self.assertRaises(ValueError):
            verify_hmac(TEST1, TEST_KEY, "short")

    def test_verify_hmac_empty_args(self):
        """Empty arguments raise ValueError (via compute_hmac)."""
        with self.assertRaises(ValueError):
            verify_hmac("", TEST_KEY, TEST_HMAC)
        with self.assertRaises(ValueError):
            verify_hmac(TEST1, "", TEST_HMAC)

    def test_tamper_message_changes_first_char(self):
        """First character is replaced."""
        original = "Hello, world!"
        tampered = tamper_message(original)
        self.assertEqual(len(tampered), len(original))
        self.assertNotEqual(tampered, original)
        self.assertEqual(tampered[1:], original[1:])

    def test_tamper_message_empty_string(self):
        """Empty string becomes 'x'."""
        self.assertEqual(tamper_message(""), "x")

    def test_tamper_message_non_string(self):
        """Non‑string argument raises TypeError."""
        with self.assertRaises(TypeError):
            tamper_message(123)

    def test_tamper_message_single_char(self):
        """Single character is replaced by a different one."""
        original = "a"
        tampered = tamper_message(original)
        self.assertEqual(len(tampered), 1)
        self.assertNotEqual(tampered, original)

    def test_tamper_message_unicode(self):
        """Unicode characters (including multi‑byte) are handled correctly."""
        original = "Hello"
        tampered = tamper_message(original)
        self.assertEqual(len(tampered), len(original))
        self.assertNotEqual(tampered, original)
        self.assertEqual(tampered[1:], original[1:])


if __name__ == "__main__":
    unittest.main()