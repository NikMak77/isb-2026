import hmac
import hashlib
import secrets
from typing import Optional


def compute_hmac(message: str, key: str) -> str:
    """
    Compute HMAC-SHA256 of a message using a secret key.

    Args:
        message: The message to authenticate.
        key: The secret key.

    Returns:
        Hex-encoded HMAC string (64 characters).

    Raises:
        TypeError: If message or key are not strings.
        ValueError: If message or key are empty.
    """
    match (message, key):
        case (str(), str()):
            if not message or not key:
                raise ValueError("Message and key must be non-empty strings.")
        case _:
            raise TypeError("Message and key must be strings.")

    key_bytes = key.encode('utf-8')
    msg_bytes = message.encode('utf-8')
    h = hmac.new(key_bytes, msg_bytes, hashlib.sha256)
    return h.hexdigest()


def verify_hmac(message: str, key: str, expected_hmac: str) -> bool:
    """
    Verify the HMAC of a message against an expected value.
    Uses constant-time comparison to prevent timing attacks.

    Args:
        message: The message to check.
        key: The secret key.
        expected_hmac: The expected HMAC (hex string).

    Returns:
        True if computed HMAC matches expected_hmac, False otherwise.

    Raises:
        TypeError: If any argument is not a string.
        ValueError: If expected_hmac is not 64 hex characters.
    """
    match (message, key, expected_hmac):
        case (str(), str(), str()):
            if len(expected_hmac) != 64:
                raise ValueError("Expected HMAC must be 64 hex characters.")
        case _:
            raise TypeError("All arguments must be strings.")

    computed = compute_hmac(message, key)
    return hmac.compare_digest(computed, expected_hmac)


def tamper_message(original: str) -> str:
    """
    Modify a random character of the message to simulate tampering.

    Args:
        original: Original message.

    Returns:
        Altered message (first character replaced with a random Unicode char).

    Raises:
        TypeError: If original is not a string.
    """
    if not isinstance(original, str):
        raise TypeError("Original message must be a string.")

    match original:
        case "":
            return "x"
        case _:
            new_char = chr(secrets.randbelow(0x10FFFF))
            return new_char + original[1:]