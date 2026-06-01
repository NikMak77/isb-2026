import hmac
import hashlib
import secrets
from typing import Union
from constants import HMAC_DIGEST_HEX_LENGTH

def compute_hmac(message: str, key: str) -> str:
    """
    Computes HMAC-SHA256 for a message using a secret key.

    Args:
        message (str): The original message (non-empty string).
        key (str): The secret key (non-empty string).

    Returns:
        str: HMAC as a hexadecimal string of length HMAC_DIGEST_HEX_LENGTH.

    Raises:
        TypeError: If message or key is not a string.
        ValueError: If message or key is empty.
    """
    match (message, key):
        case (str(), str()):
            if not message or not key:
                raise ValueError("Message and key must be non-empty strings.")
        case _:
            raise TypeError("Message and key must be strings.")

    key_bytes: bytes = key.encode('utf-8')
    msg_bytes: bytes = message.encode('utf-8')
    h: hmac.HMAC = hmac.new(key_bytes, msg_bytes, hashlib.sha256)
    return h.hexdigest()

def verify_hmac(message: str, key: str, expected_hmac: str) -> bool:
    """
    Verifies the authenticity of a message by comparing the computed HMAC
    with the expected one. Uses constant-time comparison to prevent timing attacks.

    Args:
        message (str): The message to verify.
        key (str): The secret key.
        expected_hmac (str): The expected HMAC (hexadecimal string).

    Returns:
        bool: True if HMAC matches, False otherwise.

    Raises:
        TypeError: If any argument is not a string.
        ValueError: If expected_hmac has an invalid length.
    """
    match (message, key, expected_hmac):
        case (str(), str(), str()):
            if len(expected_hmac) != HMAC_DIGEST_HEX_LENGTH:
                raise ValueError(
                    f"Expected HMAC must be {HMAC_DIGEST_HEX_LENGTH} hex characters."
                )
        case _:
            raise TypeError("All arguments must be strings.")

    computed: str = compute_hmac(message, key)
    return hmac.compare_digest(computed, expected_hmac)

def tamper_message(original: str) -> str:
    """
    Creates a tampered version of the message to demonstrate detection.

    Replaces the first character with a random Unicode character (all code points
    from 0 to 0x10FFFF). If the original message is empty, returns "x".

    Args:
        original (str): The original message.

    Returns:
        str: The message with its first character replaced.

    Raises:
        TypeError: If original is not a string.
    """
    if not isinstance(original, str):
        raise TypeError("Original message must be a string.")

    match original:
        case "":
            return "x"
        case _:
            new_char: str = chr(secrets.randbelow(0x10FFFF))
            return new_char + original[1:]