import hmac
import hashlib
import secrets
from constants import HMAC_DIGEST_HEX_LENGTH

def compute_hmac(message: str, key: str) -> str:
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
    match (message, key, expected_hmac):
        case (str(), str(), str()):
            if len(expected_hmac) != HMAC_DIGEST_HEX_LENGTH:
                raise ValueError(f"Expected HMAC must be {HMAC_DIGEST_HEX_LENGTH} hex characters.")
        case _:
            raise TypeError("All arguments must be strings.")
    computed = compute_hmac(message, key)
    return hmac.compare_digest(computed, expected_hmac)

def tamper_message(original: str) -> str:
    if not isinstance(original, str):
        raise TypeError("Original message must be a string.")
    match original:
        case "":
            return "x"
        case _:
            new_char = chr(secrets.randbelow(0x10FFFF))
            return new_char + original[1:]