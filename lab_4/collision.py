import hashlib
import secrets
from typing import Optional, Tuple
from tqdm import tqdm
from constants import DEFAULT_COLLISION_BITS, DEFAULT_MAX_ATTEMPTS


def truncated_hash(data: bytes, bits: int) -> int:
    """
    Compute truncated SHA256 hash (first 'bits' bits).

    Args:
        data: Input bytes.
        bits: Number of bits to keep (1..32).

    Returns:
        Integer value of the truncated hash.

    Raises:
        ValueError: If bits out of range.
        TypeError: If data is not bytes.
    """
    if not isinstance(data, bytes):
        raise TypeError("Data must be bytes.")
    if not 1 <= bits <= 32:
        raise ValueError("Bits must be between 1 and 32.")

    full = hashlib.sha256(data).digest()
    byte_count = (bits + 7) // 8
    truncated = int.from_bytes(full[:byte_count], 'big')
    if bits % 8 != 0:
        truncated >>= (8 - bits % 8)
    return truncated


def find_collision(
    bits: int = DEFAULT_COLLISION_BITS,
    max_attempts: int = DEFAULT_MAX_ATTEMPTS
) -> Optional[Tuple[bytes, bytes, int]]:
    """
    Find a collision for truncated SHA256 using birthday attack.

    Args:
        bits: Number of bits for truncation (1..32).
        max_attempts: Maximum number of random messages to try.

    Returns:
        Tuple (message1, message2, truncated_hash) if collision found,
        otherwise None.

    Raises:
        ValueError: If bits out of range or max_attempts <= 0.
        TypeError: If arguments are of wrong type.
    """
    if not isinstance(bits, int) or not isinstance(max_attempts, int):
        raise TypeError("Bits and max_attempts must be integers.")
    if not 1 <= bits <= 32:
        raise ValueError("Bits must be between 1 and 32.")
    if max_attempts <= 0:
        raise ValueError("max_attempts must be positive.")

    seen: dict = {}
    for _ in tqdm(range(max_attempts), desc=f"Searching collision ({bits} bits)"):
        msg = secrets.token_bytes(16)
        h = truncated_hash(msg, bits)
        if h in seen:
            return (seen[h], msg, h)
        seen[h] = msg
    return None