"""
entropy_utils.py
Small helper to calculate and describe the entropy of generated keys/passwords,
used on the Key Generator page to make the abstract idea of "randomness
strength" concrete and visible to the user.
"""

import math
from collections import Counter


def shannon_entropy_bits(data: str) -> float:
    """Shannon entropy in bits per character."""
    if not data:
        return 0.0
    counts = Counter(data)
    n = len(data)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


def keyspace_bits(charset_size: int, length: int) -> float:
    """Theoretical entropy (bits) of a uniformly random string from a given charset."""
    if charset_size <= 1:
        return 0.0
    return length * math.log2(charset_size)


def strength_label(bits: float) -> str:
    if bits < 40:
        return "Weak"
    if bits < 64:
        return "Moderate"
    if bits < 100:
        return "Strong"
    return "Very strong"
