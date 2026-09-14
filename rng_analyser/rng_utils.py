"""
rng_utils.py
Two key/nonce generation strategies for the vault, plus the attack that
breaks the insecure one.

- SecureRNG   : uses Python's `secrets` module (a CSPRNG). This is the
                only appropriate choice for real cryptographic keys.
- InsecureLCG : a Linear Congruential Generator, included ONLY to
                demonstrate -- inside this same working system -- a real
                and historically common mistake: deriving secret key
                material from a predictable generator.

The attack modeled here is realistic: it does not require guessing or
brute-forcing anything. It requires only ONE value that the system
already exposes publicly (a "session id"), because that value happens
to reveal the generator's internal state.
"""

import secrets


class SecureRNG:
    """Cryptographically secure key/nonce generator (safe to use for real keys)."""

    @staticmethod
    def generate_key(size=32):
        return secrets.token_bytes(size)

    @staticmethod
    def generate_nonce(size=12):
        return secrets.token_bytes(size)


class InsecureLCG:
    """
    A Linear Congruential Generator: X(n+1) = (a*X(n) + c) mod m.

    The constants below are PUBLIC constants baked into the algorithm --
    this mirrors real systems, where the algorithm is rarely secret, only
    the internal state/seed is meant to be. Knowing A, C, and M is not
    the vulnerability; the vulnerability is that any ONE output instantly
    reveals the exact state needed to compute every future output.
    """
    A = 1103515245
    C = 12345
    M = 2 ** 31

    def __init__(self, seed):
        self.state = seed % self.M

    def next_int(self):
        self.state = (self.A * self.state + self.C) % self.M
        return self.state

    def generate_bytes(self, n_bytes):
        """Generates n_bytes of key material, 4 bytes per LCG output."""
        out = bytearray()
        while len(out) < n_bytes:
            out += self.next_int().to_bytes(4, "big")
        return bytes(out[:n_bytes])


def derive_insecure_key_and_nonce(seed):
    """
    Simulates a realistic mistake: a single PRNG stream is used both for a
    'public-looking' session id (e.g. shown in a URL, stored in a cookie,
    written to a log file) AND for the secret key and nonce that follow it.

    Returns (session_id, key, nonce).
    """
    lcg = InsecureLCG(seed)
    session_id = lcg.next_int()      # attacker-visible value
    key = lcg.generate_bytes(32)     # meant to stay secret
    nonce = lcg.generate_bytes(12)   # meant to stay secret
    return session_id, key, nonce


def attacker_recover_key_and_nonce(session_id):
    """
    THE ATTACK.

    Because the LCG's constants are public and the session_id IS the
    generator's internal state at that moment, anyone can restart the
    same generator from that state and reproduce the exact key and nonce
    that followed it. No brute force, no cryptanalysis of AES itself --
    the weakness is entirely in the RNG, not the cipher.
    """
    lcg = InsecureLCG(session_id)
    key = lcg.generate_bytes(32)
    nonce = lcg.generate_bytes(12)
    return key, nonce


if __name__ == "__main__":
    # --- Demo ---
    seed = 20250914  # e.g. attacker knows a timestamp-like value was used
    session_id, real_key, real_nonce = derive_insecure_key_and_nonce(seed)
    print("Session id (public) :", session_id)
    print("Real key            :", real_key.hex())

    recovered_key, recovered_nonce = attacker_recover_key_and_nonce(session_id)
    print("Recovered key       :", recovered_key.hex())
    print("Attack success       :", recovered_key == real_key and recovered_nonce == real_nonce)
