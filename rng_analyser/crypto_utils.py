"""
crypto_utils.py
Real AES-256-GCM authenticated encryption.

GCM mode provides BOTH:
- Confidentiality: the message is unreadable without the key.
- Integrity/Authenticity: any tampering with the ciphertext causes
  decryption to fail loudly, instead of silently returning garbage.

This is the actual cryptographic operation the whole system depends on.
The RNG topic matters here because AES's security guarantee assumes the
key and nonce are unpredictable -- if they aren't, none of AES's math
protects you, no matter how strong the cipher itself is.
"""

import base64
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.exceptions import InvalidTag

KEY_SIZE = 32     # AES-256
NONCE_SIZE = 12   # 96-bit nonce, the size recommended for GCM


def encrypt(plaintext: str, key: bytes, nonce: bytes) -> str:
    """Encrypts a UTF-8 string, returns base64-encoded ciphertext (includes auth tag)."""
    aesgcm = AESGCM(key)
    ciphertext = aesgcm.encrypt(nonce, plaintext.encode("utf-8"), associated_data=None)
    return base64.b64encode(ciphertext).decode("ascii")


def decrypt(ciphertext_b64: str, key: bytes, nonce: bytes) -> str:
    """
    Decrypts base64-encoded ciphertext. Raises InvalidTag if the key/nonce
    is wrong or the ciphertext was tampered with -- callers should catch this.
    """
    aesgcm = AESGCM(key)
    ciphertext = base64.b64decode(ciphertext_b64)
    plaintext = aesgcm.decrypt(nonce, ciphertext, associated_data=None)
    return plaintext.decode("utf-8")


if __name__ == "__main__":
    import secrets
    key = secrets.token_bytes(KEY_SIZE)
    nonce = secrets.token_bytes(NONCE_SIZE)
    ct = encrypt("Hello, cryptography!", key, nonce)
    print("Ciphertext:", ct)
    print("Decrypted :", decrypt(ct, key, nonce))

    try:
        decrypt(ct, secrets.token_bytes(KEY_SIZE), nonce)
    except InvalidTag:
        print("Wrong key correctly rejected (integrity check works).")
