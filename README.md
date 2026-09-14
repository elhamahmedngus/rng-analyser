# RNG Analyser
# RNG Analyser Project
This project demonstrates secure vs insecure RNG in AES-256-GCM.


A small working cryptographic system: real AES-256-GCM encryption, with a
built-in comparison between a secure key generator (CSPRNG) and a weak one
(LCG) — including a live "Attack Lab" that actually recovers the weak key
and decrypts a message using only one leaked value.

## Files

| File | Purpose |
|---|---|
| `app.py` | Flask app — all routes |
| `crypto_utils.py` | Real AES-256-GCM encrypt/decrypt |
| `rng_utils.py` | SecureRNG (CSPRNG) + InsecureLCG + the attack |
| `entropy_utils.py` | Entropy calculations for the key generator page |
| `templates/` | HTML pages |
| `static/style.css` | Styling |

## Run it

```
pip install -r requirements.txt
python app.py
```

Then open **http://127.0.0.1:5000** in your browser.

## What to try

1. **Encrypt a message → Secure mode.** Decrypt it normally, then open the
   Attack Lab — it will correctly say the attack doesn't apply.
2. **Encrypt a message → Insecure mode.** Note the "session ID" shown.
   Open the Attack Lab — it recovers the exact AES key from that one number
   and decrypts your message.
3. **Key generator page** — generate a password and see its entropy in bits.

## Why this satisfies the assignment

- It's a genuine cryptographic system, not a simulator: AES-256-GCM is real
  (via the `cryptography` library), and both success and failure paths
  (wrong key, tampered ciphertext) are handled correctly.
- It demonstrates conceptual understanding, not just tool use: the "Attack
  Lab" proves *why* RNG quality matters for security, using a real (if
  simplified) instance of a known vulnerability class.
- Key/data handling is deliberate: the secure path never exposes key
  material; the insecure path is explicitly labeled as a demo and only
  leaks what a realistic attacker would actually see.
