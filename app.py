"""
app.py
RNG Analyser -- a small working cryptographic system.

Routes:
    /                request        -> home / overview
    /encrypt         GET, POST      -> encrypt a message (secure or insecure RNG mode)
    /decrypt/<id>    GET            -> legitimate decrypt (as the intended recipient)
    /attack/<id>     GET            -> attacker simulation (only uses the leaked session id)
    /keygen          GET, POST      -> secure password/key generator with entropy display

Note on storage: `VAULT` is an in-memory dict simulating a server-side
store of encrypted messages. This is intentional for a demo/coursework
system running on a single process -- a production system would use a
real database, but that is not the cryptographic concept under test here.
"""

import secrets as py_secrets
import string
import uuid

from flask import Flask, render_template, request, redirect, url_for, flash

from crypto_utils import encrypt, decrypt, KEY_SIZE, NONCE_SIZE
from rng_utils import SecureRNG, derive_insecure_key_and_nonce, attacker_recover_key_and_nonce
from entropy_utils import shannon_entropy_bits, keyspace_bits, strength_label
from cryptography.exceptions import InvalidTag

app = Flask(__name__)
app.secret_key = py_secrets.token_hex(16)  # only used to sign flash-message cookies

# In-memory "vault" of encrypted messages: {id: {...}}
VAULT = {}


@app.route("/")
def home():
    return render_template("index.html")


@app.route("/encrypt", methods=["GET", "POST"])
def encrypt_message():
    if request.method == "POST":
        plaintext = request.form.get("plaintext", "").strip()
        mode = request.form.get("mode", "secure")

        if not plaintext:
            flash("Enter a message to encrypt.", "error")
            return redirect(url_for("encrypt_message"))

        session_id = None
        if mode == "secure":
            key = SecureRNG.generate_key(KEY_SIZE)
            nonce = SecureRNG.generate_nonce(NONCE_SIZE)
        else:
            seed = py_secrets.randbelow(2 ** 31)  # simulates e.g. a predictable time-based seed
            session_id, key, nonce = derive_insecure_key_and_nonce(seed)

        ciphertext = encrypt(plaintext, key, nonce)
        result_id = uuid.uuid4().hex[:10]
        VAULT[result_id] = {
            "ciphertext": ciphertext,
            "key": key,
            "nonce": nonce,
            "mode": mode,
            "session_id": session_id,
        }
        return redirect(url_for("view_result", result_id=result_id))

    return render_template("encrypt.html")


@app.route("/result/<result_id>")
def view_result(result_id):
    entry = VAULT.get(result_id)
    if entry is None:
        flash("That vault entry does not exist (server may have restarted).", "error")
        return redirect(url_for("encrypt_message"))
    return render_template("result.html", result_id=result_id, entry=entry)


@app.route("/decrypt/<result_id>")
def decrypt_message(result_id):
    """Legitimate decryption path: as if this were the intended recipient with proper key access."""
    entry = VAULT.get(result_id)
    if entry is None:
        flash("That vault entry does not exist.", "error")
        return redirect(url_for("encrypt_message"))

    try:
        plaintext = decrypt(entry["ciphertext"], entry["key"], entry["nonce"])
        error = None
    except InvalidTag:
        plaintext = None
        error = "Decryption failed: key/nonce mismatch or tampered ciphertext."

    return render_template("decrypt.html", result_id=result_id, entry=entry,
                            plaintext=plaintext, error=error)


@app.route("/attack/<result_id>")
def attack_simulation(result_id):
    """
    Attacker simulation: deliberately only uses `ciphertext` and `session_id`
    -- the two things that would realistically be visible to an outside
    observer (e.g. captured on the network or read from a log file) -- and
    never touches the real stored key directly.
    """
    entry = VAULT.get(result_id)
    if entry is None:
        flash("That vault entry does not exist.", "error")
        return redirect(url_for("encrypt_message"))

    if entry["mode"] != "insecure" or entry["session_id"] is None:
        return render_template("attack.html", result_id=result_id, entry=entry,
                                possible=False, plaintext=None)

    recovered_key, recovered_nonce = attacker_recover_key_and_nonce(entry["session_id"])
    try:
        plaintext = decrypt(entry["ciphertext"], recovered_key, recovered_nonce)
    except InvalidTag:
        plaintext = None

    return render_template("attack.html", result_id=result_id, entry=entry,
                            possible=True, plaintext=plaintext,
                            recovered_key=recovered_key.hex())


@app.route("/keygen", methods=["GET", "POST"])
def keygen():
    password = None
    bits = None
    theoretical_bits = None
    label = None
    length = 16

    if request.method == "POST":
        length = max(4, min(128, int(request.form.get("length", 16))))
        use_symbols = request.form.get("symbols") == "on"

        charset = string.ascii_letters + string.digits
        if use_symbols:
            charset += "!@#$%^&*()-_=+"

        password = "".join(py_secrets.choice(charset) for _ in range(length))
        bits = shannon_entropy_bits(password) * length  # observed, for this specific string
        theoretical_bits = keyspace_bits(len(charset), length)  # theoretical, for the charset/length
        label = strength_label(theoretical_bits)

    return render_template("keygen.html", password=password, bits=bits,
                            theoretical_bits=theoretical_bits, label=label, length=length)


if __name__ == "__main__":
   
    import os

    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port)
