from flask import Flask, request, jsonify
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding
import base64
import os
import time
import hmac
import hashlib
import struct

app = Flask(__name__)

PRIVATE_KEY_FILE = "student_private.pem"
SEED_FILE_PATH = "/data/seed.txt"

# -------------------------------------------------------------------
# Endpoint 1: POST /decrypt-seed
# -------------------------------------------------------------------
@app.post("/decrypt-seed")
def decrypt_seed_api():
    try:
        data = request.get_json()
        encrypted_seed_b64 = data.get("encrypted_seed")

        if not encrypted_seed_b64:
            return jsonify({"error": "Decryption failed"}), 500

        # Load private key
        with open(PRIVATE_KEY_FILE, "rb") as f:
            private_key = serialization.load_pem_private_key(
                f.read(),
                password=None
            )

        # Base64 decode
        encrypted_seed = base64.b64decode(encrypted_seed_b64)

        # RSA OAEP SHA256 decrypt
        decrypted_seed = private_key.decrypt(
            encrypted_seed,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )

        seed_hex = decrypted_seed.decode().strip()

        # Validate 64-character hex
        if len(seed_hex) != 64 or not all(c in "0123456789abcdefABCDEF" for c in seed_hex):
            return jsonify({"error": "Decryption failed"}), 500

        # Save to /data/seed.txt
        os.makedirs("/data", exist_ok=True)
        with open(SEED_FILE_PATH, "w") as f:
            f.write(seed_hex)

        return jsonify({"status": "ok"}), 200

    except Exception:
        return jsonify({"error": "Decryption failed"}), 500


# -------------------------------------------------------------------
# TOTP Helpers
# -------------------------------------------------------------------
def load_seed_bytes():
    if not os.path.exists(SEED_FILE_PATH):
        return None

    with open(SEED_FILE_PATH, "r") as f:
        seed_hex = f.read().strip()

    try:
        return bytes.fromhex(seed_hex)
    except ValueError:
        return None


def generate_totp_code(seed, for_time=None, period=30, digits=6):
    if for_time is None:
        for_time = int(time.time())

    counter = for_time // period
    msg = struct.pack(">Q", counter)

    hmac_digest = hmac.new(seed, msg, hashlib.sha1).digest()
    offset = hmac_digest[-1] & 0x0F

    code_int = (
        ((hmac_digest[offset] & 0x7F) << 24) |
        ((hmac_digest[offset + 1] & 0xFF) << 16) |
        ((hmac_digest[offset + 2] & 0xFF) << 8) |
        (hmac_digest[offset + 3] & 0xFF)
    )

    code_int = code_int % (10 ** digits)
    return f"{code_int:0{digits}d}"


# -------------------------------------------------------------------
# Endpoint 2: GET /generate-2fa
# -------------------------------------------------------------------
@app.get("/generate-2fa")
def generate_2fa():
    seed = load_seed_bytes()
    if seed is None:
        return jsonify({"error": "Seed not decrypted yet"}), 500

    now = int(time.time())
    period = 30

    code = generate_totp_code(seed, now)

    used = now % period
    valid_for = period - 1 - used

    return jsonify({
        "code": code,
        "valid_for": valid_for
    }), 200


# -------------------------------------------------------------------
# Endpoint 3: POST /verify-2fa
# -------------------------------------------------------------------
@app.post("/verify-2fa")
def verify_2fa():
    data = request.get_json(silent=True) or {}
    code = data.get("code")

    if not code:
        return jsonify({"error": "Missing code"}), 400

    seed = load_seed_bytes()
    if seed is None:
        return jsonify({"error": "Seed not decrypted yet"}), 500

    now = int(time.time())
    period = 30

    valid = False
    for offset in (-1, 0, 1):
        t = now + offset * period
        if generate_totp_code(seed, t) == code:
            valid = True
            break

    return jsonify({"valid": valid}), 200


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8080)
