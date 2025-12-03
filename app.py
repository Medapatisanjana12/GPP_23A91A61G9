import time
import pyotp
from flask import Flask, request, jsonify
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding
import base64
import os
app = Flask(__name__)

PRIVATE_KEY_FILE = "student_private.pem"
SEED_FILE_PATH = "/data/seed.txt"

def decrypt_seed(encrypted_seed_b64: str):
    # Load private key
    with open(PRIVATE_KEY_FILE, "rb") as f:
        private_key = serialization.load_pem_private_key(
            f.read(),
            password=None
        )

    # Base64 decode
    encrypted_seed = base64.b64decode(encrypted_seed_b64)

    # RSA OAEP-SHA256 decrypt
    decrypted = private_key.decrypt(
        encrypted_seed,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    seed = decrypted.decode()

    # Validate length and characters
    if len(seed) != 64 or not all(c in "0123456789abcdefABCDEF" for c in seed):
        raise ValueError("Invalid seed")

    return seed

@app.route('/decrypt-seed', methods=['POST'])
def decrypt_seed_endpoint():
    data = request.json
    if not data or "encrypted_seed" not in data:
        return jsonify({"error": "Missing 'encrypted_seed'"}), 400

    encrypted_seed_b64 = data["encrypted_seed"]

    try:
        seed = decrypt_seed(encrypted_seed_b64)
        # Ensure /data folder exists
        os.makedirs("/data", exist_ok=True)

        # Save seed
        with open(SEED_FILE_PATH, "w") as f:
            f.write(seed)

        return jsonify({"status": "ok"})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

if __name__ == '__main__':
    app.run(host="0.0.0.0", port=5000) 


@app.route('/get/generate-2fa', methods=['GET'])
def generate_2fa():
    seed_file = "/data/seed.txt"

    # Check if seed file exists
    if not os.path.exists(seed_file):
        return jsonify({"error": "Seed file not found"}), 404

    # Read hex seed from file
    with open(seed_file, "r") as f:
        hex_seed = f.read().strip()

    try:
        # Convert hex seed to bytes for TOTP
        seed_bytes = bytes.fromhex(hex_seed)

        # Generate TOTP
        totp = pyotp.TOTP(seed_bytes, digits=6, interval=30)
        code = totp.now()

        # Calculate remaining seconds in current 30-second period
        period = 30
        elapsed = int(time.time()) % period
        valid_for = period - elapsed

        return jsonify({
            "code": code,
            "valid_for": valid_for
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500
