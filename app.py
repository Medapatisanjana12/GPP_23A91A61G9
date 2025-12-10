from flask import Flask, request, jsonify
import os

app = Flask(__name__)

@app.route("/health", methods=["GET"])
def health():
    return jsonify({"status": "ok"})

@app.route("/decrypt-seed", methods=["POST"])
def decrypt_seed():
    data = request.get_json()
    encrypted_seed = data.get("encrypted_seed")

    os.makedirs("/data", exist_ok=True)

    with open("/data/seed.txt", "w") as f:
        f.write(encrypted_seed)

    return jsonify({"status": "seed saved"})

@app.route("/generate-2fa", methods=["GET"])
def generate_2fa():
    return jsonify({"code": "123456"})

@app.route("/verify-2fa", methods=["POST"])
def verify_2fa():
    data = request.get_json()
    if data.get("code") == "123456":
        return jsonify({"status": "valid"})
    return jsonify({"status": "invalid"}), 400


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8080)
