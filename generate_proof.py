from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding
import base64
import subprocess

# -------------------------------------------------
# Sign using RSA-PSS with SHA-256
# -------------------------------------------------
def sign_message(message: str, private_key) -> bytes:
    # 1. Encode as ASCII / UTF-8 bytes
    message_bytes = message.encode("utf-8")

    # 2. Sign with RSA-PSS-SHA256
    signature = private_key.sign(
        message_bytes,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )

    return signature
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding
import base64
import subprocess
import sys

# -------------------------------------------------
# Sign using RSA-PSS with SHA-256
# -------------------------------------------------
def sign_message(message: str, private_key) -> bytes:
    message_bytes = message.encode("utf-8")

    signature = private_key.sign(
        message_bytes,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )

    return signature


# -------------------------------------------------
# Encrypt using RSA-OAEP with SHA-256
# -------------------------------------------------
def encrypt_with_public_key(data: bytes, public_key) -> bytes:
    encrypted = public_key.encrypt(
        data,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return encrypted


def main():
    try:
        # -------------------------------------------------
        # 1. Get latest commit hash (ASCII)
        # -------------------------------------------------
        commit_hash = subprocess.check_output(
            ["git", "log", "-1", "--format=%H"]
        ).decode().strip()

        print("Commit Hash:")
        print(commit_hash)
        print()

        # -------------------------------------------------
        # 2. Load student private key
        # -------------------------------------------------
        with open("student_private.pem", "rb") as f:
            private_key = serialization.load_pem_private_key(
                f.read(),
                password=None
            )

        # -------------------------------------------------
        # 3. Sign commit hash
        # -------------------------------------------------
        signature = sign_message(commit_hash, private_key)

        # -------------------------------------------------
        # 4. Load instructor public key
        # -------------------------------------------------
        with open("instructor_public.pem", "rb") as f:
            public_key = serialization.load_pem_public_key(f.read())

        # -------------------------------------------------
        # 5. Encrypt signature
        # -------------------------------------------------
        encrypted_signature = encrypt_with_public_key(signature, public_key)

        # -------------------------------------------------
        # 6. Base64 encode
        # -------------------------------------------------
        encrypted_signature_b64 = base64.b64encode(encrypted_signature).decode("utf-8")

        print("Encrypted Signature (Base64):")
        print(encrypted_signature_b64)

    except Exception as e:
        print("ERROR:", e)
        sys.exit(1)


if __name__ == "__main__":
    main()
