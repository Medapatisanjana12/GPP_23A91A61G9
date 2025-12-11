import base64
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding


def decrypt_seed(encrypted_seed_b64: str, private_key_path: str) -> str:
    # 1. Load private key
    with open(private_key_path, "rb") as key_file:
        private_key = serialization.load_pem_private_key(
            key_file.read(),
            password=None
        )

    # 2. Base64 decode ciphertext
    encrypted_bytes = base64.b64decode(encrypted_seed_b64)

    # 3. RSA/OAEP Decryption with SHA-256
    decrypted_bytes = private_key.decrypt(
        encrypted_bytes,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    # 4. Convert bytes → UTF-8 string
    seed_str = decrypted_bytes.decode("utf-8")

    # 5. Validate 64-character hex seed
    if len(seed_str) != 64:
        raise ValueError("Invalid seed length")

    if not all(c in "0123456789abcdef" for c in seed_str.lower()):
        raise ValueError("Seed is not valid hexadecimal")

    return seed_str


if __name__ == "__main__":
    # Load encrypted seed from file
    with open("encrypted_seed.txt", "r") as f:
        encrypted_seed = f.read().strip()

    seed = decrypt_seed(encrypted_seed, "student_private.pem")
    print("✅ DECRYPTED SEED:")
    print(seed)
