from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding
import base64

def decrypt_seed(encrypted_seed_b64: str, private_key_path: str):
    with open(private_key_path, "rb") as f:
        private_key = serialization.load_pem_private_key(
            f.read(),
            password=None,
        )

    encrypted_seed = base64.b64decode(encrypted_seed_b64)

    decrypted = private_key.decrypt(
        encrypted_seed,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    seed = decrypted.decode()

    if len(seed) != 64:
        raise ValueError("Invalid seed length")

    return seed


if _name_ == "_main_":
    encrypted = input("Enter encrypted seed: ").strip()
    seed = decrypt_seed(encrypted, "student_private.pem")
    print("Decrypted Seed:", seed)
