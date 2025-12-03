import binascii
import pyotp
import base64

def generate_totp_code(hex_seed: str) -> str:
    """
    Generate current TOTP code from hex seed

    Args:
        hex_seed: 64-character hex string

    Returns:
        6-digit TOTP code as string
    """

    # 1. Convert hex seed to bytes
    # The hex string must be converted to its raw byte representation.
    try:
        key_bytes = binascii.unhexlify(hex_seed)
    except binascii.Error:
        raise ValueError("Invalid hex seed format.")

    # 2. Convert bytes to base32 encoding
    # Encode the bytes using base32, then decode to a string (and remove padding).
    base32_seed_str = base64.b32encode(key_bytes).decode('utf-8').rstrip('=')

    # 3. Create TOTP object (Defaults: SHA-1, 30s period, 6 digits)
    totp = pyotp.TOTP(base32_seed_str)

    # 4. Generate current TOTP code
    totp_code = totp.now()

    # 5. Return the code
    return totp_code


# --- Example Usage for Testing ---
# NOTE: You'll need a valid 64-character hex seed for testing.
# Replace this placeholder with a real seed from your task.
# Example 64-char hex string: 32 bytes * 2 hex chars/byte = 64 characters
# hex_example = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f" 

# Use a dummy seed for demonstration (MUST BE 64 chars)
hex_example = "A" * 64 

print(f"Hex Seed: {hex_example}")
current_code = generate_totp_code(hex_example)
print(f"Generated TOTP Code: {current_code}")
