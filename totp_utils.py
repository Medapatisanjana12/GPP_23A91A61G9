import base64
import hashlib
import pyotp


def _hex_seed_to_base32(hex_seed: str) -> str:
    """
    Convert 64-character hex seed to a Base32 string for TOTP library.
    """
    # 1. Hex string -> raw bytes
    seed_bytes = bytes.fromhex(hex_seed)

    # 2. Bytes -> base32-encoded string
    b32 = base64.b32encode(seed_bytes).decode("utf-8")

    return b32


def generate_totp_code(hex_seed: str) -> str:
    """
    Generate current TOTP code from hex seed.

    Args:
        hex_seed: 64-character hex string

    Returns:
        6-digit TOTP code as a string (e.g., "123456")
    """
    # Convert hex seed to base32 for TOTP library
    base32_seed = _hex_seed_to_base32(hex_seed)

    # Create TOTP object
    totp = pyotp.TOTP(
        s=base32_seed,
        digits=6,
        interval=30,            # 30-second period
        digest=hashlib.sha1     # Algorithm: SHA-1
    )

    # Generate current TOTP code
    code = totp.now()
    return code


def verify_totp_code(hex_seed: str, code: str, valid_window: int = 1) -> bool:
    """
    Verify TOTP code with time window tolerance.

    Args:
        hex_seed: 64-character hex seed (hex string)
        code: 6-digit TOTP code to verify
        valid_window: number of periods to allow before/after
                      current time (default 1 => ±30s)

    Returns:
        True if code is valid, False otherwise.
    """
    base32_seed = _hex_seed_to_base32(hex_seed)

    # Same TOTP parameters as generation
    totp = pyotp.TOTP(
        s=base32_seed,
        digits=6,
        interval=30,
        digest=hashlib.sha1
    )

    # pyotp's valid_window matches the spec needs
    return totp.verify(code, valid_window=valid_window)


# Optional: simple manual test when running this file directly
if __name__ == "__main__":
    # Replace this with your actual hex seed
    HEX_SEED = "226623e4fe0b481fb28d9a83a58741741636481d5a7e89b0ebeeae69a5cfe535"    
    current_code = generate_totp_code(HEX_SEED)
    print("Current TOTP code:", current_code)

    print("Verification:", verify_totp_code(HEX_SEED, current_code))
