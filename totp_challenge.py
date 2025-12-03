import binascii
import pyotp
import base64
from time import sleep

# --- Implementation of the Generation Function ---
def generate_totp_code(hex_seed: str) -> str:
    try:
        key_bytes = binascii.unhexlify(hex_seed)
    except binascii.Error:
        raise ValueError("Invalid hex seed format.")
    
    base32_seed_str = base64.b32encode(key_bytes).decode('utf-8').rstrip('=')
    totp = pyotp.TOTP(base32_seed_str)
    totp_code = totp.now()
    return totp_code


# --- Implementation of the Verification Function ---
def verify_totp_code(hex_seed: str, code: str, valid_window: int = 1) -> bool:
    try:
        key_bytes = binascii.unhexlify(hex_seed)
    except binascii.Error:
        raise ValueError("Invalid hex seed format.")

    base32_seed_str = base64.b32encode(key_bytes).decode('utf-8').rstrip('=')
    
    totp = pyotp.TOTP(base32_seed_str)
    is_valid = totp.verify(code, valid_window=valid_window)
    return is_valid


# --- Test Case ---
# NOTE: Use a valid 64-character hex string for the seed
HEX_SEED_EXAMPLE = "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20" 
WINDOW_SIZE = 1 # Allows +/- 30 seconds tolerance

print("--- TOTP Challenge Test ---")
print(f"Seed: {HEX_SEED_EXAMPLE}")

# 1. Generate the current valid code
current_code = generate_totp_code(HEX_SEED_EXAMPLE)
print(f"1. Current Generated Code: {current_code}")

# 2. Test Verification (Should be True)
result_1 = verify_totp_code(HEX_SEED_EXAMPLE, current_code, valid_window=WINDOW_SIZE)
print(f"2. Verification Result (Valid Code): {result_1}")

# 3. Test Verification with Invalid Code (Should be False)
result_2 = verify_totp_code(HEX_SEED_EXAMPLE, "999999", valid_window=WINDOW_SIZE)
print(f"3. Verification Result (Invalid Code): {result_2}")

# 4. Test Verification with Time Window (Optional, but shows tolerance)
# Wait for 35 seconds. The code should now be "expired" but still accepted 
# by the valid_window=1 tolerance (which checks the previous period).
print("\n4. Testing time window tolerance...")
print("    Waiting 35 seconds to test validation of an expired code...")
sleep(35) 
expired_code = current_code # This code is now in the previous period (-1)
result_3 = verify_totp_code(HEX_SEED_EXAMPLE, expired_code, valid_window=WINDOW_SIZE)

print(f"    Code from 35s ago ({expired_code}) is still valid: {result_3}")
print(f"    New current code is: {generate_totp_code(HEX_SEED_EXAMPLE)}")
