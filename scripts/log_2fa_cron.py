#!/usr/bin/env python3
# Cron script to log 2FA codes every minute

import os
import time
import hmac
import hashlib
import struct
from datetime import datetime, timezone

SEED_FILE_PATH = "/data/seed.txt"

def load_seed():
    try:
        with open(SEED_FILE_PATH, "r") as f:
            seed_hex = f.read().strip()
            return bytes.fromhex(seed_hex)
    except FileNotFoundError:
        print("Seed file not found")
        return None
    except Exception as e:
        print(f"Error reading seed: {e}")
        return None


def generate_totp(seed, period=30, digits=6):
    now = int(time.time())
    counter = now // period
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


def main():
    seed = load_seed()
    if seed is None:
        return
