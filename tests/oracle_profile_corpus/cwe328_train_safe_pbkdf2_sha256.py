import hashlib
import os


def derive(payload: bytes) -> bytes:
    salt = os.urandom(16)
    return hashlib.pbkdf2_hmac("sha256", payload, salt, 100_000)
