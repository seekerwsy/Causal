import hashlib


def derive(payload: bytes, salt: bytes) -> bytes:
    return hashlib.pbkdf2_hmac("sha512", payload, salt, 120_000)
