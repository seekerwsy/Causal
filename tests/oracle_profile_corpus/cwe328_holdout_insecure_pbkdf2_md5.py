import hashlib


def derive(payload: bytes, salt: bytes) -> bytes:
    return hashlib.pbkdf2_hmac("md5", payload, salt, 120_000)
