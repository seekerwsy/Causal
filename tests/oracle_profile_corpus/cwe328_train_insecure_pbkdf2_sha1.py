import hashlib


def derive(payload: bytes, salt: bytes) -> bytes:
    return hashlib.pbkdf2_hmac("sha1", payload, salt, 100_000)
