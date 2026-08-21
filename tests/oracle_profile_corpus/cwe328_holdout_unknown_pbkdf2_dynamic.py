import hashlib


def derive(payload: bytes, salt: bytes, algorithm: str) -> bytes:
    return hashlib.pbkdf2_hmac(algorithm, payload, salt, 120_000)
