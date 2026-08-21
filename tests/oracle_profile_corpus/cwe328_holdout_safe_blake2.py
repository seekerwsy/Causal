import hashlib


def digest(payload):
    return hashlib.blake2b(payload).hexdigest()
