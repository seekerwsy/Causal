import hashlib


def digest(payload):
    return hashlib.sha256(payload).hexdigest()
