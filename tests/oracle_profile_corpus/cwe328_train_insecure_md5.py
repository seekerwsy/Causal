import hashlib


def digest(payload):
    return hashlib.md5(payload).hexdigest()
