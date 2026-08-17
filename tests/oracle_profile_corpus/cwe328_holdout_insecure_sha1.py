import hashlib


def digest(payload):
    return hashlib.sha1(payload).hexdigest()
