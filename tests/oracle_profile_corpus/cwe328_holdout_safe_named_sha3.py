import hashlib


def digest(payload):
    return hashlib.new("sha3_256", payload).hexdigest()
