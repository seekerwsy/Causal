import hashlib


def digest(payload):
    return hashlib.new("md5", payload).hexdigest()
