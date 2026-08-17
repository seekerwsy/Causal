import hashlib


def digest(payload, algorithm):
    return hashlib.new(algorithm, payload).hexdigest()
