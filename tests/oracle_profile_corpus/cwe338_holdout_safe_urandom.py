import os


def token():
    return os.urandom(24).hex()
