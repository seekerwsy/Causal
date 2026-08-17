import random


def token():
    return str(random.getrandbits(128))
