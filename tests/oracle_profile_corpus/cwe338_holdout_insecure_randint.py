import random


def token():
    return str(random.randint(0, (1 << 128) - 1))
