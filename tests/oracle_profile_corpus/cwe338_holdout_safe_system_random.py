import random


def token():
    generator = random.SystemRandom()
    return generator.randrange(1 << 128)
