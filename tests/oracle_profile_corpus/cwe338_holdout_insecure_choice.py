import random


def token(alphabet):
    return "".join(random.choice(alphabet) for _ in range(24))
