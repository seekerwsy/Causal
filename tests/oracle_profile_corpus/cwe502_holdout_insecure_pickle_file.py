import pickle


def decode(path):
    with open(path, "rb") as stream:
        return pickle.load(stream)
