import yaml


def decode(payload):
    return yaml.load(payload, Loader=yaml.SafeLoader)
