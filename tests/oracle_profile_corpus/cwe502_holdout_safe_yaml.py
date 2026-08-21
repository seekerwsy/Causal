import yaml


def decode(payload):
    return yaml.safe_load(payload)
