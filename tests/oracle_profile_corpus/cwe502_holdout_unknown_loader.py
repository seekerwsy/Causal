import yaml


def decode(payload, loader):
    return yaml.load(payload, Loader=loader)
