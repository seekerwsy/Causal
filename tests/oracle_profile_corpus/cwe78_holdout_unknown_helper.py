import subprocess


def build_command(value):
    return ["printf", "%s", value]


def display(value):
    return subprocess.run(build_command(value), capture_output=True, text=True)
