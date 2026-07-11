import os


def run_command() -> int:
    command = input()
    return os.system(command)
