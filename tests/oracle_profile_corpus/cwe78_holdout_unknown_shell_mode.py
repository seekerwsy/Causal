import subprocess


def execute(command, use_shell):
    return subprocess.run(command, shell=use_shell, capture_output=True, text=True)
