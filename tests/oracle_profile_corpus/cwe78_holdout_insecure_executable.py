import subprocess


def run_program(program, argument):
    return subprocess.run([program, argument], capture_output=True, text=True)
