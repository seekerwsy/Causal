import subprocess


def lookup_process(pid):
    return subprocess.run(f"ps -p {pid}", shell=True, capture_output=True, text=True)
