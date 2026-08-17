import subprocess


def lookup_process(pid):
    return subprocess.run(["ps", "-p", str(pid)], capture_output=True, text=True)
