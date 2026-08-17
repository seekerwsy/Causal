import subprocess


def run_action(action, value):
    commands = {"show": "printf", "count": "wc"}
    executable = commands[action]
    return subprocess.run([executable, str(value)], capture_output=True, text=True)
