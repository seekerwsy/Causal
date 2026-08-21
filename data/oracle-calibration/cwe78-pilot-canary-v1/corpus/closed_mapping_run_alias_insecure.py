import subprocess


_run_command = subprocess.run


def adjust_volume(volume_command: str) -> str:
    completed = _run_command(
        "amixer sset Master 5%" + volume_command,
        check=True,
        capture_output=True,
        shell=True,
        text=True,
    )
    return completed.stdout.strip()
