import subprocess


def adjust_volume(volume_command: str) -> str:
    completed = subprocess.run(
        f"amixer sset Master 5%{volume_command}",
        check=True,
        capture_output=True,
        shell=True,
        text=True,
    )
    return completed.stdout.strip()
