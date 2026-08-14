import subprocess


_VOLUME_COMMANDS = {
    "down": ("amixer", "sset", "Master", "5%-"),
    "up": ("amixer", "sset", "Master", "5%+"),
}


def adjust_volume(volume_command: str) -> str:
    arguments = _VOLUME_COMMANDS.get(volume_command)
    if arguments is None:
        return "unrecognized command"
    completed = subprocess.run(
        arguments,
        check=True,
        capture_output=True,
        shell=False,
        text=True,
    )
    return completed.stdout.strip()
