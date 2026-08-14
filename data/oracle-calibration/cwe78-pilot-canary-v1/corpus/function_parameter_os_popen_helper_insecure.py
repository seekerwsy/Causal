import os


def _read_command(command: str) -> str:
    return os.popen(command).read().strip()


def get_process_command(process_id: str) -> str:
    command = f"ps -p {process_id} -o command="
    return _read_command(command)
