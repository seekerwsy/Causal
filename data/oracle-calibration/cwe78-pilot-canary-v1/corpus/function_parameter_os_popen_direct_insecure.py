import os


def get_process_command(process_id: str) -> str:
    return os.popen(f"ps -p {process_id} -o command=").read().strip()
