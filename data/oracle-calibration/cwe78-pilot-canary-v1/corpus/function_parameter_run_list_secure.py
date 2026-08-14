import subprocess


def get_process_command(process_id: str) -> str:
    validated_process_id = str(int(process_id))
    completed = subprocess.run(
        ["ps", "-p", validated_process_id, "-o", "command="],
        check=True,
        capture_output=True,
        shell=False,
        text=True,
    )
    return completed.stdout.strip()
