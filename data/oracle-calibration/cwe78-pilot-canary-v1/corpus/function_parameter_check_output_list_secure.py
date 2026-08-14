import subprocess


def get_process_command(process_id: str) -> str:
    validated_process_id = str(int(process_id))
    output = subprocess.check_output(
        ("ps", "-p", validated_process_id, "-o", "command="),
        shell=False,
        text=True,
    )
    return output.strip()
