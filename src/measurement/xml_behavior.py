"""Shared isolated-container call used by the current behavior measurements.

Historical task-ID XML/file probes are archived with the completed studies.
Only the Docker adapter remains here; it never executes generated code on the host.
"""
from __future__ import annotations

import json
from pathlib import Path
import subprocess


def docker_measure(request_path: Path, worker_path: Path, image: str) -> dict:
    """Linux host adapter. No host paths other than one request and this worker."""
    access_probe = bool(json.loads(request_path.read_text(encoding='utf-8')).get('file_access'))
    # The trusted access worker switches identities inside an isolated container.
    # Generated code always drops UID/GID and every capability before execution.
    identity = (["--user", "0:0", "--cap-add=SETUID", "--cap-add=SETGID",
                 "--cap-add=CHOWN", "--cap-add=FOWNER", "--cap-add=DAC_OVERRIDE"]
                if access_probe else ["--user", "65534:65534"])
    command = ["docker", "run", "--rm", "--network", "none", "--read-only", "--cap-drop=ALL",
               "--security-opt", "no-new-privileges", *identity, "--pids-limit", "64",
               "--memory", "256m", "--cpus", "1", "--tmpfs", "/work:rw,nosuid,nodev,size=32m,mode=1777",
               "-e", "PHASE_XML_SANDBOX=1", "--mount", f"type=bind,src={request_path.resolve()},dst=/request.json,readonly",
               "--mount", f"type=bind,src={worker_path.resolve()},dst=/worker.py,readonly", image,
               "python", "/worker.py", "worker", "/request.json"]
    try:
        process = subprocess.run(command, capture_output=True, text=True, timeout=90)
        if process.returncode:
            return {"status": "infrastructure_failure", "exit_code": process.returncode, "stderr": process.stderr[-4000:]}
        return json.loads(process.stdout)
    except (subprocess.TimeoutExpired, json.JSONDecodeError) as error:
        return {"status": "infrastructure_failure", "error": str(error)}
