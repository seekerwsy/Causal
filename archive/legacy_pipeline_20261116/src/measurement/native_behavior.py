from __future__ import annotations

import json
import subprocess
from pathlib import Path

from prompt_mechanism_study.artifact_io import read_json_exact


def docker_measure(request_path: Path, worker_path: Path, image: str) -> dict:
    payload = read_json_exact(request_path)
    if 'controlled_command' not in payload:
        raise ValueError('当前容器测量需要 controlled_command 输入')
    workspace_megabytes = payload.get('workspace_megabytes', 32)
    if type(workspace_megabytes) is not int or not 32 <= workspace_megabytes <= 128:
        raise ValueError('workspace_megabytes 必须是 [32,128] 内的整数')
    channel_timeout = payload.get('channel_timeout_seconds', 15)
    if type(channel_timeout) is not int or not 1 <= channel_timeout <= 60:
        raise ValueError('channel_timeout_seconds 必须是 [1,60] 内的整数')
    command = [
        'docker', 'run', '--rm', '--network', 'none', '--read-only', '--cap-drop=ALL',
        '--security-opt', 'no-new-privileges', '--user', '65534:65534', '--pids-limit', '64',
        '--memory', '256m', '--cpus', '1', '--tmpfs',
        f'/work:rw,nosuid,nodev,size={workspace_megabytes}m,mode=1777', '-e', 'PHASE_XML_SANDBOX=1',
        '--mount', f'type=bind,src={request_path.resolve()},dst=/request.json,readonly',
        '--mount', f'type=bind,src={worker_path.resolve()},dst=/worker.py,readonly',
        image, 'python', '/worker.py', 'worker', '/request.json',
    ]
    total_timeout = max(90, 20 + channel_timeout * len(payload.get('tests', {})))
    try:
        process = subprocess.run(command, capture_output=True, text=True, timeout=total_timeout)
    except subprocess.TimeoutExpired as error:
        return dict(status='infrastructure_failure', error=str(error))
    if process.returncode:
        return dict(status='infrastructure_failure', exit_code=process.returncode, stderr=process.stderr[-4000:])
    try:
        return json.loads(process.stdout)
    except json.JSONDecodeError as error:
        return dict(status='infrastructure_failure', error=str(error))
