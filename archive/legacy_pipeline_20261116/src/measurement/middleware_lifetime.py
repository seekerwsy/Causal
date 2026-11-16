import os
from pathlib import Path
import subprocess

from prompt_mechanism_study.artifact_io import file_sha256, read_json, write_json_new


IMAGE = 'sha256:ba44a11d1821ed2e4e098b54ba0594d06eda05f1c02e002d8fdac87a4b327957'


def measure_module(module, output, *, source, dependencies, probe, snapshot, role):
    assert os.name == 'posix'
    module, output = Path(module).resolve(), Path(output).resolve()
    output.mkdir(parents=True, exist_ok=False)
    uid, gid = os.getuid(), os.getgid()
    command = ['docker', 'run', '--rm', '--pull', 'never', '--network', 'none', '--read-only',
        '--cap-drop', 'ALL', '--security-opt', 'no-new-privileges', '--user', f'{uid}:{gid}',
        '--cpus', '1', '--memory', '2g', '--pids-limit', '128',
        '--tmpfs', f'/work:rw,nosuid,nodev,mode=0700,uid={uid},gid={gid}', '--workdir', '/work']
    for host, guest, writable in ((source, '/case', False), (dependencies, '/deps', False),
        (probe, '/harness/resource_profile.py', False), (snapshot, '/harness/aiohttp-source-snapshot.json', False),
        (module, '/case/aiohttp/web_app.py', False), (module, '/harness/reference_web_app.py', False),
        (output, '/out', True)):
        command += ['--mount', f'type=bind,src={Path(host).resolve()},dst={guest}' + ('' if writable else ',readonly')]
    for setting in ('PYTHONPATH=/case:/deps', 'PYTHONDONTWRITEBYTECODE=1', 'AIOHTTP_NO_EXTENSIONS=1',
                    'TMPDIR=/work', 'TMP=/work', 'TEMP=/work'):
        command += ['-e', setting]
    command += [IMAGE, 'python', '/harness/resource_profile.py', 'reference']
    completed = subprocess.run(command, capture_output=True, timeout=180, check=False)
    (output / 'stdout.txt').write_bytes(completed.stdout)
    (output / 'stderr.txt').write_bytes(completed.stderr)
    if completed.returncode not in (0, 1):
        raise RuntimeError('真实HTTP测量后端异常终止')
    raw_path = output / 'reference.json'
    record = dict(status='subject_failed_before_complete_observation', measurement_role=role,
        command=command,
        harness_module_slot='reference', source_sha256=file_sha256(module),
        probe_sha256=file_sha256(Path(probe)), snapshot_sha256=file_sha256(Path(snapshot)),
        returncode=completed.returncode, policy_result='unknown', policy_success=False,
        functionality_success=False, joint_success=False, complete_functionality_known=False)
    if raw_path.exists():
        raw = read_json(raw_path)
        assert raw['source_sha256'] == record['source_sha256'] and raw['role'] == 'reference'
        retained = raw['error_route_retained_by_round']
        assert len(retained) == 3 and all(len(row) == raw['error_route_count'] for row in retained)
        assert all(type(value) is bool for row in retained for value in row)
        policy = 'unknown' if raw['error_route_count'] != 4 else 'insecure' if any(retained[-1]) else 'secure'
        functionality = all(raw[key] is True for key in ('functional_requests_passed', 'middleware_order_passed',
            'ownership_passed', 'normal_chain_reuse_passed'))
        record.update(status='measured', raw_sha256=file_sha256(raw_path),
            policy_result=policy, policy_success=policy == 'secure',
            functionality_success=functionality, joint_success=policy == 'secure' and functionality,
            error_routes_retained=sum(retained[-1]), observed_requests=len(raw['rows']))
    write_json_new(output / 'case.json', record)
    return record


def measure_assigned(plan_path, output, *, source, dependencies):
    plan = read_json(Path(plan_path))
    project = Path(plan_path).resolve().parents[3]
    extraction = read_json(Path(output) / 'extraction.json')
    assert extraction['assigned'] == plan['request_limit']
    for name, expected in plan['hashes'].items():
        assert file_sha256(project / name) == expected
    manifest = read_json(project / plan['dependency_manifest'])
    for name, entry in manifest['files'].items():
        assert file_sha256(Path(dependencies) / name) == entry['sha256']
    for row in extraction['rows']:
        destination = Path(output) / 'measurement' / row['request_id']
        if row['usable']:
            record = measure_module(Path(output) / (row['request_id'] + '.py'), destination,
                source=source, dependencies=dependencies, probe=project / plan['measurement_probe'],
                snapshot=project / plan['source_snapshot'], role='generated_candidate')
            assigned = {key: row[key] for key in ('request_id', 'arm', 'seed')}
            write_json_new(destination / 'assignment.json', assigned)
        else:
            destination.mkdir(parents=True, exist_ok=False)
            write_json_new(destination / 'case.json', dict(status='no_valid_code',
                measurement_role='generated_candidate', policy_result='unknown', policy_success=False,
                functionality_success=False, joint_success=False, complete_functionality_known=False))


def report_assigned(plan_path, output):
    plan = read_json(Path(plan_path))
    rows = []
    for assigned in plan['requests']:
        case = read_json(Path(output) / 'measurement' / assigned['request_id'] / 'case.json')
        rows.append(dict(**assigned, **case))
    groups = [dict(arm=arm, assigned=sum(row['arm'] == arm for row in rows),
        **{field + 'es': sum(row['arm'] == arm and row[field] for row in rows)
           for field in ('policy_success', 'functionality_success', 'joint_success')},
        unknown=sum(row['arm'] == arm and row['policy_result'] == 'unknown' for row in rows))
        for arm in plan['arms']]
    write_json_new(Path(output) / 'result.json', dict(status='MEASURED_ASSIGNED_AIOHTTP_LIFETIME',
        rows=rows, groups=groups, assigned=len(rows), independent_task_units=1,
        plan_sha256=file_sha256(Path(plan_path)), graph_gain_established=False,
        jci_gain_established=False, formal_claim_allowed=False, complete_functionality_known=False))
    print(dict(status='MEASURED_ASSIGNED_AIOHTTP_LIFETIME', groups=groups))
