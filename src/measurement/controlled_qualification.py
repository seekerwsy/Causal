from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from prompt_mechanism_study.artifact_io import (
    file_sha256, read_json, read_json_exact, verify_bundle, write_bundle, write_json_new,
)
from prompt_mechanism_study.measurement.native_behavior import docker_measure


def controlled_repair_inputs(repo: Path, output: Path):
    root = repo / 'data/method/controlled-semantic-20260930'
    records = read_json(root / 'development-sources/records.json')
    source = root / 'measurement-controls.py'
    inputs = {}
    for family in ('find', 'grep', 'tar', 'git'):
        task = next(row for row in records if row['family'] == family)
        for mode, label in (('secure', 'secure'), ('equivalent', 'secure'), ('insecure', 'insecure'), ('unknown', 'unknown')):
            inputs[f'{family}-{mode}.json'] = dict(code=source.read_text(encoding='utf-8'),
                expected_label=label, expected_functionality='finite_pass' if mode in ('secure', 'equivalent') else None,
                workspace_megabytes=64, evidence_role='EXPOSED_DEVELOPMENT_ORACLE_CHECK',
                controlled_command=dict(blueprint=task['blueprint'], entry_point='solve', probe_seconds=12, control_mode=mode))
    requests = (
        ('controlled-evaluation-318762b46983748cb6d1', 'secure', 'finite_pass'),
        ('controlled-evaluation-5c7d4cda886c470dcbd0', 'unknown', 'finite_fail'),
        ('controlled-evaluation-709b4f4aea60d85bff7d', 'unknown', 'finite_fail'),
        ('controlled-evaluation-bb6784bf201c0048a94d', 'unknown', 'finite_pass'),
        ('controlled-evaluation-a65518b2e7cb5de2aae8', 'unknown', 'finite_fail'),
        ('controlled-evaluation-9c12a37f6beceac846f1', 'unknown', 'finite_fail'),
    )
    for request_id, label, functional in requests:
        folder = repo / 'results/controlled-semantic-20260930/evaluation' / request_id
        request = read_json_exact(folder / 'measurement-request.json')
        if request['code'] != (folder / 'code.py').read_text(encoding='utf-8'):
            raise ValueError('暴露案例的测量代码与原代码不一致')
        inputs[request_id + '.json'] = dict(request, expected_label=label, expected_functionality=functional,
            source_request_id=request_id, source_code_sha256=file_sha256(folder / 'code.py'),
            evidence_role='POST_HOC_EXPOSED_CODE_REMEASUREMENT')
    control = repo / 'data/method/controlled-repair-20261007/target-access-controls.py'
    task = next(row for row in records if row['family'] == 'grep')
    for mode, label in (('child_relative', 'secure'), ('pattern_decoy', 'unknown')):
        inputs['grep-' + mode + '.json'] = dict(code=control.read_text(encoding='utf-8'), expected_label=label,
            expected_functionality=None, workspace_megabytes=64, evidence_role='REAL_TARGET_ACCESS_CONTROL',
            controlled_command=dict(blueprint=task['blueprint'], entry_point='solve', probe_seconds=12, control_mode=mode))
    write_bundle(output, inputs)


def qualify_controlled_observer(inputs: Path, output: Path, worker: Path, image: str, workers: int = 1):
    if workers not in (1, 4):
        raise ValueError('真实控制并行数必须为一或四')
    manifest = verify_bundle(inputs)
    output.mkdir(parents=True, exist_ok=False)

    def one(name):
        request = read_json(inputs / name)
        measured = docker_measure(inputs / name, worker, image)
        write_json_new(output / name, measured)
        matched = (measured['status'] == 'measured'
                   and measured['security_label'] == request['expected_label']
                   and (request['expected_functionality'] is None
                        or measured['functionality'] == request['expected_functionality']))
        result = dict(input=name, matched=matched, status=measured['status'],
                      security_label=measured.get('security_label'), functionality=measured.get('functionality'))
        if not matched:
            raise ValueError(f'真实观察控制未通过: {name}')
        return result

    with ThreadPoolExecutor(max_workers=workers) as executor:
        summary = list(executor.map(one, manifest['files']))
    write_bundle(output / 'verified', {'summary.json': summary, 'identity.json': dict(
        image=image, worker_sha256=file_sha256(worker),
        input_manifest_sha256=file_sha256(inputs / 'manifest.json'))})
    return dict(status='QUALIFIED', cases=len(summary))
