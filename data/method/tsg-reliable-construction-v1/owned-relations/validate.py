"""Compile one retained construction attempt using this batch's frozen source."""
import hashlib
import json
from pathlib import Path
import sys
import tarfile
import tempfile

BASE = Path(__file__).resolve().parent
case = Path(sys.argv[1]).resolve()
number = int(sys.argv[2])
plan = json.loads((BASE/'protocol/plan.json').read_text(encoding='utf-8'))
assert case.parent == BASE and case.name in {row['run'] for row in plan['cases']}
assert 1 <= number <= plan['maximum_attempts_per_run']
output = case/'checks'/f'attempt-{number}'
assert not output.exists(), 'Retained attempts cannot be overwritten.'
if number > 1:
    previous = json.loads((case/'checks'/f'attempt-{number-1}/result.json').read_text(encoding='utf-8'))
    assert previous['status'] == 'COMPILATION_FAILED', 'Stop at the first successful compile.'
raw = (case/f'attempt-{number}.json').read_bytes()
archive_path = BASE/'execution-source.tar.gz'
assert hashlib.sha256(archive_path.read_bytes()).hexdigest() == plan['execution_source_sha256']
with tempfile.TemporaryDirectory(prefix='tsg-agent-compile-') as directory:
    with tarfile.open(archive_path) as archive:
        archive.extractall(directory, filter='data')
    sys.path.insert(0, str(Path(directory)/'src'))
    from prompt_mechanism_study.artifact_io import read_json, write_bundle
    from prompt_mechanism_study.source_records import compile_records, structural_readback
    from prompt_mechanism_study.prompt_contract import compile_task_context_contract, task_context_contract_record
    from prompt_mechanism_study.prompt_tsg import prompt_tsg_record
    request = read_json(case/'inputs/request.json')
    task = read_json(case/'inputs/task.json')
    catalog = read_json(case/'inputs/catalog.json')
    result = dict(attempt=number, response_sha256=hashlib.sha256(raw).hexdigest(),
                  semantic_correctness_not_certified=True, scientific_claim_allowed=False)
    artifacts = {}
    try:
        value = json.loads(raw)
        contract = compile_records(value, request=request, task=task, catalog=catalog,
            annotator_id='bounded-codex-source-agent', review_status='development_exposed')
        graph = compile_task_context_contract(contract, prompt=task['prompt'], catalog=catalog)
        result['status'] = 'COMPILED_NOT_SEMANTICALLY_CERTIFIED'
        artifacts.update({'contract.json':task_context_contract_record(contract),
                          'graph.json':prompt_tsg_record(graph),
                          'structural-readback.json':structural_readback(request, value)})
    except Exception as error:
        result.update(status='COMPILATION_FAILED', error_type=type(error).__name__, error_message=str(error))
    write_bundle(output, {**artifacts, 'result.json':result})
print(json.dumps(result))
