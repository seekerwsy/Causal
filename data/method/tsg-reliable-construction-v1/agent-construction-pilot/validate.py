"""Bounded compiler feedback for the source-only construction-agent experiment."""
import hashlib
import json
from pathlib import Path
import sys

from prompt_mechanism_study.artifact_io import read_json, write_bundle
from prompt_mechanism_study.source_records import compile_records, structural_readback
from prompt_mechanism_study.prompt_contract import compile_task_context_contract, task_context_contract_record
from prompt_mechanism_study.prompt_tsg import prompt_tsg_record

case = Path(sys.argv[1]).resolve()
number = int(sys.argv[2])
assert 1 <= number <= 3
assert case.parent == Path(__file__).resolve().parent and case.name in {'firmware', 'pandoc', 'book'}
output = case/'checks'/f'attempt-{number}'
assert not output.exists(), 'Do not overwrite a retained attempt.'
assert number == 1 or (case/'checks'/f'attempt-{number-1}').exists()
response = case/f'attempt-{number}.json'
raw = response.read_bytes()
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
    artifacts.update({'contract.json': task_context_contract_record(contract),
                      'graph.json': prompt_tsg_record(graph),
                      'structural-readback.json': structural_readback(request, value)})
except Exception as error:
    result.update(status='COMPILATION_FAILED', error_type=type(error).__name__, error_message=str(error))
write_bundle(output, {**artifacts, 'result.json': result})
print(json.dumps(result))
