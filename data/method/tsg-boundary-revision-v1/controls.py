"""Replay fixed authored boundary records; no model, parsing or semantic gold claim."""
import sys
from pathlib import Path
from prompt_mechanism_study.artifact_io import read_json, write_bundle
from prompt_mechanism_study.prompt_contract_extract import contract_decision_request
from prompt_mechanism_study.prompt_contract import compile_task_context_contract, task_context_contract_record
from prompt_mechanism_study.prompt_tsg import prompt_tsg_record
from prompt_mechanism_study.source_records import record_request, compile_records, structural_readback

base, version, output = Path(sys.argv[1]), sys.argv[2], Path(sys.argv[3])
catalog=read_json(base/version/'inputs/catalog.json')
rows=[]
for case in read_json(base/'controls-inputs/controls.json'):
    task=case['task']
    request=record_request(contract_decision_request(task,catalog))
    records=case[version+'_records']
    contract=compile_records(records,request=request,task=task,catalog=catalog,
        annotator_id='authored-boundary-control',review_status='development_exposed')
    graph=compile_task_context_contract(contract,prompt=task['prompt'],catalog=catalog)
    rows.append(dict(case_id=case['case_id'],contract=task_context_contract_record(contract),
        graph=prompt_tsg_record(graph),readback=structural_readback(request,records)))
write_bundle(output,{'results.json':rows})
