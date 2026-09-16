"""Two source-audited API probes; not automatic candidate discovery or qualification."""
from pathlib import Path
import sys,tarfile
from prompt_mechanism_study.artifact_io import read_json, write_bundle, json_object
from prompt_mechanism_study.candidate_construction import candidate_request, compile_candidate_proposal
from prompt_mechanism_study.prompt_contract import task_context_contract_from_record

base,output=Path(sys.argv[1]),Path(sys.argv[2])
task=read_json(base/'inputs/cases.json')[0]['task']
design=dict(outcome_id='oracle_evaluable_secure_code_yield',language_scope=['python'],
 api_scope=['source_audit'],task_archetype_scope=['source_audit'],operations=['add','remove'],
 model_id='offline_boundary_diagnostic',covariate_names=[],support_rule=dict(
 minimum_state_task_units=2,minimum_shared_lineages=1,maximum_unresolved_fraction=.2,minimum_feature_reliability=.8))
results=[]
for version in ('baseline','revised'):
    with tarfile.open(base/version/'results.tar.gz') as archive:
        member=next(m for m in archive.getmembers() if m.name.lstrip('./')=='run/cases/01-single/result.json')
        case=json_object(archive.extractfile(member).read())
    contract=task_context_contract_from_record(case['graph_contract'])
    request=candidate_request([task],[contract],input_catalog=read_json(base/version/'inputs/catalog.json'))
    source=request['sources'][0]
    # This selection locates the already source-audited compound, not a semantic classifier.
    requirement,=[n for n in source['nodes'] if n['node_type']=='safety_requirement'
                  and 'os.system' in n['definition'] and 'subprocess.run' in n['definition']]
    operation,=[e['target_id'] for e in source['edges']
                if e['source_id']==requirement['node_id'] and e['edge_type']=='constrains']
    occurrence=dict(task_id=task['task_id'],requirement_node_ids=[requirement['node_id']],
        scope=dict(operation_node_id=operation,subject_node_ids=[],condition_node_ids=[]))
    response=dict(factors=[dict(label=api,definition=definition,
        atomicity_rationale='Deliberate source-splitting probe; author audit expects rejection of this compound source node.',
        occurrences=[occurrence]) for api,definition in [
        ('os.system','Do not pass user-controlled input to os.system.'),
        ('subprocess.run','Do not pass user-controlled input to subprocess.run with shell=True.')]],
        dispositions=[dict(task_id=task['task_id'],requirement_node_id=n['node_id'],
            status='included' if n['node_id']==requirement['node_id'] else 'not_actionable',
            rationale='Focal fixed probes; other requirements remain non-target constraints.')
            for n in source['nodes'] if n['node_type'] in {'task_requirement','safety_requirement','constraint','presentation_control'}])
    try:
        compile_candidate_proposal(request,response,design)
    except ValueError as error:
        result=dict(version=version,status='SPLIT_REJECTED',error=str(error),
            reference_usable_single_api_factors=2,accepted=0,accepted_correct=0,missed=2,
            actual_prompt_edits=0,edit_status='NOT_RUN_NO_SOURCE_ATOMIC_FACTOR')
    else:
        raise AssertionError('The shared source node was incorrectly split into two candidate meanings.')
    results.append(result)
    write_bundle(output/version,{'request.json':request,'response.json':response,'design.json':design,'result.json':result})
write_bundle(output/'summary',{'results.json':results,'interpretation.json':dict(
    scope='Fixed source-audited diagnostic probes, not automatic candidate discovery.',
    author_review='Both automatic graphs retain a single compound prohibition. Ordinary failure exceptions remain non-target functionality even if a model labels them safety_requirement.',
    edit_gate='No source-faithful independent API factor was accepted; no edit or generated code was produced.')} )
