"""Bounded TSG development: atomic source records, one review and a local patch.

Historical pilot runners are preserved only in their frozen execution archives.
"""
from pathlib import Path
from time import monotonic
import json
import sys
from prompt_mechanism_study.artifact_io import read_json, write_bundle, bundle_digest
from prompt_mechanism_study.records import content_hash
from prompt_mechanism_study.functional_judge import bailian_complete


def run(base, output):
    from prompt_mechanism_study.prompt_contract import task_context_contract_record
    from prompt_mechanism_study.prompt_tsg import prompt_tsg_record
    inputs=base/'inputs';plan=read_json(inputs/'plan.json')
    assert not output.exists();output.mkdir(parents=True)
    evaluators=read_json(inputs/'evaluators.json');catalog=read_json(inputs/'catalog.json')
    instruction=read_json(inputs/'instructions.json')['system_prompt']
    rows=read_json(inputs/'cases.json')
    from prompt_mechanism_study.prompt_contract_extract import _attempt_source_graph, _assess_candidate_scopes
    name,=evaluators;calls=[];results=[];debited=0
    conditions=plan.get('conditions', ['single'])
    assert conditions == ['single']
    assert plan['fresh_complete'] and plan['atomic_source_records']
    assert not any(any(k.startswith('cached_') for k in row) for row in rows)
    assert 5*len(rows)<=plan['maximum_provider_calls']
    shared={};reuse=[]
    original_prompt=read_json(inputs/'instructions.json').get('stage_system_prompt') or Path('data/method/open-tsg-annotator-v15.md').read_text(encoding='utf-8').strip()
    def deliver(request,config,prompt,continuation=(), *, share=False):
        nonlocal debited
        schema=config['response_format'].get('json_schema',{}).get('schema')
        delivered_prompt=prompt
        # Keep native schema only for inventory. The fixed-draft delivery
        # control recovered missing binding arrays in ordinary JSON mode.
        native_schema=plan.get('native_response_schema') and request['request_kind']=='source_only_atomic_records'
        if schema and (not native_schema or plan.get('schema_in_prompt')):
            delivered_prompt+='\n\nReturn a JSON object conforming to this response schema. The schema describes output structure, not additional source facts:\n'+json.dumps(schema,ensure_ascii=False,separators=(',',':'))
        delivered_config=config if native_schema else {**config,'response_format':{'type':'json_object'}}
        identity=content_hash(dict(request=request,evaluator=delivered_config,
            system_prompt=delivered_prompt,continuation=list(continuation)))
        if share and condition_index:
            if identity not in shared:
                raise RuntimeError('The paired condition changed a shared request.')
            saved, failure=shared[identity]
            reuse.append(dict(task_id=row['task']['task_id'],condition=condition,
                source_call=saved['ordinal'],request_identity=identity))
            if failure is not None: raise failure
            return saved['response_text'].encode()
        assert len(calls)<plan['maximum_provider_calls']
        cap=plan['per_call_conservative_cost_microunits']
        if debited+cap>plan['maximum_conservative_cost_microunits']:
            raise RuntimeError('The frozen batch budget cannot reserve another provider call.')
        record=dict(task_id=row['task']['task_id'],condition='shared' if share else condition,
            ordinal=len(calls)+1,request_identity=identity,request=request,
            evaluator=delivered_config,system_prompt=delivered_prompt,trace={},response_text=None,error=None)
        failure=None
        started=monotonic()
        if continuation:record['continuation']=continuation
        if plan.get('source_first_delivery'):record['source_first_delivery']=True
        calls.append(record)
        try:
            options=dict(trace=lambda kind,value:record['trace'].update({kind:value.decode('utf-8')}))
            if continuation:options['continuation']=continuation
            if plan.get('source_first_delivery'):options['source_first_delivery']=True
            raw=bailian_complete(request,delivered_config,delivered_prompt,**options)
            record['response_text']=raw.decode();return raw
        except Exception as error:
            failure=error
            record['error']=dict(type=type(error).__name__,message=str(error));raise
        finally:
            # Reserve the full per-call ceiling; release only conservatively
            # verified usage. Budget exhaustion retains every unfinished case.
            charge=cap
            try:
                envelope=json.loads(record['trace']['response']);usage=envelope['usage']
                pt,ct=usage['prompt_tokens'],usage['completion_tokens'];rates=plan['cost_accounting']
                amount=pt*rates['input_microunits_per_token']+ct*rates['output_microunits_per_token']
                if (record['error'] is None and type(pt) is int and type(ct) is int
                    and 0<pt<=config['maximum_input_bytes'] and 0<ct<=config['maximum_completion_tokens']
                    and envelope['model']==config['model_id']
                    and envelope['choices'][0]['finish_reason']=='stop' and amount<=cap):
                    charge=amount
            except (KeyError,TypeError,ValueError,IndexError):
                pass
            debited+=charge
            record['conservative_cost_microunits']=charge
            record['elapsed_seconds']=round(monotonic()-started,3)
            if share:shared[identity]=(record,failure)
            write_bundle(output/'calls'/f'{len(calls):02d}',{'call.json':record})
            print(f'{record["ordinal"]} {record["condition"]} {request["request_kind"]}: {record["error"] or "response retained"}; debit={debited/1e6:.6f}',flush=True)
    def complete(request,config,prompt):
        return deliver(request,config,instruction)
    for case_index,row in enumerate(rows):
        order=conditions if case_index%2==0 else list(reversed(conditions))
        shared.clear()
        for condition_index,condition in enumerate(order):
            before=len(calls)
            graph_attempt=_attempt_source_graph(row['task'],catalog=catalog,evaluator=evaluators[name],
                annotator_prompt=original_prompt,review_status='development_exposed',provider=complete)
            # Candidate scopes follow the graph; source semantics are immutable across this boundary.
            attempt=_assess_candidate_scopes(graph_attempt,task=row['task'],catalog=catalog,
                evaluator=evaluators[name],annotator_prompt=original_prompt,provider=complete)
            record=dict(task_id=attempt.task_id,condition=condition,
                graph_contract=task_context_contract_record(graph_attempt.contract) if graph_attempt.contract else None,
                source_graph=prompt_tsg_record(graph_attempt.graph) if graph_attempt.graph else None,
                graph_error_type=graph_attempt.error_type,graph_error_message=graph_attempt.error_message,
                contract=task_context_contract_record(attempt.contract) if attempt.contract else None,
                graph=prompt_tsg_record(attempt.graph) if attempt.graph else None,binding_annotation=attempt.binding_annotation,
                scope_assessment=attempt.scope_assessment,error_type=attempt.error_type,error_message=attempt.error_message)
            if graph_attempt.succeeded and attempt.succeeded:
                for field in ('facts','relations','source_inventory'):
                    assert record['graph_contract'][field]==record['contract'][field]
            results.append(record)
            write_bundle(output/'cases'/f'{case_index+1:02d}-{condition}',{'result.json':record})
            print(f'CASE {case_index+1} {condition}: {attempt.error_type or "closed"}; fresh_calls={len(calls)-before}',flush=True)
    write_bundle(output/'summary',{'results.json':results,'reuse.json':reuse,'report.json':dict(
        actual_provider_calls=len(calls),actual_conservative_cost_microunits=debited,
        input_bundle_sha256=bundle_digest(inputs),conditions=conditions,
        fresh_shared_drafts=True,paired_conditions_share_upstream=len(conditions)==2,
        scientific_claim_allowed=False)})


if __name__ == '__main__':
    run(Path(sys.argv[1]),Path(sys.argv[2]))
