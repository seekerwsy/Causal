"""Replay this fixed author-annotated diagnostic through existing TSG/edit code.

Not an extractor, gold annotator, alternative study runner or Discovery sample.
Usage: python replay.py NEW_OUTPUT_DIRECTORY
"""
import json
import sys
from collections import Counter
from copy import deepcopy
from dataclasses import asdict, replace
from pathlib import Path

from prompt_mechanism_study.artifact_io import read_json, write_bundle, verify_bundle
from prompt_mechanism_study.prompt_contract import (
    open_concept_catalog, compile_task_context_contract, task_context_contract_record,
)
from prompt_mechanism_study.prompt_contract_extract import contract_decision_request
from prompt_mechanism_study.source_records import record_request, compile_records, structural_readback
from prompt_mechanism_study.prompt_tsg import prompt_tsg_record, FeatureScope
from prompt_mechanism_study.mechanisms import bind_task_hypothesis, render_task_hypothesis
from prompt_mechanism_study.records import content_hash
from prompt_mechanism_study.task_input import generation_input_for_prompt, prepare_task_input

ROOT = Path(__file__).resolve().parent


def authored_records(annotation, request):
    units = request['source_units']
    result = dict(objects=[], operations=[], requirements=[], coverage={}, unit_impacts={},
                  unresolved_notes=[annotation['scope_blocker']] if annotation.get('unresolved_units') else [])

    def cite(unit, quote):
        assert units[unit]['evidence_text'].count(quote) == 1, (unit, quote)
        return dict(evidence_source_unit=unit, evidence_text=quote)

    def fact(key, meaning, unit, quote, kind, layer='runtime'):
        return dict(**cite(unit, quote), source_units=[unit], layer=layer,
                    concept=dict(concept_id='author.'+key, node_type=kind, definition=meaning))

    def condition(guard, unit):
        quote, meaning = guard
        return fact('guard', meaning, unit, quote, 'condition')

    objects = {o[0]: o for o in annotation['objects']}
    for key, meaning, unit, quote, *layer in annotation['objects']:
        result['objects'].append(dict(record_id=key, fact=fact(key, meaning, unit, quote,
                                     'data_object', layer[0] if layer else 'runtime')))
    for unit in annotation.get('generation_units', []):
        text = units[unit]['evidence_text']
        if text.startswith(('Only return', 'such as')):
            continue  # The higher-priority system already specifies the effective output envelope.
        key = 'declaration_'+unit
        result['objects'].append(dict(record_id=key, fact=fact(key,
            'Supplied generation scaffold: '+text, unit, text, 'data_object', 'generation')))
    for key, meaning, unit, quote, inputs, outputs, *guard in annotation['operations']:
        f = fact(key, meaning, unit, quote, 'task_operation')
        f['source_units'] = sorted({unit, *(objects[s.split(':')[0]][2] for s in inputs),
                                   *(objects[s][2] for s in outputs)})
        result['operations'].append(dict(record_id=key, fact=f,
            inputs=[dict(subject=s.split(':')[0], role=s.split(':')[1],
                         **cite(unit, quote)) for s in inputs],
            results=[dict(subject=s, **cite(unit, quote)) for s in outputs],
            execution_conditions=[condition(guard[0], unit)] if guard else [],
            scope_conditions=[], precedes=[]))
    for key, meaning, unit, quote, targets, *guard in annotation['requirements']:
        result['requirements'].append(dict(record_id=key,
            fact=fact(key, meaning, unit, quote, 'task_requirement'), modality='obligation',
            structure=dict(kind='atom', members=[]), scope_kind='targets',
            operations=targets, subjects=[], target_class=None,
            conditions=[condition(guard[0], unit)] if guard else [], relations=[]))
    operations = {r['record_id']:r for r in result['operations']}
    for key, meaning, unit, quote, before, after in annotation.get('order_requirements', []):
        f = fact(key, meaning, unit, quote, 'task_requirement')
        f['source_units'] = sorted({unit, *operations[before]['fact']['source_units'],
                                   *operations[after]['fact']['source_units']})
        result['requirements'].append(dict(record_id=key, fact=f, modality='obligation',
            structure=dict(kind='atom', members=[]), scope_kind='targets', operations=[after],
            subjects=[], target_class=None, conditions=[],
            relations=[dict(source=before, target=after, edge_type='precedes', **cite(unit,quote))]))
    for unit, source in units.items():
        records = [r for group in ('objects','operations','requirements') for r in result[group]
                   if unit in r['fact']['source_units']]
        status = ('unresolved' if unit in annotation.get('unresolved_units', []) else
                  'represented' if records else 'no_task_fact')
        reason = annotation.get('scope_blocker') if status == 'unresolved' else (
            'Author source review: the cited records preserve this source clause.' if records else
            'Delimiter or generation wording; the effective system output/interface template is retained.')
        result['coverage'][unit] = dict(status=status, reason=reason)
        affected = sorted({r['record_id'] for r in result['operations'] if unit in r['fact']['source_units']}
                          | {target for r in result['requirements'] if unit in r['fact']['source_units']
                             for target in r['operations']})
        effect = 'unresolved' if status == 'unresolved' else 'local' if affected else 'no_runtime_effect'
        result['unit_impacts'][unit] = dict(effect=effect,
            operations=affected if effect=='local' else [], reason=reason,
            **cite(unit, source['evidence_text']))
    return result


def discovery_support(results):
    """Use the actual pre-outcome fold constructor; never invent a positive state."""
    from prompt_mechanism_study.prioritization import AtomicPreOutcomeObservation, _atomic_candidate_fold_manifest
    from prompt_mechanism_study.representation import Operation
    evidence=[]
    for policy in sorted({r['policy_id'] for r in results}):
        group=[r for r in results if r['policy_id']==policy]
        rows=tuple(AtomicPreOutcomeObservation(r['task_id'], 'saved-baseline-diagnostic', policy, 0,
            ((policy,0),), (), content_hash(r['scope']), ((policy,()),))
            for r in group if r['comparison_state']=='absent')
        record=dict(policy_id=policy, total_task_units=len(group), natural_zero=len(rows),
            natural_one=0, unresolved=len(group)-len(rows), cross_fit_folds=4, fold_seed=2026091801,
            outcome_read=False)
        try:
            frozen=_atomic_candidate_fold_manifest(policy,Operation.ADD,rows,4,2026091801)
            record.update(status='FOLDS_BUILT', manifest=asdict(frozen))
        except ValueError as error:
            record.update(status='BLOCKED', reason=str(error))
        evidence.append(record)
    return evidence


def replay_baselines(tasks, output):
    """Remeasure exact saved baseline replies, retaining all 12 task units."""
    from prompt_mechanism_study.measurement import measure_generated_code, MeasurementExecutionError, MeasurementLedger
    from prompt_mechanism_study.target_security_profiles import evaluate_target_security_profile
    from prompt_mechanism_study.outcomes import derive_outcomes
    verify_bundle(ROOT/'baseline-inputs')
    plan=read_json(ROOT/'baseline-inputs/plan.json')
    rows={r['task_id']:r for r in read_json(ROOT/'baseline-inputs/responses.json')}
    results=[]
    for task in tasks:
        row=rows[task['task_id']]
        calls=[]

        def complete(request, evaluator, prompt):
            if request==row['generation_request'] and prompt==task['generation_input']['system_prompt']:
                calls.append('saved_generation')
                return row['generation_response'].encode()
            if request==row['functional_request'] and prompt==plan['functional_system_prompt']:
                calls.append('saved_functional_review')
                return row['functional_response'].encode()
            raise MeasurementExecutionError('Saved reply cannot be rebound to a changed request.')

        assert row['generation_request']==task['generation_input']['request']
        measurement,evidence=measure_generated_code(
            assignment_id=row['original_assignment_id'], generation_request=row['generation_request'],
            generation_evaluator=plan['generator'], generation_prompt=task['generation_input']['system_prompt'],
            source_task_prompt=task['prompt'], functional_contract=task['functional_contract'],
            functional_evaluator=plan['functional_evaluator'], functional_prompt=plan['functional_system_prompt'],
            security_profile_id=row['security_profile_id'], complete=complete,
            security_evaluate=evaluate_target_security_profile)
        outcome=derive_outcomes(MeasurementLedger('manual-graph-baseline-replay',content_hash(row),
            'saved-responses-only',(measurement,)))[0]
        results.append(dict(task_id=task['task_id'], measurement=asdict(measurement),outcome=asdict(outcome),
                            evidence=evidence, saved_callbacks=calls))
    write_bundle(output/'baseline-measurement',{'results.json':results})
    return dict(task_units=len(results), provider_calls=0, new_generations=0,
        code_status=dict(Counter(r['measurement']['code_status'] for r in results)),
        security_status=dict(Counter(r['measurement']['oracle_status'] for r in results)),
        functional_status=dict(Counter(r['measurement']['functional_status'] for r in results)),
        limitation=plan['limitation'])


def edited_reference(task, annotation, policy, source_records, original_request, edited):
    """Authored positive counterpart, never a new natural task or model output."""
    actual=generation_input_for_prompt(task, edited)
    variant=prepare_task_input(dict(task_id=task['task_id'],language=task['language'],
        prompt=actual['request']['task'],generation_system_prompt=actual['system_prompt']))
    assert variant['prompt']==edited
    catalog=open_concept_catalog()
    feature=policy['feature_id']
    definition=policy.get('factor_definition',{}).get('definition',policy['addition'])
    catalog['semantics'][feature]='safety_requirement'
    catalog['semantic_guidance'][feature]=definition
    request=record_request(contract_decision_request(variant,catalog))
    records=deepcopy(source_records)
    new_units={k:v for k,v in request['source_units'].items() if k not in original_request['source_units']}
    assert all(request['source_units'][k]==v for k,v in original_request['source_units'].items())
    containing=[k for k,v in new_units.items() if policy['addition'] in v['evidence_text']]
    assert len(containing)==1
    unit=containing[0]
    records['requirements'].append(dict(record_id='added_policy',
        fact=dict(evidence_source_unit=unit,evidence_text=policy['addition'],source_units=[unit],
                  layer='runtime',concept=dict(concept_id=feature,node_type='safety_requirement',definition=definition)),
        modality='obligation',structure=dict(kind='atom',members=[]),scope_kind='targets',
        operations=['target'],subjects=annotation['subjects'],target_class=None,conditions=[],relations=[]))
    for key,value in new_units.items():
        records['coverage'][key]=dict(status='represented' if key==unit else 'no_task_fact',
            reason='The rendered scope heading locates the appended policy; only its complete instruction adds an obligation.')
        records['unit_impacts'][key]=dict(effect='local',operations=['target'],
            reason='Appended single scoped policy and its location heading.',
            evidence_source_unit=key,evidence_text=value['evidence_text'])
    contract=compile_records(records,request=request,task=variant,catalog=catalog,
        annotator_id='codex-authored-edited-counterpart',review_status='development_exposed')
    ordered=[r for group in ('objects','operations','requirements') for r in records[group]]
    aliases={r['record_id']:f'fact.{i}' for i,r in enumerate(ordered,1)}
    contract=replace(contract,feature_states=(dict(target=aliases['target'],concept_id=feature,state='present',
        rationale='The generated ADD instruction is explicitly present at this authored scope.',
        subjects=sorted(aliases[s] for s in annotation['subjects']),conditions=[],requirements=[aliases['added_policy']]),))
    graph=compile_task_context_contract(contract,prompt=edited,catalog=catalog)
    assert graph.scoped_feature_assessments[0].state=='present'
    return dict(task=variant,records=records,contract=task_context_contract_record(contract),
                graph=prompt_tsg_record(graph),natural_observation=False,model_extraction=False)


def run(output):
    verify_bundle(ROOT/'inputs')
    tasks, annotations = read_json(ROOT/'inputs/tasks.json'), read_json(ROOT/'annotations.json')
    policies = {p['policy_id']:p for p in read_json(ROOT/'inputs/policies.json')}
    plan = read_json(ROOT/'inputs/plan.json')
    assert [t['task_id'] for t in tasks] == plan['task_ids'] and len(tasks)==len(annotations)==12
    if output.exists(): raise FileExistsError(output)
    results = []
    for index, (task, annotation) in enumerate(zip(tasks, annotations, strict=True), 1):
        catalog = open_concept_catalog()
        policy = deepcopy(policies[task['policy_id']])
        feature = policy['feature_id']
        catalog['semantics'][feature] = 'safety_requirement'
        catalog['semantic_guidance'][feature] = policy.get('factor_definition', {}).get('definition', policy['addition'])
        request = record_request(contract_decision_request(task, catalog))
        records = authored_records(annotation, request)
        contract = compile_records(records, request=request, task=task, catalog=catalog,
            annotator_id='codex-author-source-reference-not-independent-gold', review_status='development_exposed')
        ordered = [r for group in ('objects','operations','requirements') for r in records[group]]
        aliases = {r['record_id']:f'fact.{i}' for i,r in enumerate(ordered,1)}
        contract = replace(contract, feature_states=(dict(target=aliases['target'], concept_id=feature,
            state='unresolved' if annotation.get('scope_blocker') else 'absent',
            rationale=annotation.get('scope_blocker', 'Author read the complete effective source: this scoped safety instruction is not expressed. This is not a claim about generated protection.'),
            subjects=sorted(aliases[s] for s in annotation['subjects']), conditions=[], requirements=[]),))
        graph = compile_task_context_contract(contract, prompt=task['prompt'], catalog=catalog)
        assessment = graph.scoped_feature_assessments[0]
        scope = assessment.scope
        nodes = {n.node_id:n for n in graph.nodes}
        operation = nodes[scope.operation_node_id]
        query = dict(policy['query'], required_semantics=[operation.semantic_id],
            required_relations=[], forbidden_semantics=[])
        diagnostic = dict(case=index, name=annotation['name'], task_id=task['task_id'],
            policy_id=policy['policy_id'], graph_compiled=True,
            natural_expression='not_expressed', comparison_state=assessment.state,
            scope_blocker=annotation.get('scope_blocker'), author_review=annotation['review'],
            nodes=len(graph.nodes), edges=len(graph.edges), scope=asdict(scope),
            binding_status=None, edit_status=None, scientific_claim_allowed=False)
        artifacts = {'records.json':records, 'contract.json':task_context_contract_record(contract),
                     'graph.json':prompt_tsg_record(graph), 'source-request.json':request,
                     'structural-readback.json':structural_readback(request, records)}
        try:
            binding = bind_task_hypothesis(graph, query=query, policy_id=policy['policy_id'],
                factor_feature_ids=(feature,), factor_operations=('add',), factor_scopes=(scope,))
            diagnostic['binding_status']='BOUND'
            artifacts['binding.json']=asdict(binding)
            variants = {}
            for arm in ('NOOP','STYLE','GENERIC','TARGET'):
                rendered = render_task_hypothesis(binding, graph, prompt=task['prompt'],
                    catalog=contract.catalog, enabled=(arm=='TARGET',), additions={feature:policy['addition']},
                    inactive_texts={} if arm=='TARGET' else {feature:task['control_texts'][arm]})
                edited = rendered['prompt']
                # ADD is a suffix edit: the entire original effective input must survive byte-for-byte.
                assert edited.startswith(task['prompt'])
                assert content_hash(task['prompt']) == task['prompt_sha256']
                actual_input = generation_input_for_prompt(task, edited)
                assert actual_input['system_prompt']==task['generation_input']['system_prompt']
                variants[arm]=dict(prompt=edited, prompt_sha256=content_hash(edited),
                                   generation_input=actual_input, edit=rendered)
            artifacts['variants.json']=variants
            artifacts['edited-reference.json']=edited_reference(task,annotation,policy,records,request,
                                                               variants['TARGET']['prompt'])
            diagnostic['edit_status']='FOUR_ARMS_RENDERED_SOURCE_PRESERVED'
            diagnostic['authored_edited_state']='present'
        except ValueError as error:
            diagnostic['binding_status']=diagnostic['binding_status'] or 'BLOCKED'
            diagnostic['edit_status']='BLOCKED'
            diagnostic['error']=dict(type=type(error).__name__, message=str(error))
        artifacts['result.json']=diagnostic
        write_bundle(output/f'case-{index:02}', artifacts)
        results.append(diagnostic)
        print(index, diagnostic['comparison_state'], diagnostic['binding_status'], diagnostic['edit_status'])
    supports=discovery_support(results)
    measured=replay_baselines(tasks, output)
    summary = dict(status='AUTHORED_GRAPH_DOWNSTREAM_DIAGNOSTIC', scientific_claim_allowed=False,
        annotation_sha256=content_hash(annotations), source_plan_sha256=content_hash(plan),
        cases=results, compile_count=sum(r['graph_compiled'] for r in results),
        binding_counts=dict(Counter(r['binding_status'] for r in results)),
        edit_counts=dict(Counter(r['edit_status'] for r in results)), provider_calls=0,
        natural_discovery_status='BLOCKED_NO_NATURAL_POSITIVE_STATE',
        natural_discovery_reason='All original focal requirements remain unexpressed. Edited arms are not natural observations; two unclear invocation scopes remain unresolved.',
        actual_fold_checks=supports,
        saved_baseline_measurement=measured,
        independent_gold=False, automatic_extraction_tested=False)
    write_bundle(output/'summary', {'report.json':summary})
    return summary


if __name__=='__main__':
    run(Path(sys.argv[1]))
