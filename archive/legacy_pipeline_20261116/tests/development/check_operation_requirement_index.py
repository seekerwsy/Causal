from pathlib import Path
import sys

from prompt_mechanism_study.artifact_io import read_json, write_json_new
from prompt_mechanism_study.records import canonical_json
from prompt_mechanism_study.tsg.prompt_contract import compile_source_propositions
from prompt_mechanism_study.tsg.prompt_tsg import source_requirement_inventory
from prompt_mechanism_study.tsg.source_representation import (
    display_source_graph, reference_source_texts, restore_source_texts, source_edit_guidance)


folders = [Path('data/method') / name for name in ('aiohttp-representation-20261103',
    'codecov-representation-20261102', 'security-code-source-20261102')]
output = Path(sys.argv[1]) if len(sys.argv) == 2 else Path('.test-tmp/graph-operation-guidance-20261103')
rows = []
for folder in folders:
    source = read_json(folder / 'representation-source.json')
    record = read_json(folder / 'representation-graph.json')
    graph, compiled = compile_source_propositions(source, record, extractor_id='source-representation-readout')
    inventory = source_requirement_inventory(graph, prompt=source['prompt'], catalog=compiled['catalog'])
    view, aliases = display_source_graph(inventory['readback'])
    guidance = source_edit_guidance(source, record, 'graph')
    assert guidance['representation'] == view
    displayed = reference_source_texts(guidance, prompt=source['prompt'])
    assert restore_source_texts(displayed, prompt=source['prompt']) == guidance
    index = guidance['operation_requirement_index']
    assert set(index) == set(view['operations'])
    expected = {(aliases[edge.source_id], aliases[edge.target_id]) for edge in graph.edges
        if edge.edge_type == 'about_operation' and edge.source_id in inventory['readback']['propositions']}
    actual = {(proposition, operation) for operation, row in index.items() for proposition in row['propositions']}
    assert actual == expected
    for operation, row in index.items():
        assert row['operation'] == view['nodes'][operation] and row['flow'] == view['operations'][operation]
        assert row['expression_navigation_only'] is True
        for key, frame in row['propositions'].items():
            assert frame == view['propositions'][key]
            assert frame['expression_path_node_ids'][0] in row['expression_root_node_ids']
    unbound = {key for key in inventory['readback']['propositions']
               if not any(edge.source_id == key and edge.edge_type == 'about_operation' for edge in graph.edges)}
    assert set(guidance['propositions_without_recorded_operation']) == {aliases[key] for key in unbound}
    if folder.name == 'aiohttp-representation-20261103':
        operation, = [key for key, node in view['nodes'].items() if node['semantic_id'] == 'op.cached_build']
        semantics = {view['nodes'][key]['semantic_id'] for key in index[operation]['propositions']}
        assert 'policy.reuse' in semantics
        policies = [view['nodes'][key]['evidence_text'] for key, frame in index[operation]['propositions'].items()
                    if frame['binding']['force'] == 'normative']
        assert any('Persistent middleware construction caching must not keep' in text for text in policies)
        assert any('reuse of constructed middleware chains for normal routes' in text for text in policies)
        original_inputs = read_json(folder / 'generation-inputs.json')
        common = ('\nCheck that every newly used Python symbol is available through a valid import or definition. '
                  'Preserve the complete policy and declared non-target behavior. '
                  'An operation requirement index is navigation into the full expressions; '
                  'do not convert OR, NOT, quantifiers or contextual members into independent requirements.\n')
        prompts = {}
        for method in ('raw', 'flat', 'graph'):
            prepared = source_edit_guidance(source, read_json(folder / ('representation-' + method + '.json')), method)
            material = {key: value for key, value in prepared.items() if key != 'kind'}
            material['source_coverage_verified'] = False
            referenced = reference_source_texts(material, prompt=source['prompt'])
            assert restore_source_texts(referenced, prompt=source['prompt']) == material
            prompts[method] = (source['prompt'] + '\nSOURCE-BASED EDITING PREPARATION\n' + canonical_json(referenced)
                + '\nImplement the complete original task and Atomic requirement. Preparation notes are not a correctness certificate. '
                + 'Preserve the declared non-target behavior. Return the entire web_app.py module.\n'
                + 'source_prompt_chars [start,end] identifies the complete evidence in the common source prompt; '
                + 'source_unit_ranges [first,last] includes every numbered source unit in that range.\n' + common)
        write_json_new(output / 'tokenizer-inputs.json',
            dict(prompts=prompts, system=original_inputs['system'], generation=original_inputs['generation'],
                 context_limit=original_inputs['context_limit'], new_model_calls=0,
                 evidence_role='EXPOSED_SOURCE_MECHANICAL_CONTEXT_CHECK_ONLY'))
    rows.append(dict(source=folder.name, operations=len(index), reverse_bindings=len(actual),
        unbound_propositions=len(unbound), complete_guidance_characters=len(canonical_json(guidance)),
        displayed_guidance_characters=len(canonical_json(displayed)),
        expression_kinds=sorted({frame['composition']['kind'] for frame in view['propositions'].values()})))
write_json_new(output / 'check.json',
    dict(status='VERIFIED_OPERATION_INDEX_ON_EXPOSED_SOURCE_GRAPHS', rows=rows,
        graph_gain_established=False, new_model_calls=0, new_task_units=0))
print(dict(status='VERIFIED_OPERATION_INDEX_ON_EXPOSED_SOURCE_GRAPHS', rows=rows))
