import json
from pathlib import Path

from prompt_mechanism_study.records import canonical_json
from prompt_mechanism_study.tsg.prompt_contract import compile_source_propositions
from prompt_mechanism_study.tsg.prompt_tsg import source_requirement_inventory
from prompt_mechanism_study.tsg.source_representation import source_edit_guidance


root = Path('data/method/codecov-representation-20261102')
load = lambda path: json.loads(path.read_text(encoding='utf-8'))
source = load(root / 'representation-source.json')
record = load(root / 'representation-graph.json')
graph, compiled = compile_source_propositions(source, record, extractor_id='guidance-check')
inventory = source_requirement_inventory(graph, prompt=source['prompt'], catalog=compiled['catalog'])
guidance = source_edit_guidance(source, record, 'graph')
view = guidance['representation']
assert len(view['nodes']) <= len(inventory['source_state_readback']['nodes'])
assert len(view['selected_proposition_node_ids']) == len(inventory['inventory_root_node_ids']) > 0
assert len(view['operations']) > 0
for operation in view['operations'].values():
    for field in ('input_node_ids', 'output_node_ids', 'execution_condition_node_ids', 'non_gating_context_node_ids'):
        assert set(operation[field]) <= set(view['nodes'])
assert guidance['source_entailment_verified'] is False
assert guidance['source_coverage_verified'] is False
for node in view['nodes'].values():
    assert node['evidence_text'] in source['prompt']
flat = load(root / 'representation-flat.json')
assert source_edit_guidance(source, flat, 'flat')['representation'] == flat
raw_record = dict(task_unit_id=source['task_unit_id'], analysis_text=source['prompt'], evidence=[source['prompt']])
raw = source_edit_guidance(source, raw_record, 'raw', character_limit=4 * len(source['prompt']))
assert raw['analysis_text'] == source['prompt']
print(dict(status='VERIFIED_EXPOSED_POLICY_DEPENDENCY_GUIDANCE',
    source_nodes=len(inventory['source_state_readback']['nodes']), selected_nodes=len(view['nodes']),
    selected_operations=len(view['operations']), guidance_characters=len(canonical_json(guidance)),
    source_semantics_verified=False, graph_gain_established=False, new_generation_calls=0))
