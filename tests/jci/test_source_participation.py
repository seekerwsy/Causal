from copy import deepcopy
from pathlib import Path

import pytest

from prompt_mechanism_study.artifact_io import read_json
from prompt_mechanism_study.cli import main as cli_main
from prompt_mechanism_study.tsg.prompt_contract import compile_source_propositions
from prompt_mechanism_study.tsg.prompt_tsg import (
    PromptTSGError, source_participation_paths, source_proposition_readback,
)
from prompt_mechanism_study.tsg.source_representation import extract_tsg_structural_attributes


SOURCE = read_json(Path('src/fixtures/object-participation.json'))


def compile_source(record=None):
    graph, compiled = compile_source_propositions(SOURCE['task'],
        SOURCE['record'] if record is None else record, extractor_id='object-participation-source')
    ids = compiled['local_node_ids']
    target = {key: ids[value] for key, value in SOURCE['target'].items()}
    return graph, compiled, ids, target


def read_target(graph, compiled, target):
    return source_proposition_readback(graph, [target['requirement_local_id']],
        prompt=SOURCE['task']['prompt'], catalog=compiled['catalog'])


def test_requirement_object_remains_distinct_from_the_actual_output():
    graph, compiled, ids, target = compile_source()
    view = read_target(graph, compiled, target)
    frame = view['propositions'][target['requirement_local_id']]['binding']
    assert frame['binding_complete'] is True
    assert frame['subject_node_ids'] == [target['subject_local_id']]
    assert frame['subject_node_ids'] != [ids['example_result']]
    paths = source_participation_paths(graph, [target['operation_local_id']], [target['subject_local_id']])
    assert len(paths) == 1 and paths[0]['ownership_path_node_ids'] == [ids[key] for key in SOURCE['expected_path_local_ids']]
    assert paths[0]['participant_node_id'] == ids['example_result'] and paths[0]['participation_kind'] == 'produces'
    operation = view['operations'][target['operation_local_id']]
    assert target['subject_local_id'] not in operation['input_node_ids'] + operation['output_node_ids']
    assert ids['example_air'] in operation['input_node_ids'] and ids['example_ds'] not in operation['input_node_ids']
    assert view['source_entailment_verified'] is False


def test_nested_attribute_path_retains_each_recorded_owner():
    graph, _, ids, target = compile_source()
    paths = source_participation_paths(graph, [target['operation_local_id']], [ids['example_time_attrs']])
    assert len(paths) == 1
    assert paths[0]['ownership_path_node_ids'] == [ids[key] for key in SOURCE['expected_nested_path_local_ids']]


def test_reference_relationship_does_not_replace_object_composition():
    record = deepcopy(SOURCE['record'])
    for relation in record['relations']:
        if relation == dict(source='example_time', target='example_result', edge_type='part_of'):
            relation['edge_type'] = 'refers_to'
    graph, compiled, ids, target = compile_source(record)
    assert source_participation_paths(graph, [target['operation_local_id']], [target['subject_local_id']]) == []
    assert read_target(graph, compiled, target)['measurement']['binding_complete'] is False


def test_a_path_does_not_override_an_explicitly_unfinished_binding():
    record = deepcopy(SOURCE['record'])
    for fact in record['facts']:
        if fact['local_id'] == SOURCE['target']['requirement_local_id']:
            fact['attributes']['binding_complete'] = False
    graph, compiled, _, target = compile_source(record)
    view = read_target(graph, compiled, target)
    assert view['measurement']['subject_binding_paths']
    assert view['measurement']['binding_complete'] is False


@pytest.mark.parametrize('source,target', [('example_result', 'example_time'), ('example_where', 'example_result')])
def test_invalid_composition_fails_at_the_original_relation(source, target):
    record = deepcopy(SOURCE['record'])
    record['relations'].append(dict(source=source, target=target, edge_type='part_of'))
    with pytest.raises(PromptTSGError):
        compile_source(record)


def test_known_example_does_not_complete_the_unknown_general_scope():
    graph, compiled, ids, _ = compile_source()
    view = source_proposition_readback(graph, [ids['general_coordinate_requirement']],
        prompt=SOURCE['task']['prompt'], catalog=compiled['catalog'])
    assert view['measurement']['binding_complete'] is False
    assert view['propositions'][ids['general_coordinate_requirement']]['retained_scope']['kind'] == 'task'
    assert any(relation[1] == 'part_of' for relation in view['unresolved_relations'])


def test_stage1_to_stage2_structural_attributes_and_cli_inspect(tmp_path):
    graph, compiled, _, target = compile_source()
    attrs = extract_tsg_structural_attributes(
        graph,
        operation_node_id=target['operation_local_id'],
        requirement_node_id=target['requirement_local_id'],
        prompt=SOURCE['task']['prompt'],
        catalog=compiled['catalog'],
    )
    assert attrs['operation_count'] == 4
    assert attrs['multi_operation_shared_object'] is True
    assert attrs['max_component_path_depth'] == 2
    assert attrs['conditional_or_composite_guard'] is True
    assert attrs['local_binding_complete'] is True
    assert attrs['local_unresolved_count'] > 0
    assert len(attrs['structural_vector']) == 7

    out_dir = tmp_path / 'tsg-inspect'
    assert cli_main(['study', 'inspect-tsg', 'src/fixtures/object-participation.json', str(out_dir)]) == 0
    saved = read_json(out_dir / 'attributes.json')
    assert saved['tsg_id'] == saved['attributes']['tsg_id']
    assert {k: v for k, v in saved['attributes'].items() if k != 'tsg_id'} == {
        k: v for k, v in attrs.items() if k != 'tsg_id'
    }
