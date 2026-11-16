from itertools import groupby
from typing import Any, Mapping

import networkx as nx

from prompt_mechanism_study.records import canonical_json, content_hash
from prompt_mechanism_study.tsg.prompt_contract import compile_source_propositions
from prompt_mechanism_study.tsg.prompt_tsg import (
    PromptTSG,
    PromptTSGError,
    REQUIREMENT_TYPES,
    prompt_tsg_from_record,
    source_proposition_measurement,
    source_requirement_inventory,
    validate_prompt_tsg,
)


def check_source_representation(source,record,method,*,character_limit=40000,record_limit=64,relation_limit=128):
    assert record['task_unit_id'] == source['task_unit_id']
    assert len(canonical_json(record)) <= character_limit
    if method == 'graph':
        assert len(record['facts']) <= record_limit and len(record['relations']) <= relation_limit
        graph,compiled = compile_source_propositions(source,record,extractor_id='source-representation-readout')
        inventory = source_requirement_inventory(graph,prompt=source['prompt'],catalog=compiled['catalog'])
        return inventory['source_state_readback'],compiled
    assert method == 'flat' and set(record) == {'task_unit_id','records','unresolved_notes'}
    assert isinstance(record['records'],list) and len(record['records']) <= record_limit
    assert len({row['id'] for row in record['records']}) == len(record['records'])
    for row in record['records']:
        assert set(row) == {'id','kind','statement','binding','condition_scope','evidence'}
        assert row['kind'] in ('requirement','api_contract','implementation','context','unknown')
        assert all(isinstance(row[key],str) and row[key].strip() for key in ('id','statement','binding','condition_scope'))
        assert row['evidence'] and all(text and text in source['prompt'] for text in row['evidence'])
    assert isinstance(record['unresolved_notes'],list) and all(isinstance(text,str) for text in record['unresolved_notes'])
    return record,None


def display_source_graph(readback):
    aliases = {key:f'n{index:03d}' for index,key in enumerate(sorted(readback['nodes']),start=1)}

    def replace(value,mapping):
        if isinstance(value,str):
            return mapping.get(value,value)
        if isinstance(value,list):
            return [replace(child,mapping) for child in value]
        if isinstance(value,dict):
            return {mapping.get(key,key):replace(child,mapping) for key,child in value.items()}
        return value

    assert not set(aliases.values()) & set(aliases)
    rendered = replace(readback,aliases)
    assert replace(rendered,{value:key for key,value in aliases.items()}) == readback
    return rendered,aliases


def reference_source_texts(value, *, prompt):
    if isinstance(value, str) and len(value) > 512 and value in prompt:
        start = prompt.index(value)
        return dict(source_prompt_chars=[start, start + len(value)],
                    opening_excerpt=value[:160], closing_excerpt=value[-160:])
    if isinstance(value, list):
        return [reference_source_texts(child, prompt=prompt) for child in value]
    if isinstance(value, dict):
        result = {}
        for key, child in value.items():
            if key == 'source_unit_ids':
                assert all(isinstance(unit, str) and len(unit) == 5 and unit[0] == 'u' and unit[1:].isdigit() for unit in child)
                groups = [list(group) for _, group in groupby(enumerate(int(unit[1:]) for unit in child),
                                                             key=lambda pair: pair[1] - pair[0])]
                result[key] = dict(source_unit_ranges=[[group[0][1], group[-1][1]] for group in groups])
            elif key == 'evidence_text' and len(child) > 512 and 'evidence_start' in value and 'evidence_end' in value:
                start, end = value['evidence_start'], value['evidence_end']
                assert prompt[start:end] == child
                result[key] = dict(source_prompt_chars=[start, end], opening_excerpt=child[:160], closing_excerpt=child[-160:])
            else:
                result[key] = reference_source_texts(child, prompt=prompt)
        return result
    return value


def restore_source_texts(value, *, prompt):
    if isinstance(value, dict):
        if set(value) == {'source_unit_ranges'}:
            return [f'u{number:04d}' for first, last in value['source_unit_ranges'] for number in range(first, last + 1)]
        if set(value) == {'source_prompt_chars', 'opening_excerpt', 'closing_excerpt'}:
            start, end = value['source_prompt_chars']
            text = prompt[start:end]
            assert text[:160] == value['opening_excerpt'] and text[-160:] == value['closing_excerpt']
            return text
        return {key: restore_source_texts(child, prompt=prompt) for key, child in value.items()}
    if isinstance(value, list):
        return [restore_source_texts(child, prompt=prompt) for child in value]
    return value


def source_edit_guidance(source, record, method, *, character_limit=40000):
    if method == 'raw':
        assert set(record) == {'task_unit_id', 'analysis_text', 'evidence'}
        assert record['task_unit_id'] == source['task_unit_id']
        assert isinstance(record['analysis_text'], str) and record['analysis_text'].strip()
        assert len(canonical_json(record)) <= character_limit
        assert record['evidence'] and all(isinstance(value, str) and value and value in source['prompt']
                                          for value in record['evidence'])
        return dict(kind='source_text_preparation', analysis_text=record['analysis_text'],
                    evidence=record['evidence'], source_entailment_verified=False)
    view, compiled = check_source_representation(source, record, method, character_limit=character_limit)
    if method == 'flat':
        return dict(kind='flat_source_preparation', representation=view, source_entailment_verified=False)
    graph = prompt_tsg_from_record(compiled['graph'])
    inventory = source_requirement_inventory(graph, prompt=source['prompt'], catalog=compiled['catalog'])
    guidance, _ = display_source_graph(inventory['readback'])
    operation_index = {}
    for operation_id, operation in guidance['operations'].items():
        governing = {key: frame for key, frame in guidance['propositions'].items()
                     if operation_id in frame['binding']['operation_node_ids']}
        operation_index[operation_id] = dict(operation=guidance['nodes'][operation_id], flow=operation,
            propositions=governing,
            expression_root_node_ids=sorted({frame['expression_path_node_ids'][0]
                                             for frame in governing.values()}),
            expression_navigation_only=True)
    return dict(kind='policy_dependency_preparation', representation=guidance,
                operation_requirement_index=operation_index,
                propositions_without_recorded_operation=[key for key, frame in guidance['propositions'].items()
                                                         if not frame['binding']['operation_node_ids']],
                unresolved_source_candidates=[view['nodes'][key] for key in inventory['unresolved_candidate_node_ids']],
                source_entailment_verified=False, source_coverage_verified=False)


def extract_tsg_structural_attributes(
    graph: PromptTSG,
    *,
    operation_node_id: str | None = None,
    requirement_node_id: str | None = None,
    prompt: str | None = None,
    catalog: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    """Extract Stage I -> Stage II structural attributes with graceful local unresolved handling."""
    if prompt is not None and catalog is not None:
        validate_prompt_tsg(graph, prompt=prompt, catalog=catalog)
    elif prompt is not None and graph.prompt_sha256 != content_hash(prompt):
        raise PromptTSGError("Prompt TSG prompt hash does not match provided prompt")

    nodes = {node.node_id: node for node in graph.nodes}
    links = {(edge.source_id, edge.edge_type, edge.target_id) for edge in graph.edges}
    if operation_node_id is not None and (
        operation_node_id not in nodes or nodes[operation_node_id].node_type != "task_operation"
    ):
        raise PromptTSGError("target operation_node_id is missing or not a task_operation")
    if requirement_node_id is not None and (
        requirement_node_id not in nodes or nodes[requirement_node_id].node_type not in REQUIREMENT_TYPES
    ):
        raise PromptTSGError("target requirement_node_id is missing or not a proposition node")

    operation_ids = sorted(node.node_id for node in graph.nodes if node.node_type == "task_operation")
    operation_count = len(operation_ids)

    comp_dag = nx.DiGraph()
    comp_dag.add_nodes_from(node.node_id for node in graph.nodes if node.node_type == "data_object")
    for source, kind, target in links:
        if kind == "part_of":
            if source not in comp_dag or target not in comp_dag:
                raise PromptTSGError("part_of edge must connect data_object nodes")
            comp_dag.add_edge(source, target)
    if not nx.is_directed_acyclic_graph(comp_dag):
        raise PromptTSGError("part_of component graph must be acyclic")
    max_component_path_depth = (
        int(nx.dag_longest_path_length(comp_dag)) if comp_dag.number_of_edges() > 0 else 0
    )

    ops_by_object: dict[str, set[str]] = {}
    for obj_id in comp_dag.nodes:
        containers = {obj_id} | nx.descendants(comp_dag, obj_id)
        touched = {
            op
            for c in containers
            for op in operation_ids
            if (c, "used_by", op) in links or (op, "produces", c) in links
        }
        ops_by_object[obj_id] = touched
    shared_object_ids = sorted(obj_id for obj_id, touched in ops_by_object.items() if len(touched) >= 2)
    multi_operation_shared_object = operation_count >= 2 and bool(shared_object_ids)

    proposition_ids = sorted(node.node_id for node in graph.nodes if node.node_type in REQUIREMENT_TYPES)
    unbound_proposition_ids = sorted(
        pid
        for pid in proposition_ids
        if not any(s == pid and kind == "about_operation" for s, kind, _ in links)
    )

    structures = {key: kind for key, kind, _ in graph.requirement_structures}
    scope_props = [requirement_node_id] if requirement_node_id is not None else proposition_ids
    scope_ops = (
        {operation_node_id}
        if operation_node_id is not None
        else {
            target
            for pid in scope_props
            for source, kind, target in links
            if source == pid and kind == "about_operation"
        }
    )
    has_condition_edge = any(
        (kind == "conditions" and target in (set(scope_props) | scope_ops))
        or (kind == "under_condition" and source in set(scope_props))
        for source, kind, target in links
    )
    has_composite_structure = any(
        structures.get(pid, "atom") in {"and", "or", "not", "opaque"} for pid in scope_props
    )
    conditional_or_composite_guard = bool(has_condition_edge or has_composite_structure)

    if requirement_node_id is not None:
        selected_props = [requirement_node_id]
    elif operation_node_id is not None:
        selected_props = sorted(
            source
            for source, kind, target in links
            if kind == "about_operation" and target == operation_node_id and source in nodes
        )
    else:
        selected_props = [
            pid
            for pid in proposition_ids
            if dict(nodes[pid].attributes).get("normative_force") is True
        ]

    if selected_props:
        measurements = [source_proposition_measurement(graph, [pid]) for pid in selected_props]
        local_binding_complete = all(bool(m["binding_complete"]) for m in measurements)
        primary_force = measurements[0]["force"] if len(measurements) == 1 else "multiple"
    else:
        local_binding_complete = False
        primary_force = "unresolved"

    incomplete_proposition_ids = sorted(
        pid
        for pid in proposition_ids
        if dict(nodes[pid].attributes).get("binding_complete") is not True
    )
    unresolved_semantics_count = len(graph.unresolved_semantics)
    unresolved_relations_count = len(graph.unresolved_relations)
    local_unresolved_count = unresolved_semantics_count + unresolved_relations_count

    return {
        "tsg_id": graph.tsg_id,
        "task_id": graph.task_id,
        "operation_node_id": operation_node_id,
        "requirement_node_id": requirement_node_id,
        "primary_force": primary_force,
        "operation_count": operation_count,
        "multi_operation_shared_object": multi_operation_shared_object,
        "shared_object_node_ids": shared_object_ids,
        "max_component_path_depth": max_component_path_depth,
        "conditional_or_composite_guard": conditional_or_composite_guard,
        "unbound_proposition_count": len(unbound_proposition_ids),
        "unbound_proposition_node_ids": unbound_proposition_ids,
        "local_binding_complete": local_binding_complete,
        "local_unresolved_count": local_unresolved_count,
        "unresolved_semantics_count": unresolved_semantics_count,
        "unresolved_relations_count": unresolved_relations_count,
        "incomplete_proposition_count": len(incomplete_proposition_ids),
        "structural_vector": [
            operation_count,
            int(multi_operation_shared_object),
            max_component_path_depth,
            int(conditional_or_composite_guard),
            len(unbound_proposition_ids),
            int(local_binding_complete),
            local_unresolved_count,
        ],
    }
