from annotation_fixture import authored_contract
"""Source coverage, generation/runtime layers and operation-local role boundaries."""

from copy import deepcopy
from dataclasses import replace
import pytest
from prompt_mechanism_study.tsg.prompt_contract import (
    compile_task_context_contract,
    open_concept_catalog,
    task_context_contract_from_record,
    task_context_contract_record,
)
from prompt_mechanism_study.tsg.prompt_tsg import PromptTSGError
from prompt_mechanism_study.records import canonical_value, content_id


SOURCE = "Implement Python code. Return JSON. Transform buffer in place. If remote, validate buffer."


def _inventory_contract():
    definitions = [
        ("g", "task_operation", "code.implementation", "Implement Python code"),
        ("j", "presentation_control", "answer.json", "Return JSON"),
        ("op", "task_operation", "buffer.transform", "Transform buffer in place"),
        ("x", "data_object", "buffer.value", "buffer"),
        ("c", "condition", "mode.remote", "If remote"),
        ("p", "safety_requirement", "buffer.validate", "validate buffer"),
    ]
    relations = [
        ("j", "constrains", "g", "Return JSON"),
        ("x", "used_by", "op", "Transform buffer in place"),
        ("op", "produces", "x", "Transform buffer in place"),
        ("c", "conditions", "p", "If remote, validate buffer"),
        ("p", "constrains", "op", "If remote, validate buffer"),
        ("p", "constrains", "x", "validate buffer"),
    ]
    catalog = open_concept_catalog()
    contract = authored_contract(dict(
        concepts=[dict(concept_id=concept, node_type=kind, definition=quote)
                  for _, kind, concept, quote in definitions],
        nodes=[dict(local_id=key, concept_id=concept, evidence_text=quote, occurrence=1)
               for key, _, concept, quote in definitions],
        edges=[dict(source_node_local_id=source, target_node_local_id=target, edge_type=kind,
                    evidence_text=quote, occurrence=1) for source, kind, target, quote in relations],
        concept_states=[], feature_states=[], unresolved_notes=[]),
        task=dict(task_id="synthetic-source-inventory", prompt=SOURCE), catalog=catalog,
        annotator_id="authored-fixture", review_status="development_exposed")
    units = [
        ("Implement Python code.", ["g"]), ("Return JSON.", ["j"]),
        ("Transform buffer in place.", ["op", "x"]),
        ("If remote, validate buffer.", ["c", "p", "x"]),
    ]
    inventory = dict(
        source_units={f"u{i}": dict(evidence_text=quote, occurrence=1)
                      for i, (quote, _) in enumerate(units, 1)},
        coverage={f"u{i}": dict(facts=facts, status="represented", reason="Authored source facts.")
                  for i, (_, facts) in enumerate(units, 1)},
        layers={key: "generation" if key in {"g", "j"} else "runtime"
                for key, _, _, _ in definitions},
        operation_roles=[dict(operation="op", subject="x", role=role,
                              evidence_text="Transform buffer in place", occurrence=1)
                         for role in ("value_input", "result")])
    return catalog, replace(contract, source_inventory=inventory)


def test_local_input_and_result_can_be_the_same_source_object_and_metadata_roundtrips(tmp_path):
    catalog, contract = _inventory_contract()
    graph = compile_task_context_contract(contract, prompt=SOURCE, catalog=catalog)
    assert len(graph.nodes) == len(contract.facts) + 1
    record = task_context_contract_record(contract)
    assert record["source_inventory"] == contract.source_inventory
    assert task_context_contract_from_record(record) == contract
    authored = replace(contract, source_inventory=None)
    legacy = canonical_value(authored)
    legacy.pop("source_inventory")
    assert authored.contract_id == content_id("open_task_contract_", legacy)
    assert "source_inventory" not in task_context_contract_record(authored)
    assert task_context_contract_from_record(task_context_contract_record(authored)) == authored
    assert authored.contract_id != contract.contract_id

    # Candidates and the HTML viewer use the same record-derived nodes and graph.
    from prompt_mechanism_study.tsg.candidate_construction import candidate_request
    from prompt_mechanism_study.tsg.tsg_visualization import _source_graph_view, build_tsg_viewer
    from prompt_mechanism_study.tsg.prompt_tsg import prompt_tsg_record, validate_prompt_tsg
    from prompt_mechanism_study.artifact_io import write_bundle
    import json
    task = dict(task_id=contract.task_id, prompt=SOURCE, language='python')
    raw_graph = prompt_tsg_record(graph)
    view = _source_graph_view(raw_graph, record, SOURCE, contract.catalog)
    candidate = candidate_request([task], [contract], input_catalog=catalog)['sources'][0]
    assert {row['node_id'] for row in candidate['nodes']} == {node.node_id for node in graph.nodes}
    assert candidate['edges'] == view['graph']['edges']
    assert len(view['edge_evidence']) == len(contract.relations)
    assert {view['local_node_ids'][key] for key in ('g','j')} == set(view['generation_node_ids'])
    conditional = next(edge for edge in graph.edges if edge.edge_type == 'conditions')
    quote = view['edge_evidence'][conditional.edge_id]
    assert SOURCE[quote['start']:quote['end']] == 'If remote, validate buffer'
    changed = replace(graph, edges=tuple(edge for edge in graph.edges if edge != conditional))
    validate_prompt_tsg(changed, prompt=SOURCE, catalog=contract.catalog)
    with pytest.raises(ValueError, match='differs from its source records'):
        _source_graph_view(prompt_tsg_record(changed), record, SOURCE, contract.catalog)
    bundle = tmp_path / 'extraction'
    write_bundle(bundle, {'report.json': {'status': 'NON_CLAIM_TEST_ARTIFACT'},
        'graphs.json': [raw_graph], 'contracts.json': [record],
        'responses.json': [dict(task_id=contract.task_id, status='success')]})
    tasks = tmp_path / 'tasks.json'
    tasks.write_text(json.dumps([task]), encoding='utf-8')
    output = tmp_path / 'viewer.html'
    result = build_tsg_viewer(tasks, (bundle,), output)
    assert result['compiled_graphs'] == 1 and result['provider_calls'] == 0
    html = output.read_text(encoding='utf-8')
    assert '__TSG_DATA__' not in html and '__DAGRE_SOURCE__' not in html
    assert 'If remote, validate buffer' in html and conditional.edge_id in html


@pytest.mark.parametrize("section", ["source_units", "operation_roles"])
def test_units_and_role_evidence_must_quote_the_actual_source(section):
    catalog, contract = _inventory_contract()
    inventory = deepcopy(contract.source_inventory)
    row = inventory[section]["u1"] if section == "source_units" else inventory[section][0]
    row["evidence_text"] = "This evidence is not in the task."
    with pytest.raises(PromptTSGError):
        compile_task_context_contract(replace(contract, source_inventory=inventory), prompt=SOURCE, catalog=catalog)


@pytest.mark.parametrize('source,relation,target,match', [
    ('j', 'constrains', 'op', 'same resolved layer'),
    ('x', 'used_by', 'op', 'input role'),
    ('op', 'produces', 'x', 'result role'),
])
def test_edges_require_same_layer_and_the_exact_operation_subject_role(source, relation, target, match):
    catalog, contract = _inventory_contract()
    inventory = deepcopy(contract.source_inventory)
    if relation == "used_by":
        inventory["operation_roles"] = [row for row in inventory["operation_roles"] if row["role"] == "result"]
    if relation == "produces":
        inventory["operation_roles"] = [row for row in inventory["operation_roles"] if row["role"] != "result"]
    edge = dict(source=source, edge_type=relation, target=target, evidence_text=SOURCE, occurrence=1)
    with pytest.raises(PromptTSGError, match=match):
        compile_task_context_contract(replace(contract, source_inventory=inventory, relations=(edge,)),
                                   prompt=SOURCE, catalog=catalog)
